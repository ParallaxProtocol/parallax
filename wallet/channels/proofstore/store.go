// Package proofstore is the durable channel-state repository (Part 3 §4).
//
// It enforces the W-invariants at the storage layer, not merely in protocol
// code:
//
//	W1 — persist before transmit: PutSelfSigned commits (fsync) before it
//	     returns; callers MUST NOT publish a wrap or display a QR until it
//	     has returned.
//	W2 — persist before ACK: PutComplete commits before it returns; callers
//	     MUST NOT transmit a countersignature until it has returned.
//	W3 — no equivocation, ever: any write that would record this wallet's
//	     signature over a (channel, seq) already occupied by a *different*
//	     payload bearing this wallet's signature fails with ErrEquivocation.
//
// Instead of a single pendingOut slot, the store journals every self-signed
// state above the latest complete seq: the no-op-supersession flow (Part 2
// §7.4) legitimately leaves two outstanding self-signed seqs (the poisoned
// N+1 and the superseding N+2), and W3 must be checked against everything
// ever signed. Entries at or below the completed seq are pruned; monotonic
// checks make their seqs unreachable for re-signing afterwards.
package proofstore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

var (
	ErrNotFound     = errors.New("proofstore: not found")
	ErrExists       = errors.New("proofstore: already exists")
	ErrEquivocation = errors.New("proofstore: refusing to equivocate: different payload already signed at this seq (W3)")
	ErrStaleSeq     = errors.New("proofstore: seq not above latest complete state")
	ErrBadState     = errors.New("proofstore: state object invalid for this write")
	// ErrInvoicePaid refuses a payment journal write naming an invoice
	// this store already holds as paid.
	ErrInvoicePaid = errors.New("proofstore: invoice already paid")
	// ErrCorrupt wraps a decode failure on a stored record: the bytes are
	// present but no longer parse, and re-reading them cannot help.
	ErrCorrupt = errors.New("proofstore: corrupt record")
	// ErrQuarantined reports a delegation with no live record but one in
	// quarantine. It wraps ErrNotFound: there is nothing to evaluate with.
	ErrQuarantined = fmt.Errorf("%w: delegation quarantined", ErrNotFound)
)

var (
	bucketChannels = []byte("channels")
	bucketInvoices = []byte("invoices")
	bucketTower    = []byte("towerdb")
	// bucketQuarantine holds delegation records moved aside because they no
	// longer decode, keyed by channel, for operator inspection.
	bucketQuarantine = []byte("towerquarantine")

	// per-channel sub-buckets / keys
	keyMeta          = []byte("meta")
	keyState         = []byte("state")    // latest complete dual-signed state
	keyDeposits      = []byte("deposits") // confirmed on-chain funding view
	bucketSelfSigned = []byte("selfsigned")
)

// Store wraps a bbolt database. bbolt commits are fsync'd by default;
// NoSync MUST remain false (Part 3 §4.1) — the W-invariants depend on it.
type Store struct {
	db *bolt.DB
}

// Open opens (creating if absent) the proof store at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		if errors.Is(err, bolterrors.ErrTimeout) {
			return nil, fmt.Errorf("proofstore: %s is locked by another process (a channel daemon on the same data dir?)", path)
		}
		return nil, err
	}
	// Defense in depth: bbolt defaults to NoSync=false; pin it anyway.
	db.NoSync = false

	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketChannels, bucketInvoices, bucketTower, bucketQuarantine} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func seqKey(seq uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], seq)
	return k[:]
}

// channelBucket returns the sub-bucket for a channel, or nil if absent.
func channelBucket(tx *bolt.Tx, key ChannelKey) *bolt.Bucket {
	return tx.Bucket(bucketChannels).Bucket([]byte(key.String()))
}
