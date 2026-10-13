package proofstore

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ParallaxProtocol/parallax/v2/util"
	bolt "go.etcd.io/bbolt"
)

// CreateChannel records a newly usable channel. Fails with ErrExists if the
// key is already present — channel ids are never reused (Part 1 §3), so a
// collision is a caller bug.
func (s *Store) CreateChannel(meta ChannelMeta) error {
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	zero, err := json.Marshal(Deposits{})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		name := []byte(meta.Key.String())
		if tx.Bucket(bucketChannels).Bucket(name) != nil {
			return ErrExists
		}
		cb, err := tx.Bucket(bucketChannels).CreateBucket(name)
		if err != nil {
			return err
		}
		if _, err := cb.CreateBucket(bucketSelfSigned); err != nil {
			return err
		}
		if err := cb.Put(keyMeta, raw); err != nil {
			return err
		}
		return cb.Put(keyDeposits, zero)
	})
}

// Meta returns the channel metadata.
func (s *Store) Meta(key ChannelKey) (ChannelMeta, error) {
	var meta ChannelMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		cb := channelBucket(tx, key)
		if cb == nil {
			return ErrNotFound
		}
		return json.Unmarshal(cb.Get(keyMeta), &meta)
	})
	return meta, err
}

// UpdateMeta atomically mutates the channel metadata (poisoned flag, freeze
// window, towers, …). The mutation MUST NOT change Key or Role.
func (s *Store) UpdateMeta(key ChannelKey, mutate func(*ChannelMeta)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		cb := channelBucket(tx, key)
		if cb == nil {
			return ErrNotFound
		}
		var meta ChannelMeta
		if err := json.Unmarshal(cb.Get(keyMeta), &meta); err != nil {
			return err
		}
		before, role := meta.Key, meta.Role
		mutate(&meta)
		if meta.Key != before || meta.Role != role {
			return fmt.Errorf("proofstore: meta mutation may not change key or role")
		}
		raw, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		return cb.Put(keyMeta, raw)
	})
}

// ListChannels returns the metadata of every stored channel.
func (s *Store) ListChannels() ([]ChannelMeta, error) {
	var out []ChannelMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketChannels).ForEachBucket(func(name []byte) error {
			var meta ChannelMeta
			cb := tx.Bucket(bucketChannels).Bucket(name)
			if err := json.Unmarshal(cb.Get(keyMeta), &meta); err != nil {
				return err
			}
			out = append(out, meta)
			return nil
		})
	})
	return out, err
}

// LatestState returns the latest complete dual-signed state, or ErrNotFound
// if no state has completed yet (seq 0: only startCloseNoProof territory).
func (s *Store) LatestState(key ChannelKey) (SignedState, error) {
	var st SignedState
	err := s.db.View(func(tx *bolt.Tx) error {
		cb := channelBucket(tx, key)
		if cb == nil {
			return ErrNotFound
		}
		raw := cb.Get(keyState)
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &st)
	})
	return st, err
}

// SelfSigned returns every outstanding self-signed state above the latest
// complete seq, ascending. Empty means no in-flight proposal (the channel is
// not poisoned by this wallet's own signatures).
func (s *Store) SelfSigned(key ChannelKey) ([]SignedState, error) {
	var out []SignedState
	err := s.db.View(func(tx *bolt.Tx) error {
		cb := channelBucket(tx, key)
		if cb == nil {
			return ErrNotFound
		}
		return cb.Bucket(bucketSelfSigned).ForEach(func(_, v []byte) error {
			var st SignedState
			if err := json.Unmarshal(v, &st); err != nil {
				return err
			}
			out = append(out, st)
			return nil
		})
	})
	return out, err
}

// PutSelfSigned journals a state carrying this wallet's signature before it
// is transmitted (W1: this call commits with fsync before returning; the
// caller MUST NOT publish until it has).
//
// Rejections: ErrStaleSeq below-or-at the completed seq (unless identical to
// the completed payload, which is an idempotent no-op), ErrEquivocation for
// a different payload at any seq this wallet already signed, ErrBadState if
// the wallet's own signature slot is not a 65-byte signature.
func (s *Store) PutSelfSigned(st SignedState) error {
	return s.PutSelfSignedPayment(st, "")
}

// PutSelfSignedPayment is PutSelfSigned for a payment that names an
// invoice: in the same transaction as the journal write it refuses an
// invoice this store already holds as paid (ErrInvoicePaid) and marks a
// held unpaid one paid by st, so a second proposal for the same invoice
// can never be journaled. An id with no local record (URI path) journals
// unmarked. The mark is released if the journaled state is later pruned
// without completing (see putComplete).
func (s *Store) PutSelfSignedPayment(st SignedState, invoiceID string) error {
	digest, err := st.Digest()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if invoiceID != "" {
			if err := markInvoicePaid(tx, invoiceID, st.Key, st.Seq, true); err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		cb := channelBucket(tx, st.Key)
		if cb == nil {
			return ErrNotFound
		}
		var meta ChannelMeta
		if err := json.Unmarshal(cb.Get(keyMeta), &meta); err != nil {
			return err
		}
		if len(st.SigOf(meta.Role)) != 65 {
			return fmt.Errorf("%w: missing own (%s) signature", ErrBadState, meta.Role)
		}

		// Against the completed history.
		if latest, ldigest, err := latestComplete(cb); err != nil {
			return err
		} else if latest != nil {
			if st.Seq < latest.Seq {
				return ErrStaleSeq
			}
			if st.Seq == latest.Seq {
				if ldigest == digest {
					return nil // already completed, identical payload
				}
				return ErrEquivocation
			}
		}

		// Against everything this wallet ever signed and still tracks.
		ss := cb.Bucket(bucketSelfSigned)
		if prev := ss.Get(seqKey(st.Seq)); prev != nil {
			prevDigest, err := digestOf(prev)
			if err != nil {
				return err
			}
			if prevDigest != digest {
				return ErrEquivocation
			}
			return nil // identical re-journal (retransmission path)
		}
		return ss.Put(seqKey(st.Seq), raw)
	})
}

// PutComplete records a complete dual-signed state (W2: this call commits
// with fsync before returning; a responder MUST NOT transmit its
// countersignature until it has).
//
// Rejections: ErrBadState unless both signatures are present, ErrStaleSeq
// below the completed seq, ErrEquivocation if a different payload exists at
// the same seq under this wallet's signature (either a prior complete state
// or a journaled self-signed one). On success, journaled self-signed entries
// at or below the new seq are pruned — completion at the same seq and
// supersession by a strictly higher state are the only legal clears
// (Part 3 §4.2 monotonicity).
func (s *Store) PutComplete(st SignedState) error {
	return s.putComplete(st, false)
}

// PutCompleteTiebreak is PutComplete with the one narrow W3 exception the
// simultaneous-proposal tiebreak requires (Part 2 §7.5): participant B,
// holding its own journaled self-signed N+1, adopts and countersigns A's
// *different* N+1. The discarded variant can never complete — completing it
// would need A's signature over it, which A's own W3 forbids — and it is
// pruned here, so no two complete states at one seq can ever exist locally.
// Callers MUST use this only for the A-wins adoption path.
func (s *Store) PutCompleteTiebreak(st SignedState) error {
	return s.putComplete(st, true)
}

func (s *Store) putComplete(st SignedState, allowTiebreak bool) error {
	if !st.Complete() {
		return fmt.Errorf("%w: state is not dual-signed", ErrBadState)
	}
	digest, err := st.Digest()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		cb := channelBucket(tx, st.Key)
		if cb == nil {
			return ErrNotFound
		}

		if latest, ldigest, err := latestComplete(cb); err != nil {
			return err
		} else if latest != nil {
			if st.Seq < latest.Seq {
				return ErrStaleSeq
			}
			if st.Seq == latest.Seq {
				if ldigest == digest {
					return nil // idempotent
				}
				return ErrEquivocation
			}
		}

		ss := cb.Bucket(bucketSelfSigned)
		if prev := ss.Get(seqKey(st.Seq)); prev != nil && !allowTiebreak {
			prevDigest, err := digestOf(prev)
			if err != nil {
				return err
			}
			if prevDigest != digest {
				return ErrEquivocation
			}
		}

		if err := cb.Put(keyState, raw); err != nil {
			return err
		}
		// Prune superseded/completed journal entries (seq <= st.Seq). An
		// entry that differs from st never completed (a lower seq would have
		// been pruned at its own completion; one at st.Seq lost the
		// tiebreak), so an invoice it spent is released for re-payment.
		c := ss.Cursor()
		var voided []uint64
		for k, v := c.First(); k != nil && bytes.Compare(k, seqKey(st.Seq)) <= 0; k, v = c.Next() {
			d, err := digestOf(v)
			if err != nil {
				return err
			}
			if d != digest {
				voided = append(voided, binary.BigEndian.Uint64(k))
			}
			if err := c.Delete(); err != nil {
				return err
			}
		}
		return releaseInvoices(tx, st.Key, voided)
	})
}

// Deposits returns the confirmed on-chain funding view.
func (s *Store) Deposits(key ChannelKey) (Deposits, error) {
	var d Deposits
	err := s.db.View(func(tx *bolt.Tx) error {
		cb := channelBucket(tx, key)
		if cb == nil {
			return ErrNotFound
		}
		return json.Unmarshal(cb.Get(keyDeposits), &d)
	})
	return d, err
}

// PutDeposits replaces the confirmed funding view (watcher-owned, Part 3 §7:
// recomputed from canonical logs, never patched).
func (s *Store) PutDeposits(key ChannelKey, d Deposits) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		cb := channelBucket(tx, key)
		if cb == nil {
			return ErrNotFound
		}
		return cb.Put(keyDeposits, raw)
	})
}

func latestComplete(cb *bolt.Bucket) (*SignedState, util.Hash, error) {
	raw := cb.Get(keyState)
	if raw == nil {
		return nil, util.Hash{}, nil
	}
	var st SignedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, util.Hash{}, err
	}
	d, err := st.Digest()
	if err != nil {
		return nil, util.Hash{}, err
	}
	return &st, d, nil
}

func digestOf(raw []byte) (util.Hash, error) {
	var st SignedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return util.Hash{}, err
	}
	return st.Digest()
}
