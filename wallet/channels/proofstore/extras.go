package proofstore

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ---------------------------------------------------------------- invoices

// CreateInvoice stores a new invoice; ErrExists on id collision.
func (s *Store) CreateInvoice(inv Invoice) error {
	raw, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketInvoices)
		if b.Get([]byte(inv.ID)) != nil {
			return ErrExists
		}
		return b.Put([]byte(inv.ID), raw)
	})
}

// Invoice returns an invoice by id.
func (s *Store) Invoice(id string) (Invoice, error) {
	var inv Invoice
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketInvoices).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &inv)
	})
	return inv, err
}

// MarkInvoicePaid marks an invoice paid exactly once (Part 2 §7.3 step 5):
// a second call fails with ErrExists so duplicate proposals cannot double-
// fire webhooks.
func (s *Store) MarkInvoicePaid(id string, by ChannelKey, seq uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketInvoices)
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var inv Invoice
		if err := json.Unmarshal(raw, &inv); err != nil {
			return err
		}
		if inv.Paid {
			return ErrExists
		}
		inv.Paid = true
		inv.PaidBy = &by
		inv.PaidSeq = seq
		out, err := json.Marshal(inv)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), out)
	})
}

// ------------------------------------------------------------------ tower

// PutDelegation stores a delegated complete state, keeping only the max seq
// per channel (Part 2 §9). Returns the seq now on file; a stale delegation
// is a silent no-op (idempotent intake).
func (s *Store) PutDelegation(d Delegation) (keptSeq uint64, err error) {
	if !d.State.Complete() {
		return 0, fmt.Errorf("%w: delegation state is not dual-signed", ErrBadState)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return 0, err
	}
	key := []byte(d.State.Key.String())
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTower)
		if prev := b.Get(key); prev != nil {
			var have Delegation
			if err := json.Unmarshal(prev, &have); err != nil {
				// An undecodable record must not block the delegator from
				// replacing it: move it aside and let the fresh one land.
				if err := quarantine(tx, d.State.Key, prev, err); err != nil {
					return err
				}
			} else if have.State.Seq >= d.State.Seq {
				keptSeq = have.State.Seq
				return nil
			}
		}
		keptSeq = d.State.Seq
		return b.Put(key, raw)
	})
	return keptSeq, err
}

// quarantine moves the live delegation record for key into the quarantine
// bucket with the decode error that condemned it.
func quarantine(tx *bolt.Tx, key ChannelKey, raw []byte, cause error) error {
	q := QuarantinedDelegation{Key: key, Raw: raw, Error: cause.Error(), AtUnix: time.Now().Unix()}
	enc, err := json.Marshal(q)
	if err != nil {
		return err
	}
	if err := tx.Bucket(bucketQuarantine).Put([]byte(key.String()), enc); err != nil {
		return err
	}
	return tx.Bucket(bucketTower).Delete([]byte(key.String()))
}

// QuarantineDelegation moves the live delegation record for key aside (see
// QuarantinedDelegation). It reports whether a live record was there to
// move; a key with none is a no-op.
func (s *Store) QuarantineDelegation(key ChannelKey, cause error) (moved bool, err error) {
	err = s.db.Update(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketTower).Get([]byte(key.String()))
		if raw == nil {
			return nil
		}
		moved = true
		return quarantine(tx, key, raw, cause)
	})
	return moved, err
}

// QuarantinedDelegation returns the quarantined record for key, or
// ErrNotFound.
func (s *Store) QuarantinedDelegation(key ChannelKey) (QuarantinedDelegation, error) {
	var q QuarantinedDelegation
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketQuarantine).Get([]byte(key.String()))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &q)
	})
	return q, err
}

// QuarantinedDelegations lists every quarantined record.
func (s *Store) QuarantinedDelegations() ([]QuarantinedDelegation, error) {
	var out []QuarantinedDelegation
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketQuarantine).ForEach(func(_, v []byte) error {
			var q QuarantinedDelegation
			if err := json.Unmarshal(v, &q); err != nil {
				return err
			}
			out = append(out, q)
			return nil
		})
	})
	return out, err
}

// ClearQuarantine discards the quarantined record for key; ErrNotFound when
// there is none.
func (s *Store) ClearQuarantine(key ChannelKey) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQuarantine)
		if b.Get([]byte(key.String())) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(key.String()))
	})
}

func (s *Store) Delegation(key ChannelKey) (Delegation, error) {
	var d Delegation
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketTower).Get([]byte(key.String()))
		if raw == nil {
			return ErrNotFound
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return fmt.Errorf("%w: delegation %s: %v", ErrCorrupt, key, err)
		}
		return nil
	})
	return d, err
}

// TowerWatermark returns the tower's confirmed-scan watermark for one
// registry (0 = never scanned).
func (s *Store) TowerWatermark(chainID string, registryAddr string) (uint64, error) {
	var v uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTower)
		raw := b.Get([]byte("__watermark:" + chainID + ":" + registryAddr))
		if raw != nil {
			var item struct {
				Block uint64 `json:"block"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			v = item.Block
		}
		return nil
	})
	return v, err
}

// SetTowerWatermark advances the tower's confirmed-scan watermark.
func (s *Store) SetTowerWatermark(chainID string, registryAddr string, block uint64) error {
	raw, err := json.Marshal(struct {
		Block uint64 `json:"block"`
	}{block})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTower).Put([]byte("__watermark:"+chainID+":"+registryAddr), raw)
	})
}

// DelegationCount returns the number of channels a delegator has on file
// (spam cap for open registration, Part 3 §10.2).
func (s *Store) DelegationCount(delegatorNpub string) (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTower).ForEach(func(_, v []byte) error {
			var d Delegation
			if err := json.Unmarshal(v, &d); err != nil {
				// An undecodable record has no attributable delegator; it
				// is quarantined the next time anything touches its key.
				return nil
			}
			if d.DelegatorNpub == delegatorNpub {
				n++
			}
			return nil
		})
	})
	return n, err
}
