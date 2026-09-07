package proofstore

import (
	"bytes"
	"errors"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// plantCorrupt writes raw bytes under key in the live delegation bucket,
// bypassing PutDelegation (which refuses anything invalid).
func plantCorrupt(t *testing.T, s *Store, key ChannelKey, raw []byte) {
	t.Helper()
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTower).Put([]byte(key.String()), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDelegationCorruptIsTyped: a record that no longer decodes surfaces as
// ErrCorrupt, distinct from ErrNotFound, so the tower can tell "nobody
// delegated" from "delegated, but the bytes are bad".
func TestDelegationCorruptIsTyped(t *testing.T) {
	s := openStore(t)
	if _, err := s.Delegation(testKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent delegation: %v", err)
	}
	plantCorrupt(t, s, testKey, []byte("{corrupt"))
	_, err := s.Delegation(testKey)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt delegation: %v, want ErrCorrupt", err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("corrupt record reported as not found")
	}
}

// TestQuarantineRoundTrip: quarantining moves the raw bytes and the cause
// aside, leaves the live set empty for the key, lists, and clears.
func TestQuarantineRoundTrip(t *testing.T) {
	s := openStore(t)
	if moved, err := s.QuarantineDelegation(testKey, errors.New("x")); err != nil || moved {
		t.Fatalf("quarantine of an absent record: moved=%v err=%v", moved, err)
	}
	plantCorrupt(t, s, testKey, []byte("{corrupt"))
	cause := errors.New("json: unexpected end")
	moved, err := s.QuarantineDelegation(testKey, cause)
	if err != nil || !moved {
		t.Fatalf("quarantine: moved=%v err=%v", moved, err)
	}
	if _, err := s.Delegation(testKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("live record after quarantine: %v, want ErrNotFound", err)
	}
	q, err := s.QuarantinedDelegation(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if q.Key != testKey || !bytes.Equal(q.Raw, []byte("{corrupt")) || q.Error != cause.Error() || q.AtUnix == 0 {
		t.Fatalf("quarantined record: %+v", q)
	}
	all, err := s.QuarantinedDelegations()
	if err != nil || len(all) != 1 || all[0].Key != testKey {
		t.Fatalf("list: %+v %v", all, err)
	}
	if err := s.ClearQuarantine(testKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QuarantinedDelegation(testKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after clear: %v", err)
	}
	if err := s.ClearQuarantine(testKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second clear: %v", err)
	}
}

// TestPutDelegationReplacesCorruptRecord: a fresh delegation from the
// channel's delegator must land over an undecodable predecessor (which
// goes to quarantine) rather than fail on reading it, and the open-
// registration cap must keep counting while the bad record is present.
func TestPutDelegationReplacesCorruptRecord(t *testing.T) {
	s := openStore(t)
	plantCorrupt(t, s, testKey, []byte("{corrupt"))
	if n, err := s.DelegationCount("d1"); err != nil || n != 0 {
		t.Fatalf("count over a corrupt record: n=%d err=%v", n, err)
	}
	kept, err := s.PutDelegation(Delegation{State: state(4, 1, 0, RoleA, RoleB), DelegatorNpub: "d1"})
	if err != nil || kept != 4 {
		t.Fatalf("put over corrupt record: kept=%d err=%v", kept, err)
	}
	d, err := s.Delegation(testKey)
	if err != nil || d.State.Seq != 4 {
		t.Fatalf("live record after replacement: %+v %v", d, err)
	}
	if q, err := s.QuarantinedDelegation(testKey); err != nil || !bytes.Equal(q.Raw, []byte("{corrupt")) {
		t.Fatalf("predecessor not quarantined: %+v %v", q, err)
	}
	if n, err := s.DelegationCount("d1"); err != nil || n != 1 {
		t.Fatalf("count after replacement: n=%d err=%v", n, err)
	}
}

func TestParseChannelKey(t *testing.T) {
	got, err := ParseChannelKey(testKey.String())
	if err != nil || got != testKey {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"", "2110", "2110:0x12:3", "2110:" + testKey.Registry.Hex(), testKey.String() + ":x", "2110:" + testKey.Registry.Hex() + ":-1"} {
		if _, err := ParseChannelKey(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
}
