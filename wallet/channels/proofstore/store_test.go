package proofstore

import (
	"bytes"
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/util"
)

var testKey = ChannelKey{
	ChainID:   "2110",
	Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
	ChannelID: 17,
}

func sig(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 65)
}

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "proofs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newChannel(t *testing.T, s *Store, role Role) ChannelMeta {
	t.Helper()
	meta := ChannelMeta{
		Key:             testKey,
		Role:            role,
		PeerNpub:        "ab12",
		PeerAddress:     util.HexToAddress("0xbb00000000000000000000000000000000000bb0"),
		ChallengePeriod: 144,
		OpenedAtBlock:   1000,
	}
	if err := s.CreateChannel(meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

// state builds a SignedState; whoSigned lists roles whose sig slots to fill.
func state(seq uint64, tAB, tBA int64, whoSigned ...Role) SignedState {
	st := SignedState{
		Key:             testKey,
		Seq:             seq,
		TransferredAtoB: NewU256(big.NewInt(tAB)),
		TransferredBtoA: NewU256(big.NewInt(tBA)),
		LockedAmount:    NewU256(nil),
	}
	for _, r := range whoSigned {
		if r == RoleA {
			st.SigA = sig(0xaa)
		} else {
			st.SigB = sig(0xbb)
		}
	}
	return st
}

func TestChannelLifecycle(t *testing.T) {
	s := openStore(t)
	meta := newChannel(t, s, RoleA)

	if err := s.CreateChannel(meta); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	got, err := s.Meta(testKey)
	if err != nil || got.PeerNpub != "ab12" || got.Role != RoleA {
		t.Fatalf("meta roundtrip: %+v %v", got, err)
	}

	if err := s.UpdateMeta(testKey, func(m *ChannelMeta) { m.Poisoned = true; m.FrozenUntilBlock = 1234 }); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Meta(testKey)
	if !got.Poisoned || got.FrozenUntilBlock != 1234 {
		t.Fatalf("flags not persisted: %+v", got)
	}

	if err := s.UpdateMeta(testKey, func(m *ChannelMeta) { m.Role = RoleB }); err == nil {
		t.Fatal("role change accepted")
	}

	list, err := s.ListChannels()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
}

func TestW1SelfSignedJournal(t *testing.T) {
	s := openStore(t)
	newChannel(t, s, RoleA)

	if err := s.PutSelfSigned(state(1, 5, 0, RoleB)); !errors.Is(err, ErrBadState) {
		t.Fatalf("missing own sig accepted: %v", err)
	}

	st := state(1, 5, 0, RoleA)
	if err := s.PutSelfSigned(st); err != nil {
		t.Fatal(err)
	}
	// Idempotent re-journal (retransmission path).
	if err := s.PutSelfSigned(st); err != nil {
		t.Fatalf("identical re-put rejected: %v", err)
	}

	out, err := s.SelfSigned(testKey)
	if err != nil || len(out) != 1 || out[0].Seq != 1 {
		t.Fatalf("journal: %+v %v", out, err)
	}
}

func TestW3EquivocationRejected(t *testing.T) {
	s := openStore(t)
	newChannel(t, s, RoleA)

	if err := s.PutSelfSigned(state(1, 5, 0, RoleA)); err != nil {
		t.Fatal(err)
	}
	// Different payload, same seq, my signature: the one unforgivable sin.
	if err := s.PutSelfSigned(state(1, 6, 0, RoleA)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("equivocation accepted: %v", err)
	}
	// Also via the complete path: a dual-signed state at seq 1 with a
	// different payload would carry my signature over conflicting content.
	if err := s.PutComplete(state(1, 7, 0, RoleA, RoleB)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("conflicting complete accepted: %v", err)
	}
	// The matching payload completes fine.
	if err := s.PutComplete(state(1, 5, 0, RoleA, RoleB)); err != nil {
		t.Fatal(err)
	}
	// After completion, signing different content at that seq stays fatal.
	if err := s.PutSelfSigned(state(1, 9, 0, RoleA)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("post-completion equivocation accepted: %v", err)
	}
	// Identical content is an idempotent no-op.
	if err := s.PutSelfSigned(state(1, 5, 0, RoleA)); err != nil {
		t.Fatalf("idempotent no-op rejected: %v", err)
	}
}

func TestMonotonicityAndPruning(t *testing.T) {
	s := openStore(t)
	newChannel(t, s, RoleA)

	if err := s.PutComplete(state(3, 10, 2, RoleA, RoleB)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutComplete(state(2, 9, 2, RoleA, RoleB)); !errors.Is(err, ErrStaleSeq) {
		t.Fatalf("regression accepted: %v", err)
	}
	if err := s.PutComplete(state(3, 10, 2, RoleA, RoleB)); err != nil {
		t.Fatalf("idempotent complete rejected: %v", err)
	}
	if err := s.PutSelfSigned(state(2, 9, 2, RoleA)); !errors.Is(err, ErrStaleSeq) {
		t.Fatalf("stale self-signed accepted: %v", err)
	}

	// Supersession flow: journal N+1 (poisoned) and the no-op N+2.
	if err := s.PutSelfSigned(state(4, 11, 2, RoleA)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSelfSigned(state(5, 10, 2, RoleA)); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.SelfSigned(testKey); len(out) != 2 {
		t.Fatalf("expected 2 outstanding, got %d", len(out))
	}

	// N+2 completes: both journal entries prune (<= 5).
	if err := s.PutComplete(state(5, 10, 2, RoleA, RoleB)); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.SelfSigned(testKey); len(out) != 0 {
		t.Fatalf("journal not pruned: %+v", out)
	}
	latest, err := s.LatestState(testKey)
	if err != nil || latest.Seq != 5 {
		t.Fatalf("latest: %+v %v", latest, err)
	}
}

func TestLateAckAfterSupersessionProposal(t *testing.T) {
	s := openStore(t)
	newChannel(t, s, RoleA)

	// Journal N+1, then the superseding no-op N+2 while N+1 is unacked.
	if err := s.PutSelfSigned(state(1, 5, 0, RoleA)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSelfSigned(state(2, 5, 0, RoleA)); err != nil {
		t.Fatal(err)
	}
	// The late ACK for N+1 arrives: completes against the journaled payload,
	// pruning only N+1; the N+2 proposal stays outstanding.
	if err := s.PutComplete(state(1, 5, 0, RoleA, RoleB)); err != nil {
		t.Fatal(err)
	}
	out, _ := s.SelfSigned(testKey)
	if len(out) != 1 || out[0].Seq != 2 {
		t.Fatalf("expected only seq 2 outstanding: %+v", out)
	}
}

// TestNoSameSeqAdoption: a counterparty's different payload at a seq this
// wallet already signed is never completed; that would leave this wallet's
// signature on two payloads at one seq (Part 2 §7.5).
func TestNoSameSeqAdoption(t *testing.T) {
	s := openStore(t)
	newChannel(t, s, RoleB)

	if err := s.PutSelfSigned(state(1, 0, 5, RoleB)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutComplete(state(1, 7, 0, RoleA, RoleB)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("conflicting same-seq state completed: %v", err)
	}
	// The re-issue one seq above voids the journaled variant by seq.
	if err := s.PutComplete(state(2, 7, 0, RoleA, RoleB)); err != nil {
		t.Fatal(err)
	}
	if out, _ := s.SelfSigned(testKey); len(out) != 0 {
		t.Fatalf("voided variant not pruned: %+v", out)
	}
}

// TestRebaseMovesInvoiceMark: the re-issue carries the same payment, so the
// invoice the lost seq spent stays spent once that seq is pruned.
func TestRebaseMovesInvoiceMark(t *testing.T) {
	s := openStore(t)
	newChannel(t, s, RoleA)
	if err := s.CreateInvoice(Invoice{ID: "inv", AmountWei: NewU256(big.NewInt(5)), ExpiresAt: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSelfSignedPayment(state(1, 5, 0, RoleA), "inv"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSelfSignedRebase(state(2, 5, 0, RoleA), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.PutComplete(state(2, 5, 0, RoleA, RoleB)); err != nil {
		t.Fatal(err)
	}
	inv, err := s.Invoice("inv")
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Paid || inv.PaidSeq != 2 {
		t.Fatalf("rebase lost the invoice mark: %+v", inv)
	}
	if err := s.PutSelfSignedRebase(state(3, 5, 0, RoleA), 3); err == nil {
		t.Fatal("rebase onto its own seq accepted")
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proofs.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	meta := ChannelMeta{Key: testKey, Role: RoleB, ChallengePeriod: 36}
	if err := s.CreateChannel(meta); err != nil {
		t.Fatal(err)
	}
	if err := s.PutComplete(state(7, 100, 50, RoleA, RoleB)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSelfSigned(state(8, 100, 60, RoleB)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateMeta(testKey, func(m *ChannelMeta) { m.Poisoned = true }); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	m, err := s2.Meta(testKey)
	if err != nil || !m.Poisoned {
		t.Fatalf("poisoned flag lost: %+v %v", m, err)
	}
	latest, err := s2.LatestState(testKey)
	if err != nil || latest.Seq != 7 || latest.TransferredAtoB.BigInt().Int64() != 100 {
		t.Fatalf("state lost: %+v %v", latest, err)
	}
	out, err := s2.SelfSigned(testKey)
	if err != nil || len(out) != 1 || out[0].Seq != 8 {
		t.Fatalf("journal lost: %+v %v", out, err)
	}
	// W3 still enforced against reloaded journal.
	if err := s2.PutSelfSigned(state(8, 100, 61, RoleB)); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("equivocation after reopen: %v", err)
	}
}

func TestDeposits(t *testing.T) {
	s := openStore(t)
	newChannel(t, s, RoleA)

	d, err := s.Deposits(testKey)
	if err != nil || d.DepositA.BigInt().Sign() != 0 {
		t.Fatalf("zero deposits: %+v %v", d, err)
	}
	d.DepositA = NewU256(big.NewInt(1e18))
	d.LastScannedBlock = 555
	if err := s.PutDeposits(testKey, d); err != nil {
		t.Fatal(err)
	}
	d2, _ := s.Deposits(testKey)
	if d2.DepositA.BigInt().Cmp(big.NewInt(1e18)) != 0 || d2.LastScannedBlock != 555 {
		t.Fatalf("deposits roundtrip: %+v", d2)
	}
}

func TestInvoiceExactlyOnce(t *testing.T) {
	s := openStore(t)
	inv := Invoice{ID: "00112233445566778899aabbccddeeff", AmountWei: NewU256(big.NewInt(5))}
	if err := s.CreateInvoice(inv); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvoice(inv); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate invoice: %v", err)
	}
	if err := s.MarkInvoicePaid(inv.ID, testKey, 4); err != nil {
		t.Fatal(err)
	}
	// Duplicate proposal must not double-fire (exactly-once).
	if err := s.MarkInvoicePaid(inv.ID, testKey, 4); !errors.Is(err, ErrExists) {
		t.Fatalf("double-paid: %v", err)
	}
	got, _ := s.Invoice(inv.ID)
	if !got.Paid || got.PaidSeq != 4 || got.PaidBy == nil || *got.PaidBy != testKey {
		t.Fatalf("invoice state: %+v", got)
	}
}

func TestDelegationKeepsMaxSeq(t *testing.T) {
	s := openStore(t)

	kept, err := s.PutDelegation(Delegation{State: state(5, 1, 0, RoleA, RoleB), DelegatorNpub: "d1"})
	if err != nil || kept != 5 {
		t.Fatalf("kept %d %v", kept, err)
	}
	// Stale delegation is a no-op.
	kept, err = s.PutDelegation(Delegation{State: state(3, 1, 0, RoleA, RoleB), DelegatorNpub: "d1"})
	if err != nil || kept != 5 {
		t.Fatalf("stale overwrote: kept %d %v", kept, err)
	}
	kept, err = s.PutDelegation(Delegation{State: state(9, 2, 0, RoleA, RoleB), DelegatorNpub: "d1"})
	if err != nil || kept != 9 {
		t.Fatalf("kept %d %v", kept, err)
	}
	d, err := s.Delegation(testKey)
	if err != nil || d.State.Seq != 9 {
		t.Fatalf("delegation: %+v %v", d, err)
	}
	// Single-signature delegations are rejected.
	if _, err := s.PutDelegation(Delegation{State: state(10, 2, 0, RoleA)}); !errors.Is(err, ErrBadState) {
		t.Fatalf("incomplete delegation accepted: %v", err)
	}
	n, err := s.DelegationCount("d1")
	if err != nil || n != 1 {
		t.Fatalf("count: %d %v", n, err)
	}
}
