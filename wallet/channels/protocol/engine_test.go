package protocol

import (
	"errors"
	"math/big"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
)

const (
	nowBlock = uint64(2000)
	nowUnix  = int64(1_000_000)
)

var (
	wei1 = big.NewInt(1e18)
	wei2 = big.NewInt(2e18)
)

type party struct {
	engine *Engine
	store  *proofstore.Store
	signer *KeySigner
	npub   string
}

// setupPair creates two wallets sharing one channel: alice is participant A
// (10 LAX confirmed), bob is B (5 LAX confirmed).
func setupPair(t *testing.T, cfgA, cfgB Config) (alice, bob *party, key proofstore.ChannelKey) {
	t.Helper()
	key = proofstore.ChannelKey{
		ChainID:   "2110",
		Registry:  util.HexToAddress("0x00000000000000000000000000000000000021ff"),
		ChannelID: 1,
	}

	mk := func(name string, cfg Config) *party {
		priv, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		st, err := proofstore.Open(filepath.Join(t.TempDir(), name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		signer := NewKeySigner(priv)
		return &party{engine: New(st, signer, cfg), store: st, signer: signer, npub: name + "-npub"}
	}
	alice = mk("alice", cfgA)
	bob = mk("bob", cfgB)

	deposits := proofstore.Deposits{
		DepositA:         proofstore.NewU256(new(big.Int).Mul(big.NewInt(10), wei1)),
		DepositB:         proofstore.NewU256(new(big.Int).Mul(big.NewInt(5), wei1)),
		WithdrawnA:       proofstore.NewU256(nil),
		WithdrawnB:       proofstore.NewU256(nil),
		LastScannedBlock: nowBlock,
	}
	for _, p := range []struct {
		who  *party
		role proofstore.Role
		peer *party
	}{{alice, proofstore.RoleA, bob}, {bob, proofstore.RoleB, alice}} {
		meta := proofstore.ChannelMeta{
			Key:             key,
			Role:            p.role,
			Status:          proofstore.StatusOpen,
			PeerNpub:        p.peer.npub,
			PeerAddress:     p.peer.signer.Address(),
			ChallengePeriod: 144,
			OpenedAtBlock:   1000,
		}
		if err := p.who.store.CreateChannel(meta); err != nil {
			t.Fatal(err)
		}
		if err := p.who.store.PutDeposits(key, deposits); err != nil {
			t.Fatal(err)
		}
	}
	return alice, bob, key
}

func invoiceFor(t *testing.T, p *party, id string, amount *big.Int) {
	t.Helper()
	err := p.store.CreateInvoice(proofstore.Invoice{
		ID:        id,
		AmountWei: proofstore.NewU256(amount),
		ExpiresAt: nowUnix + 600,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// pay drives one full A-side payment through both engines and returns the
// final results.
func pay(t *testing.T, from, to *party, key proofstore.ChannelKey, amount *big.Int, invoiceID string) (Result, *proofstore.SignedState) {
	t.Helper()
	prop, err := from.engine.ProposePayment(key, amount, invoiceID, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, err := to.engine.HandleProposal(*prop, from.npub, nowBlock, nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	if res.Nack != nil {
		t.Fatalf("unexpected nack: %+v", res.Nack)
	}
	complete, err := from.engine.HandleAck(key, *res.Ack)
	if err != nil {
		t.Fatal(err)
	}
	return res, complete
}

func TestHappyPathPayment(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)

	res, complete := pay(t, alice, bob, key, wei1, "inv1")
	if res.Completed == nil || res.Ack == nil {
		t.Fatalf("responder result incomplete: %+v", res)
	}
	if complete.Seq != 1 || complete.TransferredAtoB.BigInt().Cmp(wei1) != 0 {
		t.Fatalf("completed state wrong: %+v", complete)
	}
	if !complete.Complete() {
		t.Fatal("state not dual-signed")
	}

	// Both sides converge on the same latest state; no journal residue.
	for _, p := range []*party{alice, bob} {
		latest, err := p.store.LatestState(key)
		if err != nil || latest.Seq != 1 {
			t.Fatalf("latest: %+v %v", latest, err)
		}
		if journal, _ := p.store.SelfSigned(key); len(journal) != 0 {
			t.Fatalf("journal not empty: %+v", journal)
		}
	}

	inv, _ := bob.store.Invoice("inv1")
	if !inv.Paid || inv.PaidSeq != 1 {
		t.Fatalf("invoice not marked paid: %+v", inv)
	}
}

func TestPaymentBothDirections(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)
	pay(t, alice, bob, key, wei1, "inv1")

	// B pays A back.
	invoiceFor(t, alice, "inv2", wei2)
	_, complete := pay(t, bob, alice, key, wei2, "inv2")
	if complete.Seq != 2 || complete.TransferredBtoA.BigInt().Cmp(wei2) != 0 ||
		complete.TransferredAtoB.BigInt().Cmp(wei1) != 0 {
		t.Fatalf("cumulative state wrong: %+v", complete)
	}
}

func TestDuplicateProposalReAcksIdempotently(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)

	prop, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res1, err := bob.engine.HandleProposal(*prop, alice.npub, nowBlock, nowUnix)
	if err != nil || res1.Ack == nil {
		t.Fatalf("first: %+v %v", res1, err)
	}
	// The retransmitted identical proposal re-ACKs with the same signature
	// and does not double-fire the invoice.
	res2, err := bob.engine.HandleProposal(*prop, alice.npub, nowBlock, nowUnix)
	if err != nil || res2.Ack == nil {
		t.Fatalf("duplicate: %+v %v", res2, err)
	}
	if res2.Ack.Sig != res1.Ack.Sig || res2.Ack.StateHash != res1.Ack.StateHash {
		t.Fatal("duplicate ack differs from original")
	}
	if res2.Completed != nil {
		t.Fatal("duplicate marked as newly completed")
	}
	// Duplicate ACK on the proposer is idempotent too.
	if _, err := alice.engine.HandleAck(key, *res1.Ack); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.engine.HandleAck(key, *res2.Ack); err != nil {
		t.Fatal(err)
	}
}

func TestOneInflightRule(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)
	if _, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock); !errors.Is(err, ErrProposalPending) {
		t.Fatalf("second proposal allowed: %v", err)
	}
}

func TestResponderRejections(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)

	base, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock)
	if err != nil {
		t.Fatal(err)
	}

	tamper := func(mut func(*ProposalMsg)) ProposalMsg {
		m := *base
		mut(&m)
		return m
	}

	cases := []struct {
		name   string
		msg    ProposalMsg
		sender string
		reason string
		drop   bool
	}{
		{"unknown sender dropped", *base, "mallory-npub", "", true},
		{"locks nonzero", tamper(func(m *ProposalMsg) { m.State.LockedAmount = "1" }), alice.npub, NackLocksNonzero, false},
		{"unknown invoice", tamper(func(m *ProposalMsg) { m.InvoiceID = "nope" }), alice.npub, NackPolicy, false},
		{"no invoice, push disabled", tamper(func(m *ProposalMsg) { m.InvoiceID = "" }), alice.npub, NackPolicy, false},
		{"tampered amount breaks sig", tamper(func(m *ProposalMsg) { m.State.TransferredAtoB = "999" }), alice.npub, NackPolicy, false},
	}
	for _, tc := range cases {
		res, err := bob.engine.HandleProposal(tc.msg, tc.sender, nowBlock, nowUnix)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.drop {
			if !res.Dropped || res.Nack != nil || res.Ack != nil {
				t.Fatalf("%s: expected silent drop: %+v", tc.name, res)
			}
			continue
		}
		if res.Nack == nil || res.Nack.Reason != tc.reason {
			t.Fatalf("%s: expected nack %q, got %+v", tc.name, tc.reason, res)
		}
	}
}

func TestRejectsWrongInvoiceAmountAndExpiry(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "small", big.NewInt(5))
	if err := bob.store.CreateInvoice(proofstore.Invoice{
		ID: "expired", AmountWei: proofstore.NewU256(wei1), ExpiresAt: nowUnix - 1,
	}); err != nil {
		t.Fatal(err)
	}

	prop, err := alice.engine.ProposePayment(key, wei1, "small", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := bob.engine.HandleProposal(*prop, alice.npub, nowBlock, nowUnix)
	if res.Nack == nil || res.Nack.Reason != NackPolicy {
		t.Fatalf("amount mismatch accepted: %+v", res)
	}

	m := *prop
	m.InvoiceID = "expired"
	res, _ = bob.engine.HandleProposal(m, alice.npub, nowBlock, nowUnix)
	if res.Nack == nil || res.Nack.Reason != NackExpiredInvoice {
		t.Fatalf("expired invoice accepted: %+v", res)
	}
}

func TestInsufficientConfirmedBalance(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{PushPayments: true})

	// A tries to send more than its confirmed deposit (10 LAX).
	tooMuch := new(big.Int).Mul(big.NewInt(11), wei1)
	if _, err := alice.engine.ProposePayment(key, tooMuch, "", nowBlock); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("own-side check: %v", err)
	}

	// Responder-side: B's confirmed view is authoritative even if A's wallet
	// lied to itself — simulate by raising A's local deposit view only.
	dep, _ := alice.store.Deposits(key)
	dep.DepositA = proofstore.NewU256(new(big.Int).Mul(big.NewInt(100), wei1))
	if err := alice.store.PutDeposits(key, dep); err != nil {
		t.Fatal(err)
	}
	prop, err := alice.engine.ProposePayment(key, tooMuch, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := bob.engine.HandleProposal(*prop, alice.npub, nowBlock, nowUnix)
	if res.Nack == nil || res.Nack.Reason != NackInsufficientBalance {
		t.Fatalf("overdraft accepted: %+v", res)
	}
}

func TestMaxInflightCap(t *testing.T) {
	alice, _, key := setupPair(t, Config{MaxInflightWei: wei1}, Config{})
	if _, err := alice.engine.ProposePayment(key, wei2, "x", nowBlock); !errors.Is(err, ErrInflightCap) {
		t.Fatalf("cap not enforced: %v", err)
	}
}

func TestTiebreakAWins(t *testing.T) {
	alice, bob, key := setupPair(t, Config{PushPayments: true}, Config{PushPayments: true})

	propA, err := alice.engine.ProposePayment(key, wei1, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	propB, err := bob.engine.ProposePayment(key, wei2, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}

	// Neither side countersigns the other's seq-1 variant: each already
	// signed a different payload there. A is told to re-issue its own.
	resA, err := alice.engine.HandleProposal(*propB, bob.npub, nowBlock, nowUnix)
	if err != nil || !resA.Dropped || resA.Ack != nil || resA.Rebase != 1 {
		t.Fatalf("A did not ignore and rebase: %+v %v", resA, err)
	}
	resB, err := bob.engine.HandleProposal(*propA, alice.npub, nowBlock, nowUnix)
	if err != nil || !resB.Dropped || resB.Ack != nil || resB.Rebase != 0 {
		t.Fatalf("B countersigned a conflicting variant: %+v %v", resB, err)
	}

	// A re-issues its payment at seq 2; a repeat returns the same state.
	re, err := alice.engine.RebaseProposal(key, 1, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := alice.engine.RebaseProposal(key, 1, "", nowBlock); err != nil || again.State != re.State {
		t.Fatalf("rebase not idempotent: %+v %v", again, err)
	}
	if re.State.Seq != "2" || re.State.TransferredAtoB != wei1.String() || re.State.TransferredBtoA != "0" {
		t.Fatalf("rebase wrong: %+v", re.State)
	}
	res2, err := bob.engine.HandleProposal(*re, alice.npub, nowBlock, nowUnix)
	if err != nil || res2.Ack == nil || len(res2.Voided) != 1 || res2.Voided[0] != 1 {
		t.Fatalf("rebased payment refused: %+v %v", res2, err)
	}
	if _, err := alice.engine.HandleAck(key, *res2.Ack); err != nil {
		t.Fatal(err)
	}

	// B's seq-1 variant died by seq; it re-issues its payment on A's totals,
	// and both payments land.
	prop3, err := bob.engine.ProposePayment(key, wei2, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	if prop3.State.Seq != "3" || prop3.State.TransferredAtoB != wei1.String() {
		t.Fatalf("B rebase wrong: %+v", prop3.State)
	}
	res3, err := alice.engine.HandleProposal(*prop3, bob.npub, nowBlock, nowUnix)
	if err != nil || res3.Ack == nil {
		t.Fatalf("B's re-issued payment refused: %+v %v", res3, err)
	}
	if _, err := bob.engine.HandleAck(key, *res3.Ack); err != nil {
		t.Fatal(err)
	}
	latest, _ := bob.store.LatestState(key)
	if latest.Seq != 3 || latest.TransferredAtoB.BigInt().Cmp(wei1) != 0 || latest.TransferredBtoA.BigInt().Cmp(wei2) != 0 {
		t.Fatalf("converged state wrong: %+v", latest)
	}
	if j, _ := alice.store.SelfSigned(key); len(j) != 0 {
		t.Fatalf("A journal not cleared: %+v", j)
	}
}

// TestTiebreakNeverEquivocates: B adopting A's conflicting seq-1 used to
// put B's signature on two payloads at seq 1. A then signed B's own variant
// too, holding two dual-signed seq-1 states, and closed with whichever
// dropped its invoice payment after B released the goods: the contract
// only lets a strictly higher seq challenge. B must never countersign at a
// seq it already signed, and the payment it does accept must land above
// every variant.
func TestTiebreakNeverEquivocates(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv-goods", wei1)

	propB, err := bob.engine.ProposePayment(key, wei2, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	propA, err := alice.engine.ProposePayment(key, wei1, "inv-goods", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	resB, err := bob.engine.HandleProposal(*propA, alice.npub, nowBlock, nowUnix)
	if err != nil || resB.Ack != nil || resB.Completed != nil {
		t.Fatalf("B countersigned A's conflicting seq 1: %+v %v", resB, err)
	}
	if inv, _ := bob.store.Invoice("inv-goods"); inv.Paid {
		t.Fatal("invoice marked paid without a countersigned state")
	}

	re, err := alice.engine.RebaseProposal(key, 1, "inv-goods", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := bob.engine.HandleProposal(*re, alice.npub, nowBlock, nowUnix)
	if err != nil || res2.Ack == nil || res2.InvoicePaid != "inv-goods" {
		t.Fatalf("rebased invoice payment refused: %+v %v", res2, err)
	}

	// The paying state sits above both seq-1 variants, B's own included, so
	// whichever A might complete and close with, B's challenge wins.
	bVariant, err := FromWire(propB.State)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Completed.Seq <= bVariant.Seq {
		t.Fatalf("paying state seq %d does not dominate B's variant at %d", res2.Completed.Seq, bVariant.Seq)
	}
	if inv, _ := bob.store.Invoice("inv-goods"); !inv.Paid || inv.PaidSeq != res2.Completed.Seq {
		t.Fatalf("invoice not credited at the dominating seq: %+v", inv)
	}
}

func TestNackPoisonsAndSupersessionCures(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)

	prop, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	seq := prop.State.Seq

	// B rejects (say, policy); A records the poison.
	n := NackMsg{V: 1, ChannelID: strconv.FormatUint(key.ChannelID, 10), Re: "21902", Seq: seq, Reason: NackPolicy}
	poisoned, err := alice.engine.HandleNack(key, n)
	if err != nil || !poisoned {
		t.Fatalf("nack not recorded: %v %v", poisoned, err)
	}
	meta, _ := alice.store.Meta(key)
	if !meta.Poisoned {
		t.Fatal("poisoned flag not set")
	}
	exposure, err := alice.engine.PoisonedExposure(key)
	if err != nil {
		t.Fatal(err)
	}
	if want := new(big.Int).Div(wei1, big.NewInt(5)); exposure.Cmp(want) != 0 {
		t.Fatalf("exposure: got %s want %s", exposure, want)
	}
	if _, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock); !errors.Is(err, ErrProposalPending) {
		t.Fatal("poisoned channel accepted a new payment")
	}

	// Cure: the no-op supersession at seq 2 with unchanged amounts.
	noop, err := alice.engine.ProposeNoOpSupersession(key, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	if noop.State.Seq != "2" || noop.State.TransferredAtoB != "0" {
		t.Fatalf("no-op wrong: %+v", noop.State)
	}
	res, err := bob.engine.HandleProposal(*noop, alice.npub, nowBlock, nowUnix)
	if err != nil || res.Ack == nil {
		t.Fatalf("no-op refused: %+v %v", res, err)
	}
	if _, err := alice.engine.HandleAck(key, *res.Ack); err != nil {
		t.Fatal(err)
	}

	meta, _ = alice.store.Meta(key)
	if meta.Poisoned {
		t.Fatal("poisoned flag not cleared after supersession completed")
	}
	if journal, _ := alice.store.SelfSigned(key); len(journal) != 0 {
		t.Fatalf("journal not cleared: %+v", journal)
	}
	// The channel is usable again.
	invoiceFor(t, bob, "inv2", wei1)
	pay(t, alice, bob, key, wei1, "inv2")
}

func TestAckVerification(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)
	prop, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bob.engine.HandleProposal(*prop, alice.npub, nowBlock, nowUnix)
	if err != nil {
		t.Fatal(err)
	}

	bad := *res.Ack
	bad.StateHash = util.Hash{0x01}.Hex()
	if _, err := alice.engine.HandleAck(key, bad); err == nil {
		t.Fatal("wrong stateHash accepted")
	}

	// Signature from a third party over the right digest.
	mallory, _ := crypto.GenerateKey()
	msig, _ := NewKeySigner(mallory).SignDigest(util.HexToHash(res.Ack.StateHash))
	bad = *res.Ack
	bad.Sig = "0x" + util.Bytes2Hex(msig)
	if _, err := alice.engine.HandleAck(key, bad); err == nil {
		t.Fatal("third-party ack accepted")
	}

	if _, err := alice.engine.HandleAck(key, AckMsg{V: 1, Seq: "42", StateHash: res.Ack.StateHash, Sig: res.Ack.Sig}); !errors.Is(err, ErrNoProposal) {
		t.Fatal("ack for unknown seq accepted")
	}
}

// TestNoOpProposalNeverReportsInvoicePaid: the invoice id rides in the
// unsigned envelope, so a zero-delta supersession naming a pending invoice
// used to read as that invoice's payment (a signed "paid" webhook for
// nothing). Only a real transition reports one.
func TestNoOpProposalNeverReportsInvoicePaid(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	invoiceFor(t, bob, "inv1", wei1)

	if _, err := alice.engine.ProposePayment(key, wei1, "", nowBlock); err != nil {
		t.Fatal(err)
	}
	noop, err := alice.engine.ProposeNoOpSupersession(key, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	noop.InvoiceID = "inv1"
	res, err := bob.engine.HandleProposal(*noop, alice.npub, nowBlock, nowUnix)
	if err != nil || res.Ack == nil {
		t.Fatalf("no-op refused: %+v %v", res, err)
	}
	if res.InvoicePaid != "" {
		t.Fatalf("zero-value proposal reported invoice %q paid", res.InvoicePaid)
	}
	if inv, _ := bob.store.Invoice("inv1"); inv.Paid {
		t.Fatal("zero-value proposal marked the invoice paid")
	}
	if _, err := alice.engine.HandleAck(key, *res.Ack); err != nil {
		t.Fatal(err)
	}

	res, _ = pay(t, alice, bob, key, wei1, "inv1")
	if res.InvoicePaid != "inv1" {
		t.Fatalf("real payment not reported: %+v", res)
	}
}
