package protocol

import (
	"errors"
	"strconv"
	"testing"
)

// payerInvoice stores the payer's copy of a merchant invoice (as received
// over 21901) alongside the merchant's own record.
func payerInvoice(t *testing.T, payer, merchant *party, id string) {
	t.Helper()
	invoiceFor(t, payer, id, wei1)
	invoiceFor(t, merchant, id, wei1)
}

func invoicePaid(t *testing.T, p *party, id string) bool {
	t.Helper()
	inv, err := p.store.Invoice(id)
	if err != nil {
		t.Fatal(err)
	}
	return inv.Paid
}

// TestProposePaymentRefusesPaidInvoice: the engine itself, under its lock,
// refuses a second payment of a held invoice, whatever path named it, and
// journals nothing for the refused proposal.
func TestProposePaymentRefusesPaidInvoice(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	payerInvoice(t, alice, bob, "inv1")

	pay(t, alice, bob, key, wei1, "inv1")
	if !invoicePaid(t, alice, "inv1") {
		t.Fatal("payer record not spent")
	}
	if _, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock); !errors.Is(err, ErrInvoicePaid) {
		t.Fatalf("second payment of a paid invoice: %v", err)
	}
	if journal, _ := alice.store.SelfSigned(key); len(journal) != 0 {
		t.Fatalf("refused payment was journaled: %+v", journal)
	}
}

// TestTiebreakLossReleasesInvoice: B's payment voided by A's re-issue above
// the conflict moved nothing, so its invoice is payable again.
func TestTiebreakLossReleasesInvoice(t *testing.T) {
	alice, bob, key := setupPair(t, Config{PushPayments: true}, Config{PushPayments: true})
	payerInvoice(t, bob, alice, "inv-b")

	propA, err := alice.engine.ProposePayment(key, wei1, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.engine.ProposePayment(key, wei1, "inv-b", nowBlock); err != nil {
		t.Fatal(err)
	}
	if !invoicePaid(t, bob, "inv-b") {
		t.Fatal("journal write did not spend the invoice")
	}
	if res, err := bob.engine.HandleProposal(*propA, alice.npub, nowBlock, nowUnix); err != nil || res.Ack != nil {
		t.Fatalf("B countersigned a conflicting variant: %+v %v", res, err)
	}
	re, err := alice.engine.RebaseProposal(key, 1, "", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	resB, err := bob.engine.HandleProposal(*re, alice.npub, nowBlock, nowUnix)
	if err != nil || resB.Ack == nil || len(resB.Voided) != 1 {
		t.Fatalf("B did not void its variant: %+v %v", resB, err)
	}
	if invoicePaid(t, bob, "inv-b") {
		t.Fatal("discarded intent left the invoice spent")
	}
	if _, err := alice.engine.HandleAck(key, *resB.Ack); err != nil {
		t.Fatal(err)
	}
	pay(t, bob, alice, key, wei1, "inv-b")
	if !invoicePaid(t, bob, "inv-b") {
		t.Fatal("re-issued payment did not spend the invoice")
	}
}

// TestTiebreakRebaseKeepsInvoiceSpent: A's payment re-issued above a
// same-seq conflict still pays the same invoice, so pruning the lost seq
// must not release it for a second payment.
func TestTiebreakRebaseKeepsInvoiceSpent(t *testing.T) {
	alice, bob, key := setupPair(t, Config{PushPayments: true}, Config{PushPayments: true})
	payerInvoice(t, alice, bob, "inv-a")

	if _, err := alice.engine.ProposePayment(key, wei1, "inv-a", nowBlock); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.engine.ProposePayment(key, wei2, "", nowBlock); err != nil {
		t.Fatal(err)
	}
	re, err := alice.engine.RebaseProposal(key, 1, "inv-a", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bob.engine.HandleProposal(*re, alice.npub, nowBlock, nowUnix)
	if err != nil || res.Ack == nil {
		t.Fatalf("rebased payment refused: %+v %v", res, err)
	}
	if _, err := alice.engine.HandleAck(key, *res.Ack); err != nil {
		t.Fatal(err)
	}
	if !invoicePaid(t, alice, "inv-a") {
		t.Fatal("completed rebase released the invoice it paid")
	}
	if _, err := alice.engine.ProposePayment(key, wei1, "inv-a", nowBlock); !errors.Is(err, ErrInvoicePaid) {
		t.Fatalf("invoice payable twice after rebase: %v", err)
	}
}

// TestSupersessionReleasesInvoice: the no-op supersession voids the NACKed
// payment, releasing its invoice.
func TestSupersessionReleasesInvoice(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	payerInvoice(t, alice, bob, "inv1")

	prop, err := alice.engine.ProposePayment(key, wei1, "inv1", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	n := NackMsg{V: 1, ChannelID: strconv.FormatUint(key.ChannelID, 10), Re: "21902", Seq: prop.State.Seq, Reason: NackPolicy}
	if _, err := alice.engine.HandleNack(key, n); err != nil {
		t.Fatal(err)
	}
	noop, err := alice.engine.ProposeNoOpSupersession(key, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bob.engine.HandleProposal(*noop, alice.npub, nowBlock, nowUnix)
	if err != nil || res.Ack == nil {
		t.Fatalf("no-op refused: %+v %v", res, err)
	}
	if _, err := alice.engine.HandleAck(key, *res.Ack); err != nil {
		t.Fatal(err)
	}
	if invoicePaid(t, alice, "inv1") {
		t.Fatal("voided payment left the invoice spent")
	}
	pay(t, alice, bob, key, wei1, "inv1")

	// The merchant's mark comes from completing the counterparty's
	// proposal, so it is never flagged as releasable.
	inv, err := bob.store.Invoice("inv1")
	if err != nil || !inv.Paid || inv.PaidByProposal {
		t.Fatalf("merchant mark wrong: %+v %v", inv, err)
	}
}
