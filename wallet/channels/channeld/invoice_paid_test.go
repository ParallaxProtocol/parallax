package channeld

import (
	"context"
	"math/big"
	"testing"
)

// TestResolveInvoiceRefusesPaid: the payer never marked a received invoice
// paid, so re-running `channel pay --invoice <id>` journaled a second
// irrevocable proposal the merchant NACKs "invoice already paid", poisoning
// the channel. The W1 write spends the local record, and ResolveInvoice
// refuses it from then on.
func TestResolveInvoiceRefusesPaid(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)

	if err := alice.handleInvoice(invoiceMsgFrom(bob, "inv-once", "1000"), bob.SelfPub); err != nil {
		t.Fatal(err)
	}
	key, amount, err := alice.ResolveInvoice("inv-once")
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Pay(context.Background(), key, amount, "inv-once"); err != nil {
		t.Fatal(err)
	}
	inv, err := alice.Store.Invoice("inv-once")
	if err != nil || !inv.Paid || inv.PaidBy == nil || *inv.PaidBy != key || inv.PaidSeq != 1 {
		t.Fatalf("invoice not spent by the proposal: %+v %v", inv, err)
	}
	if _, _, err := alice.ResolveInvoice("inv-once"); err == nil {
		t.Fatal("paid invoice resolved for a second payment")
	}

	// An invoice known only by id (URI path) has no record to spend and
	// must not fail the proposal.
	if _, err := bob.Engine.ProposePayment(e2eKey, big.NewInt(1), "not-stored", 0); err != nil {
		t.Fatalf("proposal with an unstored invoice id: %v", err)
	}
}
