package channeld

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
)

// TestAwaitPaymentNotFooledBySeqAdvance: `channel pay` declared success on
// ANY seq advance past the pre-payment state. A seq advance is not our
// payment: after a same-seq conflict the counterparty re-issues its payment
// above ours, voiding our intent — the CLI then printed "payment complete"
// for a payment that never happened. Completion means OUR outbound moved by
// the paid amount and nothing of ours is left journaled.
func TestAwaitPaymentNotFooledBySeqAdvance(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)
	ctx := context.Background()

	// Bob (role B) proposes his payment; before completion, alice's
	// conflicting proposal at the same seq arrives (Part 2 §7.5). Alice
	// re-issues hers at seq 2, and bob's countersignature voids his own.
	before, _ := bob.Store.LatestState(e2eKey)
	if err := bob.Pay(ctx, e2eKey, big.NewInt(1e9), ""); err != nil {
		t.Fatal(err)
	}
	aliceProp, err := alice.Engine.ProposePayment(e2eKey, big.NewInt(2e9), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := bob.Engine.HandleProposal(*aliceProp, alice.SelfPub, 0, time.Now().Unix()); err != nil || res.Ack != nil {
		t.Fatalf("conflicting variant countersigned: %+v %v", res, err)
	}
	re, err := alice.Engine.RebaseProposal(e2eKey, 1, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bob.Engine.HandleProposal(*re, alice.SelfPub, 0, time.Now().Unix())
	if err != nil || res.Ack == nil || len(res.Voided) != 1 {
		t.Fatalf("re-issue not countersigned: %+v %v", res, err)
	}

	// Bob's seq advanced (to alice's payment) but bob's own payment did NOT
	// complete: reporting success here tells the user their debt is paid
	// when it is not.
	if seq, err := bob.AwaitPayment(ctx, e2eKey, before, big.NewInt(1e9), 2*time.Second); err == nil {
		t.Fatalf("discarded payment intent reported as complete at seq %d", seq)
	}
}

// TestAwaitPaymentFailsFastOnNack: a NACK poisons the channel; the wait
// must surface that immediately instead of spinning out the full timeout.
func TestAwaitPaymentFailsFastOnNack(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)
	ctx := context.Background()

	before, _ := bob.Store.LatestState(e2eKey)
	if err := bob.Pay(ctx, e2eKey, big.NewInt(1e9), ""); err != nil {
		t.Fatal(err)
	}
	journal, _ := bob.Store.SelfSigned(e2eKey)
	if len(journal) != 1 {
		t.Fatalf("journal: %+v", journal)
	}
	nack := protocol.NackMsg{
		V: 1, ChannelID: "1", Re: "21902",
		Seq:    "1",
		Reason: protocol.NackPolicy,
	}
	if _, err := bob.Engine.HandleNack(e2eKey, nack); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err := bob.AwaitPayment(ctx, e2eKey, before, big.NewInt(1e9), 10*time.Second)
	if err == nil {
		t.Fatal("nacked payment reported as complete")
	}
	if !strings.Contains(err.Error(), "poisoned") {
		t.Fatalf("nack not surfaced: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("nack surfaced only after the full wait")
	}
}

// TestAwaitPaymentCompletes: the genuine flow still reports the seq.
func TestAwaitPaymentCompletes(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)
	ctx := context.Background()

	before, _ := bob.Store.LatestState(e2eKey)
	if err := bob.Pay(ctx, e2eKey, big.NewInt(1e9), ""); err != nil {
		t.Fatal(err)
	}
	journal, _ := bob.Store.SelfSigned(e2eKey)
	prop := protocol.ProposalMsg{V: 1, State: protocol.ToWire(journal[0]), ProposerRole: "B"}
	res, err := alice.Engine.HandleProposal(prop, bob.SelfPub, 0, time.Now().Unix())
	if err != nil || res.Ack == nil {
		t.Fatalf("countersign: %+v %v", res, err)
	}
	if _, err := bob.Engine.HandleAck(e2eKey, *res.Ack); err != nil {
		t.Fatal(err)
	}

	seq, err := bob.AwaitPayment(ctx, e2eKey, before, big.NewInt(1e9), 2*time.Second)
	if err != nil || seq != 1 {
		t.Fatalf("completed payment not reported: seq %d, %v", seq, err)
	}
}
