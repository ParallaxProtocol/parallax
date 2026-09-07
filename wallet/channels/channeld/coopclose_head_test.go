package channeld

import (
	"context"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
)

// erroringBackend simulates an online node whose RPC is transiently failing:
// every chain call errors. Paths not exercised panic on the nil embedded
// interface.
type erroringBackend struct{ Backend }

var errRPCDown = errors.New("rpc down")

func (erroringBackend) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return nil, errRPCDown
}

func (erroringBackend) PendingNonceAt(ctx context.Context, account util.Address) (uint64, error) {
	return 0, errRPCDown
}

func (erroringBackend) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return nil, errRPCDown
}

// TestCoopCloseProposalDeferredWhenHeadUnavailable: countersigning freezes
// the channel until the proposal's expiry, and only the head can judge the
// expiry and freeze-horizon checks. An ONLINE node whose RPC hiccups must
// defer the proposal, not process it with nowBlock 0 — that skips both
// checks and auto-countersigns a near-forever freeze the security model says
// only offline QR scanners may skip the horizon for. The peer retransmits,
// so a deferred proposal is retried against a healthy RPC.
func TestCoopCloseProposalDeferredWhenHeadUnavailable(t *testing.T) {
	h := newHub()
	bob := newTestNode(t, h, nil) // proposer (offline node: no backend)

	alice := newTestNodeWithBackend(t, h, erroringBackend{}, nil)
	linkChannel(t, alice, bob)

	// A freeze grenade: expiry absurdly far in the future. The offline
	// proposer cannot judge the horizon (nowBlock 0 skips it by design).
	msg, err := bob.Engine.ProposeCoopClose(e2eKey, 1<<40, 0)
	if err != nil {
		t.Fatal(err)
	}
	rumor := encodeRumor(t, protocol.KindCoopCloseProposal, msg)
	if err := alice.handleRumor(context.Background(), rumor, bob.SelfPub); err == nil {
		t.Fatal("far-future close processed with no head view")
	}
	meta, err := alice.Store.Meta(e2eKey)
	if err != nil {
		t.Fatal(err)
	}
	if meta.FrozenUntilBlock != 0 || meta.PendingClose != nil {
		t.Fatalf("countersigned a far-future close during an RPC outage: frozen until block %d", meta.FrozenUntilBlock)
	}
}

// TestOutboundVerbsDeferredWhenHeadUnavailable: the outbound verbs have the
// same head requirement as the inbound handlers. An online node whose RPC is
// down computed expiry = 0 + validity — a block number in the distant past —
// and signed itself into a nonsense close (or withdraw voucher): the pending
// record blocks re-proposals while the peer NACKs "expiry not in the future"
// on every retransmission until it ages out.
func TestOutboundVerbsDeferredWhenHeadUnavailable(t *testing.T) {
	h := newHub()
	bob := newTestNode(t, h, nil)

	alice := newTestNodeWithBackend(t, h, erroringBackend{}, nil)
	linkChannel(t, alice, bob)

	ctx := context.Background()
	if err := alice.CoopClose(ctx, e2eKey); err == nil {
		t.Fatal("coop close signed with no head view")
	}
	meta, err := alice.Store.Meta(e2eKey)
	if err != nil {
		t.Fatal(err)
	}
	if meta.PendingClose != nil || meta.FrozenUntilBlock != 0 {
		t.Fatalf("close signed during an RPC outage: frozen until block %d", meta.FrozenUntilBlock)
	}

	if err := alice.Withdraw(ctx, e2eKey, big.NewInt(1e9)); err == nil {
		t.Fatal("withdraw signed with no head view")
	}
	meta, _ = alice.Store.Meta(e2eKey)
	if meta.PendingWithdraw != nil {
		t.Fatal("withdraw voucher signed during an RPC outage")
	}
	if n, _ := alice.Store.OutboundLen(); n != 0 {
		t.Fatalf("%d messages queued during an RPC outage", n)
	}
}

// headCountingBackend counts HeaderByNumber calls.
type headCountingBackend struct {
	Backend
	heads atomic.Int64
}

func (b *headCountingBackend) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	b.heads.Add(1)
	return &types.Header{Number: big.NewInt(500)}, nil
}

// TestHeadFetchedOnlyWhenNeeded: handleRumor fetched the chain head for
// EVERY inbound rumor, but only the proposal kinds (payment, coop-close,
// withdraw) consult it. ACKs, NACKs, invoices, and tower receipts each cost
// an RPC round trip per message for nothing — on a busy merchant that is
// one wasted head query per payment completion.
func TestHeadFetchedOnlyWhenNeeded(t *testing.T) {
	h := newHub()
	bob := newTestNode(t, h, nil)

	counting := &headCountingBackend{}
	alice := newTestNodeWithBackend(t, h, counting, nil)
	linkChannel(t, alice, bob)
	ctx := context.Background()

	// An ACK for nothing and a NACK for nothing: neither branch reads the
	// head, so neither may cost an RPC.
	ack := protocol.AckMsg{V: 1, ChannelID: "1", Seq: "1", StateHash: util.Hash{}.Hex()}
	_ = alice.handleRumor(ctx, encodeRumor(t, protocol.KindAck, &ack), bob.SelfPub)
	nack := protocol.NackMsg{V: 1, ChannelID: "1", Re: "21902", Seq: "9", Reason: protocol.NackPolicy}
	_ = alice.handleRumor(ctx, encodeRumor(t, protocol.KindNack, &nack), bob.SelfPub)
	if n := counting.heads.Load(); n != 0 {
		t.Fatalf("%d head fetches for rumors that never read the head", n)
	}

	// A payment proposal DOES consult the head (frozen check). The response
	// send fails (no relay is running here) — only the head fetch matters.
	prop, err := bob.Engine.ProposePayment(e2eKey, big.NewInt(1e9), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = alice.handleRumor(ctx, encodeRumor(t, protocol.KindProposal, prop), bob.SelfPub)
	if n := counting.heads.Load(); n == 0 {
		t.Fatal("proposal handled without a head view")
	}
}

// TestProposalDeferredWhenHeadUnavailable: check 6 counts a withdraw
// voucher as spent until its expiry block. An online node whose RPC is
// failing would judge that at nowBlock 0 — every recorded voucher looks
// live, including one that expired unsubmitted — and NACK a valid payment
// funded by the expired entitlement, poisoning the payer's channel. The
// proposal must be deferred like closes and withdraws are; the peer
// retransmits.
func TestProposalDeferredWhenHeadUnavailable(t *testing.T) {
	h := newHub()
	bob := newTestNode(t, h, nil)
	alice := newTestNodeWithBackend(t, h, erroringBackend{}, nil)
	linkChannel(t, alice, bob)

	prop, err := bob.Engine.ProposePayment(e2eKey, big.NewInt(1e9), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	err = alice.handleRumor(context.Background(), encodeRumor(t, protocol.KindProposal, prop), bob.SelfPub)
	if !errors.Is(err, errRPCDown) {
		t.Fatalf("proposal processed without a head view: %v", err)
	}
	latest, err := alice.Store.LatestState(e2eKey)
	if err == nil && latest.Seq != 0 {
		t.Fatalf("deferred proposal was countersigned at seq %d", latest.Seq)
	}
}
