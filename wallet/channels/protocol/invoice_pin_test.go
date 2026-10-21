package protocol

import (
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
)

// TestInvoicePinQualifiedByRegistry: coexisting registries both number
// channels from 1, so a pin held as a bare uint64 matches the wrong
// channel's twin. A payment over the same-id channel on the OTHER registry
// must not satisfy a pinned invoice — it would mark the invoice paid on the
// wrong channel and NACK the intended payer after their irrevocable journal
// write.
func TestInvoicePinQualifiedByRegistry(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})

	// The same peer pair shares channel id 1 on a second registry.
	twin := key
	twin.Registry = util.HexToAddress("0x0000000000000000000000000000000000001111")
	for _, p := range []struct {
		who  *party
		role proofstore.Role
		peer *party
	}{{alice, proofstore.RoleA, bob}, {bob, proofstore.RoleB, alice}} {
		err := p.who.store.CreateChannel(proofstore.ChannelMeta{
			Key:             twin,
			Role:            p.role,
			Status:          proofstore.StatusOpen,
			PeerNpub:        p.peer.npub,
			PeerAddress:     p.peer.signer.Address(),
			ChallengePeriod: 144,
			OpenedAtBlock:   1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		dep, _ := p.who.store.Deposits(key)
		if err := p.who.store.PutDeposits(twin, dep); err != nil {
			t.Fatal(err)
		}
	}

	// Bob's invoice is pinned to channel 1 on the ORIGINAL registry.
	err := bob.store.CreateInvoice(proofstore.Invoice{
		ID:        "pinned",
		AmountWei: proofstore.NewU256(wei1),
		ExpiresAt: nowUnix + 600,
		ChannelID: key.ChannelID,
		Registry:  key.Registry,
		ChainID:   key.ChainID,
		Merchant:  bob.signer.Address(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A payment over the twin channel referencing the pinned invoice must be
	// refused — the pin names a different channel.
	prop, err := alice.engine.ProposePayment(twin, wei1, "pinned", nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bob.engine.HandleProposal(*prop, alice.npub, nowBlock, nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	if res.Nack == nil || res.Nack.Reason != NackPolicy {
		t.Fatalf("pinned invoice satisfied by its same-id twin on another registry: %+v", res)
	}
	if inv, _ := bob.store.Invoice("pinned"); inv.Paid {
		t.Fatal("invoice marked paid by the wrong channel")
	}

	// The intended channel still pays it.
	pay(t, alice, bob, key, wei1, "pinned")
	if inv, _ := bob.store.Invoice("pinned"); !inv.Paid {
		t.Fatal("payment on the pinned channel not credited")
	}
}
