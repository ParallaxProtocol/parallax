package protocol

import (
	"math/big"
	"testing"
)

// TestOversizedWireAmountsNacked: coop-close balances and withdraw totals
// are ABI-encoded into 32-byte words for the digest, and FillBytes panics
// on a wider value. A peer-supplied amount above 2^256-1 must be refused
// by the decoder, never reach the encoder.
func TestOversizedWireAmountsNacked(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	huge := new(big.Int).Lsh(big.NewInt(1), 256).String()

	prop, err := bob.engine.ProposeCoopClose(key, nowBlock+18, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(m *CoopCloseProposalMsg){
		func(m *CoopCloseProposalMsg) { m.BalanceA = huge },
		func(m *CoopCloseProposalMsg) { m.BalanceB = huge },
		func(m *CoopCloseProposalMsg) { m.BalanceA = "-1" },
	} {
		bad := *prop
		mutate(&bad)
		res, ready, err := alice.engine.HandleCoopCloseProposal(bad, bob.npub, nowBlock)
		if err != nil || ready != nil || res.Nack == nil || res.Nack.Detail != "bad balances" {
			t.Fatalf("oversized balance not refused: %+v %v", res, err)
		}
	}

	// A fresh pair: proposing the close above froze bob.
	alice, bob, key = setupPair(t, Config{}, Config{})
	wprop, err := bob.engine.ProposeWithdraw(key, wei1, nowBlock+18, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	bad := *wprop
	bad.TotalWithdrawn = huge
	res, ready, err := alice.engine.HandleWithdrawProposal(bad, bob.npub, nowBlock)
	if err != nil || ready != nil || res.Nack == nil || res.Nack.Detail != "bad totalWithdrawn" {
		t.Fatalf("oversized total not refused: %+v %v", res, err)
	}
}
