package protocol

import (
	"errors"
	"math/big"
	"testing"
)

// TestCoopCloseRefusedWhileWithdrawVoucherLive: a cooperative close signs
// explicit balances against the confirmed funding view, and the contract
// requires their sum to equal the channel's available funds at submission.
// A countersigned withdraw voucher that mines first shrinks those funds and
// reverts the close, leaving both sides frozen until its expiry for
// nothing. Neither side may sign a close while a voucher is submittable;
// after the voucher expires (and is swept) the close proceeds.
func TestCoopCloseRefusedWhileWithdrawVoucherLive(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})

	voucherExpiry := nowBlock + 18
	prop, err := bob.engine.ProposeWithdraw(key, wei2, voucherExpiry, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := alice.engine.HandleWithdrawProposal(*prop, bob.npub, nowBlock)
	if err != nil || res.Ack == nil {
		t.Fatalf("countersign: %+v %v", res, err)
	}
	if _, err := bob.engine.HandleWithdrawAck(key, *res.Ack); err != nil {
		t.Fatal(err)
	}

	// Proposer of the voucher (own PendingWithdraw) and countersigner
	// (PeerPendingWithdraw) both refuse to propose a close.
	closeExpiry := nowBlock + 30
	if _, err := bob.engine.ProposeCoopClose(key, closeExpiry, nowBlock); !errors.Is(err, ErrWithdrawPending) {
		t.Fatalf("voucher holder proposed a close: %v", err)
	}
	if _, err := alice.engine.ProposeCoopClose(key, closeExpiry, nowBlock); !errors.Is(err, ErrWithdrawPending) {
		t.Fatalf("countersigner proposed a close: %v", err)
	}

	// A close proposal arriving from a peer with a stale view is NACKed,
	// not countersigned into a freeze (refused before the signature is
	// even examined).
	closeProp := &CoopCloseProposalMsg{
		V: 1, ChannelID: prop.ChannelID, Registry: prop.Registry, ChainID: prop.ChainID,
		BalanceA:     new(big.Int).Mul(big.NewInt(10), wei1).String(),
		BalanceB:     new(big.Int).Mul(big.NewInt(5), wei1).String(),
		ExpiryBlock:  big.NewInt(int64(closeExpiry)).String(),
		ProposerRole: "B",
	}
	cres, ready, err := alice.engine.HandleCoopCloseProposal(*closeProp, bob.npub, nowBlock)
	if err != nil || ready != nil || cres.Nack == nil || cres.Nack.Detail != "withdraw voucher outstanding" {
		t.Fatalf("close with a live voucher not refused: %+v %v", cres, err)
	}

	// Past the voucher's expiry the earmark is gone and the close proceeds.
	later := voucherExpiry + 1
	if err := bob.engine.SweepWithdraw(key, later); err != nil {
		t.Fatal(err)
	}
	if err := alice.engine.SweepWithdraw(key, later); err != nil {
		t.Fatal(err)
	}
	closeMsg, err := bob.engine.ProposeCoopClose(key, later+18, later)
	if err != nil {
		t.Fatalf("close after voucher expiry: %v", err)
	}
	cres, ready, err = alice.engine.HandleCoopCloseProposal(*closeMsg, bob.npub, later)
	if err != nil || cres.Ack == nil || ready == nil {
		t.Fatalf("close after voucher expiry not countersigned: %+v %v", cres, err)
	}
}
