package protocol

import (
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
)

// signedPaymentFrom builds a payment proposal directly (bypassing the
// proposer engine's local checks), signed by the proposer — the adversarial
// counterparty the responder checks must stand alone against.
func signedPaymentFrom(t *testing.T, p *party, role proofstore.Role, key proofstore.ChannelKey, seq uint64, tAB, tBA *big.Int) ProposalMsg {
	t.Helper()
	st := proofstore.SignedState{
		Key:             key,
		Seq:             seq,
		TransferredAtoB: proofstore.NewU256(tAB),
		TransferredBtoA: proofstore.NewU256(tBA),
		LockedAmount:    proofstore.NewU256(nil),
	}
	digest, err := st.Digest()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := p.signer.SignDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	if role == proofstore.RoleA {
		st.SigA = sig
	} else {
		st.SigB = sig
	}
	return ProposalMsg{V: 1, State: ToWire(st), ProposerRole: string(role)}
}

// TestCountersignedWithdrawSpendsEntitlement: once the responder
// countersigns a withdraw voucher, the peer holds a submittable claim on
// that entitlement until expiry — a payment spending the same funds must be
// refused on both sides, or the peer withdraws on-chain after paying with
// the money and the settle clamp puts the loss on the responder.
func TestCountersignedWithdrawSpendsEntitlement(t *testing.T) {
	alice, bob, key := setupPair(t, Config{PushPayments: true}, Config{})
	five := new(big.Int).Mul(big.NewInt(5), wei1)

	// Bob withdraws his entire 5-LAX entitlement; alice countersigns.
	prop, err := bob.engine.ProposeWithdraw(key, five, nowBlock+18, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	res, ready, err := alice.engine.HandleWithdrawProposal(*prop, bob.npub, nowBlock)
	if err != nil || res.Ack == nil || ready == nil {
		t.Fatalf("countersign: %+v %v", res, err)
	}

	// Bob's own engine refuses to pay with the earmarked funds.
	if _, err := bob.engine.ProposePayment(key, five, "", nowBlock); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("proposer spent funds earmarked by its own pending withdraw: %v", err)
	}

	// And alice's responder check stands alone against a forged spend of the
	// same 5 LAX (voucher not yet confirmed on-chain: WithdrawnB still 0).
	forged := signedPaymentFrom(t, bob, proofstore.RoleB, key, 1, new(big.Int), five)
	res2, err := alice.engine.HandleProposal(forged, bob.npub, nowBlock, nowUnix)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Nack == nil || res2.Nack.Reason != NackInsufficientBalance {
		t.Fatalf("payment double-spending a countersigned withdraw voucher accepted: %+v", res2)
	}

	// Once the chain confirms the withdrawal, the same figures balance out:
	// bob's remaining entitlement is zero either way, but a 1-wei payment
	// funded by a fresh confirmed deposit goes through.
	dep, _ := alice.store.Deposits(key)
	dep.WithdrawnB = proofstore.NewU256(five)
	dep.DepositB = proofstore.NewU256(new(big.Int).Add(five, wei1))
	if err := alice.store.PutDeposits(key, dep); err != nil {
		t.Fatal(err)
	}
	if err := alice.engine.SweepWithdraw(key, nowBlock); err != nil {
		t.Fatal(err)
	}
	fresh := signedPaymentFrom(t, bob, proofstore.RoleB, key, 1, new(big.Int), wei1)
	res3, err := alice.engine.HandleProposal(fresh, bob.npub, nowBlock, nowUnix)
	if err != nil || res3.Ack == nil {
		t.Fatalf("payment against confirmed funds refused: %+v %v", res3, err)
	}
}

// TestPeerWithdrawVoucherSweep: the responder-side voucher record must clear
// on expiry (the claim is no longer submittable) so the entitlement frees up
// again, exactly like the proposer-side PendingWithdraw.
func TestPeerWithdrawVoucherSweep(t *testing.T) {
	alice, bob, key := setupPair(t, Config{PushPayments: true}, Config{})
	five := new(big.Int).Mul(big.NewInt(5), wei1)
	expiry := nowBlock + 18

	prop, err := bob.engine.ProposeWithdraw(key, five, expiry, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := alice.engine.HandleWithdrawProposal(*prop, bob.npub, nowBlock); err != nil {
		t.Fatal(err)
	}

	// Expired without submission: sweep clears the earmark on both sides.
	if err := alice.engine.SweepWithdraw(key, expiry+1); err != nil {
		t.Fatal(err)
	}
	if err := bob.engine.SweepWithdraw(key, expiry+1); err != nil {
		t.Fatal(err)
	}
	pay := signedPaymentFrom(t, bob, proofstore.RoleB, key, 1, new(big.Int), five)
	res, err := alice.engine.HandleProposal(pay, bob.npub, expiry+1, nowUnix)
	if err != nil || res.Ack == nil {
		t.Fatalf("entitlement still earmarked after voucher expiry: %+v %v", res, err)
	}
	if _, err := bob.engine.ProposeWithdraw(key, five, expiry+40, expiry+1); err != nil {
		t.Fatalf("proposer still blocked after voucher expiry: %v", err)
	}
}

// TestWithdrawExpiryHorizon: a withdraw voucher earmarks entitlement until
// its expiry, so the expiry must be bounded like a coop-close freeze — an
// effectively-infinite one makes the earmark permanent.
func TestWithdrawExpiryHorizon(t *testing.T) {
	alice, bob, key := setupPair(t, Config{}, Config{})
	farFuture := nowBlock + DefaultCoopCloseHorizonBlocks + 1

	if _, err := bob.engine.ProposeWithdraw(key, wei1, farFuture, nowBlock); err == nil {
		t.Fatal("own withdraw proposal signed beyond the horizon")
	}

	prop, err := bob.engine.ProposeWithdraw(key, wei1, nowBlock+18, nowBlock)
	if err != nil {
		t.Fatal(err)
	}
	forged := *prop
	forged.ExpiryBlock = strconv.FormatUint(farFuture, 10)
	res, ready, err := alice.engine.HandleWithdrawProposal(forged, bob.npub, nowBlock)
	if err != nil || ready != nil || res.Nack == nil {
		t.Fatalf("beyond-horizon expiry countersigned: %+v %v", res, err)
	}
	// The in-horizon original still passes.
	res, ready, err = alice.engine.HandleWithdrawProposal(*prop, bob.npub, nowBlock)
	if err != nil || res.Ack == nil || ready == nil {
		t.Fatalf("genuine refused: %+v %v", res, err)
	}
}

// signedWithdrawFrom builds a 21911 signed by p directly, bypassing its own
// engine's guards (the adversarial proposer).
func signedWithdrawFrom(t *testing.T, p *party, key proofstore.ChannelKey, total *big.Int, expiry uint64) WithdrawProposalMsg {
	t.Helper()
	d, err := withdrawDigest(key, p.signer.Address(), total, expiry)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := p.signer.SignDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	return WithdrawProposalMsg{
		V: 1, ChannelID: strconv.FormatUint(key.ChannelID, 10),
		Registry: strings.ToLower(key.Registry.Hex()), ChainID: key.ChainID,
		Participant: strings.ToLower(p.signer.Address().Hex()), TotalWithdrawn: total.String(),
		ExpiryBlock: strconv.FormatUint(expiry, 10), Sig: "0x" + util.Bytes2Hex(sig),
	}
}

// TestPeerWithdrawReplacementCannotShortenExpiry: the responder keeps one
// peer voucher record. A higher-total replacement expiring sooner used to
// overwrite it, so once the replacement lapsed nothing earmarked the first
// voucher, which stayed dual-signed and submittable: the peer spent the same
// entitlement off-chain and withdrew it on-chain, and the settle clamp put
// the shortfall on us.
func TestPeerWithdrawReplacementCannotShortenExpiry(t *testing.T) {
	alice, bob, key := setupPair(t, Config{PushPayments: true}, Config{})
	two := new(big.Int).Mul(big.NewInt(2), wei1)
	five := new(big.Int).Mul(big.NewInt(5), wei1)

	v1 := signedWithdrawFrom(t, bob, key, two, nowBlock+1000)
	if res, ready, err := alice.engine.HandleWithdrawProposal(v1, bob.npub, nowBlock); err != nil || res.Ack == nil || ready == nil {
		t.Fatalf("V1 refused: %+v %v", res, err)
	}
	v2 := signedWithdrawFrom(t, bob, key, new(big.Int).Add(two, big.NewInt(1)), nowBlock+1)
	res, ready, err := alice.engine.HandleWithdrawProposal(v2, bob.npub, nowBlock)
	if err != nil || res.Ack != nil || ready != nil || res.Nack == nil {
		t.Fatalf("shorter-lived replacement countersigned: %+v %v", res, err)
	}

	// After V2 would have lapsed, V1 still earmarks its 2 LAX: a payment of
	// the whole 5 LAX deposit is refused.
	later := nowBlock + 2
	if err := alice.engine.SweepWithdraw(key, later); err != nil {
		t.Fatal(err)
	}
	pay := signedPaymentFrom(t, bob, proofstore.RoleB, key, 1, new(big.Int), five)
	res, err = alice.engine.HandleProposal(pay, bob.npub, later, nowUnix)
	if err != nil || res.Ack != nil || res.Nack == nil || res.Nack.Reason != NackInsufficientBalance {
		t.Fatalf("payment spending V1's earmark accepted: %+v %v", res, err)
	}

	// A replacement that outlives V1 is still accepted.
	v3 := signedWithdrawFrom(t, bob, key, new(big.Int).Add(two, big.NewInt(1)), nowBlock+1000)
	if res, ready, err := alice.engine.HandleWithdrawProposal(v3, bob.npub, nowBlock); err != nil || res.Ack == nil || ready == nil {
		t.Fatalf("longer-lived replacement refused: %+v %v", res, err)
	}
}
