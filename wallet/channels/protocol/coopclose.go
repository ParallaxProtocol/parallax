package protocol

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
)

var ErrNoPendingClose = errors.New("protocol: no pending cooperative close")

// DefaultCoopCloseHorizonBlocks bounds how far in the future a cooperative
// close may expire (one week at 10-minute blocks, matching the channel-open
// accept_challenge_period_max ceiling). A signed close freezes the channel
// until it settles or expires (Part 1 §7.4), so an unbounded expiry would
// let an authenticated peer freeze the channel essentially forever.
const DefaultCoopCloseHorizonBlocks = 1008

// CoopCloseReady is a fully dual-signed cooperative close, ready for either
// party to submit on-chain (Part 2 §6.5).
type CoopCloseReady struct {
	Key         proofstore.ChannelKey
	BalanceA    *big.Int
	BalanceB    *big.Int
	ExpiryBlock uint64
	SigA        []byte
	SigB        []byte
}

func domainOf(key proofstore.ChannelKey) (registry.Domain, error) {
	return key.Domain()
}

// CloseBalances computes the explicit final balances from the latest
// complete state and the confirmed funding view, using the same clamped
// settlement math the contract applies (Part 2 §8).
func (e *Engine) CloseBalances(key proofstore.ChannelKey) (balA, balB *big.Int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closeBalances(key)
}

func (e *Engine) closeBalances(key proofstore.ChannelKey) (balA, balB *big.Int, err error) {
	latest, err := e.latestOrZero(key)
	if err != nil {
		return nil, nil, err
	}
	dep, err := e.store.Deposits(key)
	if err != nil {
		return nil, nil, err
	}
	balA, balB = registry.Settlement(
		dep.DepositA.BigInt(), dep.DepositB.BigInt(),
		dep.WithdrawnA.BigInt(), dep.WithdrawnB.BigInt(),
		latest.TransferredAtoB.BigInt(), latest.TransferredBtoA.BigInt(),
	)
	return balA, balB, nil
}

func coopCloseDigest(key proofstore.ChannelKey, balA, balB *big.Int, expiry uint64) (util.Hash, error) {
	d, err := domainOf(key)
	if err != nil {
		return util.Hash{}, err
	}
	return d.HashCooperativeClose(new(big.Int).SetUint64(key.ChannelID), balA, balB, expiry), nil
}

// ProposeCoopClose signs and returns a 21904 for the current balances. The
// channel freezes immediately: a signed close is a live grenade until it
// settles or expires (Part 1 §7.4), so nothing new is signed from here on.
// Allowed while Closing too — mutual agreement short-circuits the dispute.
func (e *Engine) ProposeCoopClose(key proofstore.ChannelKey, expiryBlock, nowBlock uint64) (*CoopCloseProposalMsg, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return nil, ErrUnknownChannel
	}
	if meta.Status != proofstore.StatusOpen && meta.Status != proofstore.StatusClosing {
		return nil, ErrNotOpen
	}
	if frozen(meta, nowBlock) {
		return nil, ErrFrozen
	}
	// A close signs explicit balances against the confirmed funding view,
	// and the contract requires their sum to equal the channel's available
	// funds at submission (Part 2 §8). A countersigned withdraw voucher that
	// mines first shrinks those funds and reverts the close, leaving both
	// sides frozen until its expiry for nothing. Refuse while any voucher is
	// still submittable; the sweep clears it after expiry.
	if voucherLive(meta.PendingWithdraw, nowBlock) || voucherLive(meta.PeerPendingWithdraw, nowBlock) {
		return nil, ErrWithdrawPending
	}
	if expiryBlock <= nowBlock {
		return nil, fmt.Errorf("protocol: expiry block %d not in the future", expiryBlock)
	}
	// An unknown head (offline node, nowBlock 0) cannot judge the horizon;
	// online nodes bound the freeze they sign themselves into.
	if nowBlock > 0 && expiryBlock > nowBlock+e.cfg.coopCloseHorizon() {
		return nil, fmt.Errorf("protocol: expiry block %d beyond the close horizon (max %d ahead)",
			expiryBlock, e.cfg.coopCloseHorizon())
	}

	balA, balB, err := e.closeBalances(key)
	if err != nil {
		return nil, err
	}
	digest, err := coopCloseDigest(key, balA, balB, expiryBlock)
	if err != nil {
		return nil, err
	}
	sig, err := e.signer.SignDigest(digest)
	if err != nil {
		return nil, err
	}

	// Persist the signed close and the freeze before the message can leave
	// (same discipline as W1).
	err = e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		m.PendingClose = &proofstore.PendingCoopClose{
			BalanceA:    proofstore.NewU256(balA),
			BalanceB:    proofstore.NewU256(balB),
			ExpiryBlock: expiryBlock,
			MySig:       sig,
		}
		m.FrozenUntilBlock = expiryBlock
	})
	if err != nil {
		return nil, err
	}

	return &CoopCloseProposalMsg{
		V:            1,
		ChannelID:    strconv.FormatUint(key.ChannelID, 10),
		Registry:     key.Registry.Hex(),
		ChainID:      key.ChainID,
		BalanceA:     balA.String(),
		BalanceB:     balB.String(),
		ExpiryBlock:  strconv.FormatUint(expiryBlock, 10),
		Sig:          "0x" + util.Bytes2Hex(sig),
		ProposerRole: string(meta.Role),
	}, nil
}

// HandleCoopCloseProposal recomputes the balances independently and
// countersigns iff they match exactly (Part 2 §8). On success the channel is
// frozen, the 21905 countersign is returned for transmission, and the
// dual-signed pair is returned for on-chain submission by this side.
func (e *Engine) HandleCoopCloseProposal(msg CoopCloseProposalMsg, senderNpub string, nowBlock uint64) (Result, *CoopCloseReady, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	channelID, err := strconv.ParseUint(msg.ChannelID, 10, 64)
	if err != nil {
		return Result{Dropped: true}, nil, fmt.Errorf("protocol: bad channelId %q", msg.ChannelID)
	}
	key := proofstore.ChannelKey{ChainID: msg.ChainID, Registry: util.HexToAddress(msg.Registry), ChannelID: channelID}

	meta, err := e.store.Meta(key)
	if err != nil {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackUnknownChannel, "")}, nil, nil
	}
	if senderNpub != meta.PeerNpub {
		return Result{Dropped: true}, nil, nil
	}
	if meta.Status != proofstore.StatusOpen && meta.Status != proofstore.StatusClosing {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackUnknownChannel, "channel settled")}, nil, nil
	}

	expiry, err := strconv.ParseUint(msg.ExpiryBlock, 10, 64)
	if err != nil || expiry <= nowBlock {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackPolicy, "expiry not in the future")}, nil, nil
	}
	// Countersigning freezes us until expiry, so the expiry must be bounded:
	// an unbounded one is a free permanent-freeze grenade for the peer.
	// nowBlock 0 (offline node) cannot judge the horizon and skips it.
	if nowBlock > 0 && expiry > nowBlock+e.cfg.coopCloseHorizon() {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackPolicy, "expiry beyond the close horizon")}, nil, nil
	}
	// parseWei bounds the balances to 256 bits: the digest ABI-encodes them
	// into 32-byte words, and an oversized peer value must be refused here
	// rather than reach the encoder.
	uA, errA := parseWei(msg.BalanceA)
	uB, errB := parseWei(msg.BalanceB)
	if errA != nil || errB != nil {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackPolicy, "bad balances")}, nil, nil
	}
	wantA, wantB := uA.BigInt(), uB.BigInt()

	// Retransmission of the close we already countersigned: re-ACK
	// idempotently instead of NACKing our own freeze (Part 2 §7.2 applies to
	// 21904/21905 the same as to payments).
	if pc := meta.PendingClose; pc != nil && len(pc.MySig) == 65 &&
		pc.ExpiryBlock == expiry && pc.BalanceA.BigInt().Cmp(wantA) == 0 && pc.BalanceB.BigInt().Cmp(wantB) == 0 {
		digest, err := coopCloseDigest(key, wantA, wantB, expiry)
		if err != nil {
			return Result{}, nil, err
		}
		peerSig, err := parseSig(msg.Sig)
		if err != nil || VerifySignedBy(digest, peerSig, meta.PeerAddress) != nil {
			return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackPolicy, "bad signature")}, nil, nil
		}
		ack := &AckMsg{
			V:         1,
			ChannelID: msg.ChannelID,
			Seq:       "0",
			StateHash: digest.Hex(),
			Sig:       "0x" + util.Bytes2Hex(pc.MySig),
		}
		return Result{Ack: ack}, e.readyPair(key, meta.Role, wantA, wantB, expiry, pc.MySig, peerSig), nil
	}
	if frozen(meta, nowBlock) {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackFrozen, "close already pending")}, nil, nil
	}
	if voucherLive(meta.PendingWithdraw, nowBlock) || voucherLive(meta.PeerPendingWithdraw, nowBlock) {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackPolicy, "withdraw voucher outstanding")}, nil, nil
	}

	balA, balB, err := e.closeBalances(key)
	if err != nil {
		return Result{}, nil, err
	}
	if balA.Cmp(wantA) != 0 || balB.Cmp(wantB) != 0 {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackPolicy, "balances do not match local view")}, nil, nil
	}

	digest, err := coopCloseDigest(key, balA, balB, expiry)
	if err != nil {
		return Result{}, nil, err
	}
	peerSig, err := parseSig(msg.Sig)
	if err != nil || VerifySignedBy(digest, peerSig, meta.PeerAddress) != nil {
		return Result{Nack: nack(key, KindCoopCloseProposal, 0, NackPolicy, "bad signature")}, nil, nil
	}

	mySig, err := e.signer.SignDigest(digest)
	if err != nil {
		return Result{}, nil, err
	}
	// Freeze before the countersignature can leave (Part 1 §7.4).
	err = e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		m.PendingClose = &proofstore.PendingCoopClose{
			BalanceA:    proofstore.NewU256(balA),
			BalanceB:    proofstore.NewU256(balB),
			ExpiryBlock: expiry,
			MySig:       mySig,
			PeerSig:     peerSig,
		}
		m.FrozenUntilBlock = expiry
	})
	if err != nil {
		return Result{}, nil, err
	}

	ack := &AckMsg{
		V:         1,
		ChannelID: msg.ChannelID,
		Seq:       "0",
		StateHash: digest.Hex(),
		Sig:       "0x" + util.Bytes2Hex(mySig),
	}
	return Result{Ack: ack}, e.readyPair(key, meta.Role, balA, balB, expiry, mySig, peerSig), nil
}

// HandleCoopCloseAck completes the proposer side from a verified 21905,
// returning the dual-signed pair for on-chain submission.
func (e *Engine) HandleCoopCloseAck(key proofstore.ChannelKey, msg AckMsg) (*CoopCloseReady, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return nil, ErrUnknownChannel
	}
	pc := meta.PendingClose
	if pc == nil || len(pc.MySig) != 65 {
		return nil, ErrNoPendingClose
	}

	digest, err := coopCloseDigest(key, pc.BalanceA.BigInt(), pc.BalanceB.BigInt(), pc.ExpiryBlock)
	if err != nil {
		return nil, err
	}
	if util.HexToHash(msg.StateHash) != digest {
		return nil, fmt.Errorf("protocol: coop-close ack hash does not match pending close")
	}
	peerSig, err := parseSig(msg.Sig)
	if err != nil {
		return nil, err
	}
	if err := VerifySignedBy(digest, peerSig, meta.PeerAddress); err != nil {
		return nil, err
	}

	if err := e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		m.PendingClose.PeerSig = peerSig
	}); err != nil {
		return nil, err
	}
	return e.readyPair(key, meta.Role, pc.BalanceA.BigInt(), pc.BalanceB.BigInt(), pc.ExpiryBlock, pc.MySig, peerSig), nil
}

// Unfreeze clears an expired, unsettled cooperative close: expiry without
// submission means the channel resumes normally (Part 2 §8). Watcher-driven.
func (e *Engine) Unfreeze(key proofstore.ChannelKey, nowBlock uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return ErrUnknownChannel
	}
	if meta.FrozenUntilBlock == 0 || nowBlock <= meta.FrozenUntilBlock {
		return nil
	}
	return e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		m.FrozenUntilBlock = 0
		m.PendingClose = nil
	})
}

func (e *Engine) readyPair(key proofstore.ChannelKey, myRole proofstore.Role, balA, balB *big.Int, expiry uint64, mySig, peerSig []byte) *CoopCloseReady {
	ready := &CoopCloseReady{Key: key, BalanceA: balA, BalanceB: balB, ExpiryBlock: expiry}
	if myRole == proofstore.RoleA {
		ready.SigA, ready.SigB = mySig, peerSig
	} else {
		ready.SigA, ready.SigB = peerSig, mySig
	}
	return ready
}
