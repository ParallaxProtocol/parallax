package protocol

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
)

var (
	ErrNoPendingWithdraw = errors.New("protocol: no pending withdraw")
	ErrWithdrawPending   = errors.New("protocol: a withdraw negotiation is already outstanding")
)

// WithdrawReady is a fully dual-signed cooperative withdraw, ready for
// on-chain submission (Part 2 §6.10).
type WithdrawReady struct {
	Key            proofstore.ChannelKey
	Participant    util.Address
	TotalWithdrawn *big.Int
	ExpiryBlock    uint64
	SigA           []byte
	SigB           []byte
}

func withdrawDigest(key proofstore.ChannelKey, participant util.Address, total *big.Int, expiry uint64) (util.Hash, error) {
	d, err := domainOf(key)
	if err != nil {
		return util.Hash{}, err
	}
	return d.HashWithdraw(new(big.Int).SetUint64(key.ChannelID), participant, total, expiry), nil
}

// entitlement is the maximum cumulative totalWithdrawn for a role at the
// latest complete state (Part 1 §7.3 wallet guard):
//
//	deposit_p + transferredToP − transferredFromP
//
// floored at zero (garbage states cannot create negative entitlements).
func (e *Engine) entitlement(key proofstore.ChannelKey, r proofstore.Role) (*big.Int, error) {
	latest, err := e.latestOrZero(key)
	if err != nil {
		return nil, err
	}
	dep, err := e.store.Deposits(key)
	if err != nil {
		return nil, err
	}
	ent := new(big.Int)
	if r == proofstore.RoleA {
		ent.Add(dep.DepositA.BigInt(), latest.TransferredBtoA.BigInt())
		ent.Sub(ent, latest.TransferredAtoB.BigInt())
	} else {
		ent.Add(dep.DepositB.BigInt(), latest.TransferredAtoB.BigInt())
		ent.Sub(ent, latest.TransferredBtoA.BigInt())
	}
	if ent.Sign() < 0 {
		ent.SetInt64(0)
	}
	return ent, nil
}

// journalEmpty enforces the Part 2 §6.10 precondition: no withdraw
// negotiation while a self-signed state is outstanding — the entitlement
// check needs an agreed latest state.
func (e *Engine) journalEmpty(key proofstore.ChannelKey) (bool, error) {
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return false, err
	}
	return len(journal) == 0, nil
}

// ProposeWithdraw signs and returns a 21911 withdrawing amountWei to this
// wallet. The pending record persists before the message can leave (same
// discipline as W1).
func (e *Engine) ProposeWithdraw(key proofstore.ChannelKey, amountWei *big.Int, expiryBlock, nowBlock uint64) (*WithdrawProposalMsg, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return nil, ErrUnknownChannel
	}
	if meta.Status != proofstore.StatusOpen {
		return nil, ErrNotOpen
	}
	if frozen(meta, nowBlock) {
		return nil, ErrFrozen
	}
	if voucherLive(meta.PendingWithdraw, nowBlock) {
		return nil, ErrWithdrawPending
	}
	if amountWei == nil || amountWei.Sign() <= 0 {
		return nil, fmt.Errorf("protocol: non-positive withdraw amount")
	}
	if expiryBlock <= nowBlock {
		return nil, fmt.Errorf("protocol: expiry block %d not in the future", expiryBlock)
	}
	// A signed voucher earmarks entitlement until it expires (and blocks
	// re-proposals meanwhile), so the expiry is bounded by the same horizon
	// as a coop-close freeze. nowBlock 0 (offline) cannot judge it.
	if nowBlock > 0 && expiryBlock > nowBlock+e.cfg.coopCloseHorizon() {
		return nil, fmt.Errorf("protocol: expiry block %d beyond the withdraw horizon (max %d ahead)",
			expiryBlock, e.cfg.coopCloseHorizon())
	}
	if empty, err := e.journalEmpty(key); err != nil {
		return nil, err
	} else if !empty {
		return nil, ErrProposalPending
	}

	dep, err := e.store.Deposits(key)
	if err != nil {
		return nil, err
	}
	total := new(big.Int).Add(dep.WithdrawnOf(meta.Role).BigInt(), amountWei)
	ent, err := e.entitlement(key, meta.Role)
	if err != nil {
		return nil, err
	}
	if total.Cmp(ent) > 0 {
		return nil, ErrInsufficient
	}

	self := e.signer.Address()
	digest, err := withdrawDigest(key, self, total, expiryBlock)
	if err != nil {
		return nil, err
	}
	sig, err := e.signer.SignDigest(digest)
	if err != nil {
		return nil, err
	}
	err = e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		m.PendingWithdraw = &proofstore.PendingWithdraw{
			Participant:    self,
			TotalWithdrawn: proofstore.NewU256(total),
			ExpiryBlock:    expiryBlock,
			MySig:          sig,
		}
	})
	if err != nil {
		return nil, err
	}

	return &WithdrawProposalMsg{
		V:              1,
		ChannelID:      strconv.FormatUint(key.ChannelID, 10),
		Registry:       strings.ToLower(key.Registry.Hex()),
		ChainID:        key.ChainID,
		Participant:    strings.ToLower(self.Hex()),
		TotalWithdrawn: total.String(),
		ExpiryBlock:    strconv.FormatUint(expiryBlock, 10),
		Sig:            "0x" + util.Bytes2Hex(sig),
	}, nil
}

// HandleWithdrawProposal runs the entitlement check and countersigns.
// Retransmissions re-validate and — via deterministic ECDSA — re-ACK with
// the identical countersignature (Part 2 §6.10).
func (e *Engine) HandleWithdrawProposal(msg WithdrawProposalMsg, senderNpub string, nowBlock uint64) (Result, *WithdrawReady, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	channelID, err := strconv.ParseUint(msg.ChannelID, 10, 64)
	if err != nil {
		return Result{Dropped: true}, nil, fmt.Errorf("protocol: bad channelId %q", msg.ChannelID)
	}
	key := proofstore.ChannelKey{ChainID: msg.ChainID, Registry: util.HexToAddress(msg.Registry), ChannelID: channelID}

	meta, err := e.store.Meta(key)
	if err != nil {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackUnknownChannel, "")}, nil, nil
	}
	if senderNpub != meta.PeerNpub {
		return Result{Dropped: true}, nil, nil
	}
	if meta.Status != proofstore.StatusOpen {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackUnknownChannel, "channel not open")}, nil, nil
	}
	if frozen(meta, nowBlock) {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackFrozen, "")}, nil, nil
	}
	if empty, err := e.journalEmpty(key); err != nil {
		return Result{}, nil, err
	} else if !empty {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "self-signed state outstanding")}, nil, nil
	}

	expiry, err := strconv.ParseUint(msg.ExpiryBlock, 10, 64)
	if err != nil || expiry <= nowBlock {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "expiry not in the future")}, nil, nil
	}
	// Countersigning earmarks the peer's entitlement until the voucher
	// expires, so the expiry must be bounded like a coop-close freeze — an
	// effectively-infinite one makes the earmark permanent. nowBlock 0
	// (offline node) cannot judge the horizon and skips it.
	if nowBlock > 0 && expiry > nowBlock+e.cfg.coopCloseHorizon() {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "expiry beyond the withdraw horizon")}, nil, nil
	}
	if !util.IsHexAddress(msg.Participant) {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "bad participant")}, nil, nil
	}
	participant := util.HexToAddress(msg.Participant)
	// The proposer only ever withdraws to itself.
	if participant != meta.PeerAddress {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "participant is not the proposer")}, nil, nil
	}
	// parseWei bounds the total to 256 bits before it can reach the digest
	// encoder, which packs it into a 32-byte word.
	utotal, err := parseWei(msg.TotalWithdrawn)
	if err != nil || utotal.Sign() <= 0 {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "bad totalWithdrawn")}, nil, nil
	}
	total := utotal.BigInt()

	// Strict cumulative increase against confirmed figures (mirrors the
	// contract) and the entitlement ceiling (Part 1 §7.3 wallet guard).
	dep, err := e.store.Deposits(key)
	if err != nil {
		return Result{}, nil, err
	}
	prole := peerRole(meta.Role)
	// The increase is measured against the outstanding countersigned voucher
	// too, not just confirmed figures: totals are cumulative on-chain, so a
	// lower re-proposal is useless to the peer, and refusing it keeps the
	// single voucher record below monotone. A retransmission of the voucher
	// itself is exempt — it re-validates and re-ACKs idempotently.
	pw := meta.PeerPendingWithdraw
	retransmit := pw != nil && pw.Participant == participant && pw.ExpiryBlock == expiry &&
		pw.TotalWithdrawn.BigInt().Cmp(total) == 0
	withdrawn := dep.WithdrawnOf(prole).BigInt()
	if !retransmit {
		withdrawn = withdrawAdjusted(meta, dep, nowBlock).WithdrawnOf(prole).BigInt()
	}
	if total.Cmp(withdrawn) <= 0 {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "totalWithdrawn does not increase")}, nil, nil
	}
	ent, err := e.entitlement(key, prole)
	if err != nil {
		return Result{}, nil, err
	}
	if total.Cmp(ent) > 0 {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackInsufficientBalance, "exceeds entitlement")}, nil, nil
	}

	digest, err := withdrawDigest(key, participant, total, expiry)
	if err != nil {
		return Result{}, nil, err
	}
	peerSig, err := parseSig(msg.Sig)
	if err != nil || VerifySignedBy(digest, peerSig, meta.PeerAddress) != nil {
		return Result{Nack: nack(key, KindWithdrawProposal, 0, NackPolicy, "bad signature")}, nil, nil
	}

	mySig, err := e.signer.SignDigest(digest)
	if err != nil {
		return Result{}, nil, err
	}
	// W2-class barrier: record the voucher before the countersignature can
	// leave. Without it the peer holds a submittable withdraw this side does
	// not account for, and pay-then-withdraw double-spends the entitlement.
	err = e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		m.PeerPendingWithdraw = &proofstore.PendingWithdraw{
			Participant:    participant,
			TotalWithdrawn: proofstore.NewU256(total),
			ExpiryBlock:    expiry,
			MySig:          mySig,
			PeerSig:        peerSig,
		}
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
	ready := &WithdrawReady{Key: key, Participant: participant, TotalWithdrawn: total, ExpiryBlock: expiry}
	if meta.Role == proofstore.RoleA {
		ready.SigA, ready.SigB = mySig, peerSig
	} else {
		ready.SigA, ready.SigB = peerSig, mySig
	}
	return Result{Ack: ack}, ready, nil
}

// HandleWithdrawAck completes the proposer side from a verified 21912.
func (e *Engine) HandleWithdrawAck(key proofstore.ChannelKey, msg AckMsg) (*WithdrawReady, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return nil, ErrUnknownChannel
	}
	pw := meta.PendingWithdraw
	if pw == nil || len(pw.MySig) != 65 {
		return nil, ErrNoPendingWithdraw
	}
	digest, err := withdrawDigest(key, pw.Participant, pw.TotalWithdrawn.BigInt(), pw.ExpiryBlock)
	if err != nil {
		return nil, err
	}
	if util.HexToHash(msg.StateHash) != digest {
		return nil, fmt.Errorf("protocol: withdraw ack hash does not match pending withdraw")
	}
	peerSig, err := parseSig(msg.Sig)
	if err != nil {
		return nil, err
	}
	if err := VerifySignedBy(digest, peerSig, meta.PeerAddress); err != nil {
		return nil, err
	}
	if err := e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		m.PendingWithdraw.PeerSig = peerSig
	}); err != nil {
		return nil, err
	}
	ready := &WithdrawReady{Key: key, Participant: pw.Participant, TotalWithdrawn: pw.TotalWithdrawn.BigInt(), ExpiryBlock: pw.ExpiryBlock}
	if meta.Role == proofstore.RoleA {
		ready.SigA, ready.SigB = pw.MySig, peerSig
	} else {
		ready.SigA, ready.SigB = peerSig, pw.MySig
	}
	return ready, nil
}

// SweepWithdraw clears pending withdraws — own proposal and countersigned
// peer voucher alike — once they expired or once the confirmed on-chain
// cumulative caught up (submission landed). Watcher-driven alongside
// Unfreeze.
func (e *Engine) SweepWithdraw(key proofstore.ChannelKey, nowBlock uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return ErrUnknownChannel
	}
	if meta.PendingWithdraw == nil && meta.PeerPendingWithdraw == nil {
		return nil
	}
	dep, err := e.store.Deposits(key)
	if err != nil {
		return err
	}
	done := func(r proofstore.Role, pw *proofstore.PendingWithdraw) bool {
		if pw == nil {
			return false
		}
		return !voucherLive(pw, nowBlock) || dep.WithdrawnOf(r).BigInt().Cmp(pw.TotalWithdrawn.BigInt()) >= 0
	}
	own := done(meta.Role, meta.PendingWithdraw)
	peer := done(peerRole(meta.Role), meta.PeerPendingWithdraw)
	if !own && !peer {
		return nil
	}
	return e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) {
		if own {
			m.PendingWithdraw = nil
		}
		if peer {
			m.PeerPendingWithdraw = nil
		}
	})
}

// withdrawAdjusted returns the confirmed funding view with each side's
// withdrawn column raised to its outstanding withdraw voucher (own pending
// proposal, or the peer's that this wallet countersigned): a signed voucher
// is submittable until its expiry, so the entitlement it spends is gone for
// balance purposes even before the chain confirms it.
func withdrawAdjusted(meta proofstore.ChannelMeta, dep proofstore.Deposits, nowBlock uint64) proofstore.Deposits {
	raise := func(r proofstore.Role, pw *proofstore.PendingWithdraw) {
		if !voucherLive(pw, nowBlock) {
			return
		}
		col := &dep.WithdrawnA
		if r == proofstore.RoleB {
			col = &dep.WithdrawnB
		}
		if pw.TotalWithdrawn.BigInt().Cmp(col.BigInt()) > 0 {
			*col = proofstore.NewU256(pw.TotalWithdrawn.BigInt())
		}
	}
	raise(meta.Role, meta.PendingWithdraw)
	raise(peerRole(meta.Role), meta.PeerPendingWithdraw)
	return dep
}

// voucherLive reports whether a recorded withdraw voucher is still
// submittable at nowBlock: the contract accepts it through its expiry block
// inclusive. An unknown head (nowBlock 0) treats every recorded voucher as
// live, so an offline node never signs against entitlement a voucher may
// still spend.
func voucherLive(pw *proofstore.PendingWithdraw, nowBlock uint64) bool {
	return pw != nil && nowBlock <= pw.ExpiryBlock
}
