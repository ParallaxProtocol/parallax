package protocol

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
)

var (
	ErrUnknownChannel  = errors.New("protocol: unknown channel")
	ErrNotOpen         = errors.New("protocol: channel not open")
	ErrFrozen          = errors.New("protocol: channel frozen by pending cooperative close")
	ErrProposalPending = errors.New("protocol: a self-signed state is already outstanding (one in-flight rule)")
	ErrNoProposal      = errors.New("protocol: no matching outstanding proposal")
	ErrInsufficient    = errors.New("protocol: insufficient confirmed balance")
	ErrInflightCap     = errors.New("protocol: amount exceeds max_inflight_payment_wei")
)

// Config carries the engine policy knobs (Part 3 §11).
type Config struct {
	// PushPayments accepts inbound proposals with no matching invoice
	// (default off for merchants, Part 2 §6.2).
	PushPayments bool
	// MaxInflightWei caps a single outgoing payment, bounding poisoned
	// exposure ex ante (Part 4 R2). nil or zero = unlimited.
	MaxInflightWei *big.Int
	// CoopCloseHorizonBlocks caps how far past the current head a
	// cooperative-close expiry may lie (freeze bound); zero applies
	// DefaultCoopCloseHorizonBlocks.
	CoopCloseHorizonBlocks uint64
}

func (c Config) coopCloseHorizon() uint64 {
	if c.CoopCloseHorizonBlocks == 0 {
		return DefaultCoopCloseHorizonBlocks
	}
	return c.CoopCloseHorizonBlocks
}

// Engine drives one wallet's side of the channel protocol. Methods
// serialize on an internal lock (Part 3 §2's actor discipline, enforced
// here): callers span the dispatcher, the watcher loop, the transmitter
// give-up callback, merchant HTTP handlers, and CLI verbs, and every method
// is a read-check-sign-write sequence whose checks must not interleave.
type Engine struct {
	mu     sync.Mutex
	store  *proofstore.Store
	signer Signer
	cfg    Config
}

func New(store *proofstore.Store, signer Signer, cfg Config) *Engine {
	return &Engine{store: store, signer: signer, cfg: cfg}
}

// Result is the outcome of handling one inbound message: at most one of Ack
// or Nack to transmit; Completed set when a new dual-signed state was
// committed (trigger tower delegation + self-backup); Dropped when the
// message was silently ignored (unknown sender, or the A-side tiebreak
// ignore); AdoptedTiebreak when this wallet (as B) discarded its own pending
// intent for A's variant and should rebase it as a fresh proposal.
type Result struct {
	Ack             *AckMsg
	Nack            *NackMsg
	Completed       *proofstore.SignedState
	Dropped         bool
	AdoptedTiebreak bool
}

// ---------------------------------------------------------------- helpers

// zeroState is the implicit pre-first-payment state (seq 0, all zero).
func zeroState(key proofstore.ChannelKey) proofstore.SignedState {
	return proofstore.SignedState{
		Key:             key,
		TransferredAtoB: proofstore.NewU256(nil),
		TransferredBtoA: proofstore.NewU256(nil),
		LockedAmount:    proofstore.NewU256(nil),
	}
}

func (e *Engine) latestOrZero(key proofstore.ChannelKey) (proofstore.SignedState, error) {
	st, err := e.store.LatestState(key)
	if errors.Is(err, proofstore.ErrNotFound) {
		return zeroState(key), nil
	}
	return st, err
}

// OutboundOf returns the cumulative amount sent by the given role in a state.
func OutboundOf(st *proofstore.SignedState, r proofstore.Role) *big.Int {
	if r == proofstore.RoleA {
		return st.TransferredAtoB.BigInt()
	}
	return st.TransferredBtoA.BigInt()
}

// balanceOf computes a participant's off-chain balance at a state against
// the confirmed funding view (Part 3 §8):
//
//	bal_p = deposit_p(≥3 conf) − withdrawn_p + transferredToP − transferredFromP
func balanceOf(r proofstore.Role, st *proofstore.SignedState, dep proofstore.Deposits) *big.Int {
	bal := new(big.Int)
	if r == proofstore.RoleA {
		bal.Add(dep.DepositA.BigInt(), st.TransferredBtoA.BigInt())
		bal.Sub(bal, dep.WithdrawnA.BigInt())
		bal.Sub(bal, st.TransferredAtoB.BigInt())
	} else {
		bal.Add(dep.DepositB.BigInt(), st.TransferredAtoB.BigInt())
		bal.Sub(bal, dep.WithdrawnB.BigInt())
		bal.Sub(bal, st.TransferredBtoA.BigInt())
	}
	return bal
}

func peerRole(r proofstore.Role) proofstore.Role {
	if r == proofstore.RoleA {
		return proofstore.RoleB
	}
	return proofstore.RoleA
}

func frozen(meta proofstore.ChannelMeta, nowBlock uint64) bool {
	return meta.FrozenUntilBlock != 0 && nowBlock <= meta.FrozenUntilBlock
}

// setSig writes sig into the slot for role r.
func setSig(st *proofstore.SignedState, r proofstore.Role, sig []byte) {
	if r == proofstore.RoleA {
		st.SigA = sig
	} else {
		st.SigB = sig
	}
}

func (e *Engine) refreshPoisonedFlag(key proofstore.ChannelKey) error {
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return err
	}
	if len(journal) == 0 {
		return e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) { m.Poisoned = false })
	}
	return nil
}

func nack(key proofstore.ChannelKey, re int, seq uint64, reason, detail string) *NackMsg {
	return &NackMsg{
		V:         1,
		ChannelID: strconv.FormatUint(key.ChannelID, 10),
		Registry:  strings.ToLower(key.Registry.Hex()),
		ChainID:   key.ChainID,
		Re:        strconv.Itoa(re),
		Seq:       strconv.FormatUint(seq, 10),
		Reason:    reason,
		Detail:    detail,
	}
}

// ------------------------------------------------------------- proposer

// ProposePayment builds, signs, and journals (W1) the next state paying
// amountWei to the counterparty, returning the 21902 to transmit. The
// message MUST NOT be transmitted before this returns (the store commit is
// the W1 barrier).
func (e *Engine) ProposePayment(key proofstore.ChannelKey, amountWei *big.Int, invoiceID string, nowBlock uint64) (*ProposalMsg, error) {
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
	if amountWei == nil || amountWei.Sign() <= 0 {
		return nil, fmt.Errorf("protocol: non-positive amount")
	}
	if e.cfg.MaxInflightWei != nil && e.cfg.MaxInflightWei.Sign() > 0 && amountWei.Cmp(e.cfg.MaxInflightWei) > 0 {
		return nil, ErrInflightCap
	}

	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return nil, err
	}
	if len(journal) > 0 {
		return nil, ErrProposalPending
	}

	latest, err := e.latestOrZero(key)
	if err != nil {
		return nil, err
	}
	dep, err := e.store.Deposits(key)
	if err != nil {
		return nil, err
	}
	// Outstanding withdraw vouchers spend entitlement before the chain
	// confirms them (Part 2 §6.10).
	dep = withdrawAdjusted(meta, dep, nowBlock)
	myBal := balanceOf(meta.Role, &latest, dep)
	if myBal.Cmp(amountWei) < 0 {
		return nil, ErrInsufficient
	}

	next := latest
	next.Key = key
	next.Seq = latest.Seq + 1
	next.SigA, next.SigB = nil, nil
	out := new(big.Int).Add(OutboundOf(&latest, meta.Role), amountWei)
	if meta.Role == proofstore.RoleA {
		next.TransferredAtoB = proofstore.NewU256(out)
		next.TransferredBtoA = proofstore.NewU256(latest.TransferredBtoA.BigInt())
	} else {
		next.TransferredBtoA = proofstore.NewU256(out)
		next.TransferredAtoB = proofstore.NewU256(latest.TransferredAtoB.BigInt())
	}

	digest, err := next.Digest()
	if err != nil {
		return nil, err
	}
	sig, err := e.signer.SignDigest(digest)
	if err != nil {
		return nil, err
	}
	setSig(&next, meta.Role, sig)

	if err := e.store.PutSelfSigned(next); err != nil { // W1 barrier
		return nil, err
	}
	return &ProposalMsg{V: 1, InvoiceID: invoiceID, State: ToWire(next), ProposerRole: string(meta.Role)}, nil
}

// ProposeNoOpSupersession builds the seq-space-cleaning proposal whose
// amounts equal the latest complete state (Part 2 §7.4 cancel-by-
// supersession). Requires an outstanding self-signed state to supersede.
func (e *Engine) ProposeNoOpSupersession(key proofstore.ChannelKey, nowBlock uint64) (*ProposalMsg, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return nil, ErrUnknownChannel
	}
	// The supersession signs and journals a NEW state, so it is bound by
	// the same guards as ProposePayment: a frozen channel signs nothing
	// (Part 1 §7.4) and a settled one has no seq space left — skipping
	// them would journal one more irrevocable state the counterparty will
	// never countersign.
	if meta.Status != proofstore.StatusOpen {
		return nil, ErrNotOpen
	}
	if frozen(meta, nowBlock) {
		return nil, ErrFrozen
	}
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return nil, err
	}
	if len(journal) == 0 {
		return nil, ErrNoProposal
	}

	latest, err := e.latestOrZero(key)
	if err != nil {
		return nil, err
	}
	next := latest
	next.Key = key
	next.Seq = journal[len(journal)-1].Seq + 1
	next.SigA, next.SigB = nil, nil
	next.TransferredAtoB = proofstore.NewU256(latest.TransferredAtoB.BigInt())
	next.TransferredBtoA = proofstore.NewU256(latest.TransferredBtoA.BigInt())

	digest, err := next.Digest()
	if err != nil {
		return nil, err
	}
	sig, err := e.signer.SignDigest(digest)
	if err != nil {
		return nil, err
	}
	setSig(&next, meta.Role, sig)
	if err := e.store.PutSelfSigned(next); err != nil { // W1 barrier
		return nil, err
	}
	return &ProposalMsg{V: 1, State: ToWire(next), ProposerRole: string(meta.Role)}, nil
}

// HandleAck completes an outstanding proposal from a verified 21903. The
// completed state is returned for tower delegation and self-backup.
func (e *Engine) HandleAck(key proofstore.ChannelKey, msg AckMsg) (*proofstore.SignedState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return nil, ErrUnknownChannel
	}
	seq, err := strconv.ParseUint(msg.Seq, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("protocol: bad ack seq %q", msg.Seq)
	}
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return nil, err
	}
	var pending *proofstore.SignedState
	for i := range journal {
		if journal[i].Seq == seq {
			pending = &journal[i]
			break
		}
	}
	if pending == nil {
		// Duplicate ACK for an already-completed state is a no-op
		// (retransmission idempotency, Part 2 §7.2).
		latest, lerr := e.latestOrZero(key)
		if lerr == nil && latest.Seq == seq && seq > 0 {
			if d, derr := latest.Digest(); derr == nil && d == util.HexToHash(msg.StateHash) {
				return &latest, nil
			}
		}
		return nil, ErrNoProposal
	}

	digest, err := pending.Digest()
	if err != nil {
		return nil, err
	}
	if util.HexToHash(msg.StateHash) != digest {
		return nil, fmt.Errorf("protocol: ack stateHash does not match local state")
	}
	sig, err := parseSig(msg.Sig)
	if err != nil {
		return nil, err
	}
	if err := VerifySignedBy(digest, sig, meta.PeerAddress); err != nil {
		return nil, err
	}

	complete := *pending
	setSig(&complete, peerRole(meta.Role), sig)
	if err := e.store.PutComplete(complete); err != nil { // W2-class barrier
		return nil, err
	}
	if err := e.refreshPoisonedFlag(key); err != nil {
		return nil, err
	}
	return &complete, nil
}

// HandleNack records the poisoned condition for an outstanding proposal
// (Part 2 §7.4). Advisory: the proposal remains journaled and irrevocable.
func (e *Engine) HandleNack(key proofstore.ChannelKey, msg NackMsg) (poisoned bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	seq, err := strconv.ParseUint(msg.Seq, 10, 64)
	if err != nil {
		return false, fmt.Errorf("protocol: bad nack seq %q", msg.Seq)
	}
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return false, err
	}
	for _, st := range journal {
		if st.Seq == seq {
			if err := e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) { m.Poisoned = true }); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// MarkPoisoned is the retransmission layer's signal that backoff for an
// outstanding proposal is exhausted (Part 3 §5).
func (e *Engine) MarkPoisoned(key proofstore.ChannelKey) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return err
	}
	if len(journal) == 0 {
		return nil
	}
	return e.store.UpdateMeta(key, func(m *proofstore.ChannelMeta) { m.Poisoned = true })
}

// PoisonedExposure returns the exact worst-case cost of unilaterally closing
// at the latest complete state while self-signed states are outstanding:
// 20% of the largest un-countersigned outbound delta (Part 1 §9.2), which
// clients MUST surface rather than a vague warning (Part 3 §5).
func (e *Engine) PoisonedExposure(key proofstore.ChannelKey) (*big.Int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	meta, err := e.store.Meta(key)
	if err != nil {
		return nil, ErrUnknownChannel
	}
	latest, err := e.latestOrZero(key)
	if err != nil {
		return nil, err
	}
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return nil, err
	}
	maxDelta := new(big.Int)
	base := OutboundOf(&latest, meta.Role)
	for i := range journal {
		delta := new(big.Int).Sub(OutboundOf(&journal[i], meta.Role), base)
		if delta.Cmp(maxDelta) > 0 {
			maxDelta = delta
		}
	}
	// 20% of the largest in-flight delta.
	return maxDelta.Div(maxDelta.Mul(maxDelta, big.NewInt(2000)), big.NewInt(10_000)), nil
}

// ------------------------------------------------------------- responder

// HandleProposal runs the normative responder validation (Part 2 §7.3) plus
// the A-wins tiebreak (§7.5), countersigning iff every check passes. The W2
// barrier: the complete state is committed before the ACK is returned for
// transmission.
//
// nowBlock is the confirmed chain head; nowUnix the wall clock for invoice
// expiry.
func (e *Engine) HandleProposal(msg ProposalMsg, senderNpub string, nowBlock uint64, nowUnix int64) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, err := FromWire(msg.State)
	if err != nil {
		return Result{Dropped: true}, err
	}
	key := st.Key

	meta, err := e.store.Meta(key)
	if err != nil {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackUnknownChannel, "")}, nil
	}
	// Check 1a: authenticated sender is the channel counterparty. Unknown
	// senders referencing known channels are dropped, not answered
	// (Part 3 §6).
	if senderNpub != meta.PeerNpub {
		return Result{Dropped: true}, nil
	}
	if meta.Status != proofstore.StatusOpen {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackUnknownChannel, "channel not open")}, nil
	}
	if frozen(meta, nowBlock) {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackFrozen, "")}, nil
	}

	// Check 3: reserved lock fields must be zero in v1.
	if st.LocksRoot != (util.Hash{}) || st.LockedAmount.BigInt().Sign() != 0 {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackLocksNonzero, "")}, nil
	}

	latest, err := e.latestOrZero(key)
	if err != nil {
		return Result{}, err
	}
	// Duplicate of an already-countersigned proposal: resend the ACK
	// idempotently (Part 2 §7.2) — same seq, same digest as the completed
	// state, and our signature already exists on it.
	if st.Seq == latest.Seq && latest.Seq > 0 {
		latestDigest, err := latest.Digest()
		if err != nil {
			return Result{}, err
		}
		stDigest, err := st.Digest()
		if err != nil {
			return Result{}, err
		}
		if latestDigest == stDigest {
			return Result{Ack: &AckMsg{
				V:         1,
				ChannelID: strconv.FormatUint(key.ChannelID, 10),
				Seq:       strconv.FormatUint(st.Seq, 10),
				StateHash: latestDigest.Hex(),
				Sig:       "0x" + util.Bytes2Hex(latest.SigOf(meta.Role)),
				InvoiceID: msg.InvoiceID,
			}}, nil
		}
	}
	// Check 2: seq must advance past the completed history. Exact +1 in the
	// ordinary flow; a gap is legal only for supersessions of proposals this
	// side never countersigned (Part 2 §7.4), which check 4 constrains.
	if st.Seq <= latest.Seq {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackBadSeq,
			fmt.Sprintf("latest complete seq %d", latest.Seq))}, nil
	}

	// Check 4: cumulative monotonicity. The proposer's outbound may not
	// decrease and my outbound must be untouched; a zero-delta proposal is
	// the no-op supersession.
	prole := peerRole(meta.Role)
	delta := new(big.Int).Sub(OutboundOf(&st, prole), OutboundOf(&latest, prole))
	if delta.Sign() < 0 || OutboundOf(&st, meta.Role).Cmp(OutboundOf(&latest, meta.Role)) != 0 {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackPolicy, "non-monotone amounts")}, nil
	}
	isNoOp := delta.Sign() == 0

	// Check 7 (early: nothing below should trust an unauthenticated state):
	// the proposer's signature over the EIP-712 digest.
	digest, err := st.Digest()
	if err != nil {
		return Result{}, err
	}
	peerSig := st.SigOf(prole)
	if len(peerSig) != 65 || VerifySignedBy(digest, peerSig, meta.PeerAddress) != nil {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackPolicy, "bad signature")}, nil
	}
	if len(st.SigOf(meta.Role)) != 0 {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackPolicy, "proposal carries my signature slot")}, nil
	}

	// Tiebreak (§7.5): both sides proposed the same seq.
	journal, err := e.store.SelfSigned(key)
	if err != nil {
		return Result{}, err
	}
	adopted := false
	for i := range journal {
		if journal[i].Seq != st.Seq {
			continue
		}
		mineDigest, err := journal[i].Digest()
		if err != nil {
			return Result{}, err
		}
		if mineDigest == digest {
			break // identical states: just countersign below
		}
		if meta.Role == proofstore.RoleA {
			// A's proposal wins; ignore B's conflicting one — B will
			// countersign ours and rebase.
			return Result{Dropped: true}, nil
		}
		adopted = true // B adopts A's variant, discards own intent
	}

	// Check 5: the delta must pay an open, unexpired invoice (merchant
	// auto-accept), unless push payments are enabled. No-op supersessions
	// transfer nothing and need no invoice. Push payments waive the invoice
	// REQUIREMENT (no id, or an id this store never minted) — never the
	// validation of a known invoice the proposal references: skipping it
	// would let any delta flip the invoice to Paid below.
	if !isNoOp {
		var inv *proofstore.Invoice
		if msg.InvoiceID != "" {
			if rec, ierr := e.store.Invoice(msg.InvoiceID); ierr == nil {
				inv = &rec
			}
		}
		if !e.cfg.PushPayments || inv != nil {
			if res := checkInvoice(key, msg.InvoiceID, inv, delta, nowUnix, st.Seq); res != nil {
				return Result{Nack: res}, nil
			}
		}
	}

	// Check 6: proposer's post-state balance against confirmed deposits
	// only — the contract clamps at settle, so accepting a state funded by
	// a reorged deposit shifts the loss to us (Part 3 §8). Withdraw
	// vouchers still submittable count as withdrawn already: a payment
	// funded by entitlement the proposer holds a countersigned withdraw
	// for would double-spend it (Part 2 §6.10).
	dep, err := e.store.Deposits(key)
	if err != nil {
		return Result{}, err
	}
	dep = withdrawAdjusted(meta, dep, nowBlock)
	if balanceOf(prole, &st, dep).Sign() < 0 {
		return Result{Nack: nack(key, KindProposal, st.Seq, NackInsufficientBalance, "")}, nil
	}

	// Countersign. W2 barrier: commit the complete state before the ACK is
	// released for transmission.
	mySig, err := e.signer.SignDigest(digest)
	if err != nil {
		return Result{}, err
	}
	complete := st
	setSig(&complete, meta.Role, mySig)
	if adopted {
		err = e.store.PutCompleteTiebreak(complete)
	} else {
		err = e.store.PutComplete(complete)
	}
	if err != nil {
		return Result{}, err
	}
	if err := e.refreshPoisonedFlag(key); err != nil {
		return Result{}, err
	}

	// Mark the invoice paid exactly once; a duplicate proposal after a
	// completed payment re-ACKs without re-firing (Part 2 §7.2, §7.3.5).
	// This runs even under push-payments policy: skipping the invoice
	// REQUIREMENT never skips crediting one that was referenced. An unknown
	// id under push policy is tolerated (nothing to credit).
	if !isNoOp && msg.InvoiceID != "" {
		err := e.store.MarkInvoicePaid(msg.InvoiceID, key, st.Seq)
		if err != nil && !errors.Is(err, proofstore.ErrExists) &&
			!(e.cfg.PushPayments && errors.Is(err, proofstore.ErrNotFound)) {
			return Result{}, err
		}
	}

	return Result{
		Ack: &AckMsg{
			V:         1,
			ChannelID: strconv.FormatUint(key.ChannelID, 10),
			Seq:       strconv.FormatUint(st.Seq, 10),
			StateHash: digest.Hex(),
			Sig:       "0x" + util.Bytes2Hex(mySig),
			InvoiceID: msg.InvoiceID,
		},
		Completed:       &complete,
		AdoptedTiebreak: adopted,
	}, nil
}

// checkInvoice validates §7.3 check 5 against the invoice record the
// proposal references (nil when it names none, or one this store never
// minted); nil means pass.
func checkInvoice(key proofstore.ChannelKey, invoiceID string, inv *proofstore.Invoice, delta *big.Int, nowUnix int64, seq uint64) *NackMsg {
	if invoiceID == "" {
		return nack(key, KindProposal, seq, NackPolicy, "push payments disabled")
	}
	if inv == nil {
		return nack(key, KindProposal, seq, NackPolicy, "unknown invoice")
	}
	if inv.Paid {
		// Idempotent duplicate of a completed payment is handled upstream by
		// the digest match; a *new* state paying a spent invoice is refused.
		return nack(key, KindProposal, seq, NackPolicy, "invoice already paid")
	}
	if nowUnix > inv.ExpiresAt {
		return nack(key, KindProposal, seq, NackExpiredInvoice, "")
	}
	if inv.AmountWei.BigInt().Cmp(delta) != 0 {
		return nack(key, KindProposal, seq, NackPolicy, "amount does not match invoice")
	}
	// The pin is compared as a qualified key: coexisting registries share
	// bare ids, and honoring a pin on its same-id twin would mark the
	// invoice paid on the wrong channel.
	if !inv.PinMatches(key) {
		return nack(key, KindProposal, seq, NackPolicy, "invoice pinned to another channel")
	}
	return nil
}
