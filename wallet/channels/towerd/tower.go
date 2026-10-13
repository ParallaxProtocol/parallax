// Package towerd is the watchtower (Part 3 §10): it accepts delegated
// complete states over Nostr (kind 21906), watches every CloseStarted on the
// registry, and challenges any close that is stale against its delegation
// store. Structurally trustless: delegated material only fits the
// anyone-can-call challenge — the tower can be lazy, never a thief.
package towerd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/watcher"
)

// Config is the tower policy (Part 3 §10.2).
type Config struct {
	ChainID       string
	Registry      util.Address
	Confirmations uint64

	// Delegators is the npub allowlist; OpenRegistration accepts anyone,
	// bounded by MaxDelegationsPerNpub (storage-spam cap).
	Delegators            map[string]bool
	OpenRegistration      bool
	MaxDelegationsPerNpub int

	// MinDiscrepancyWei ignores dust closes (tower economics, not a
	// defense: the victim's own wallet challenges dust regardless).
	MinDiscrepancyWei *big.Int
}

// Tower watches one registry.
type Tower struct {
	cfg      Config
	store    *proofstore.Store
	backend  watcher.TxBackend
	contract *registry.ChannelRegistry
	txmgr    *watcher.TxManager

	// gaveUp holds the CloseStarted events Tick stopped retrying. While an
	// earlier, still-retryable failure pins the watermark below them they
	// are re-scanned every tick; skipping them avoids repeating the
	// give-up check (an RPC) and its alarm. Pruned as the watermark passes.
	gaveUpMu sync.Mutex
	gaveUp   map[closeEvent]struct{}

	// Alarm receives operator-grade alerts. Optional.
	Alarm func(format string, args ...any)
}

// New wires a tower to one registry. txmgr MUST be the shared per-chain
// manager for the submitting key (channeld's TxManagerFor when a channel
// node runs alongside): a second manager on the same key races nonce
// allocation and one submission silently replaces the other.
func New(cfg Config, store *proofstore.Store, backend watcher.TxBackend, txmgr *watcher.TxManager) (*Tower, error) {
	if txmgr == nil {
		return nil, fmt.Errorf("towerd: nil transaction manager")
	}
	if cfg.Confirmations == 0 {
		cfg.Confirmations = 3
	}
	if cfg.MaxDelegationsPerNpub == 0 {
		cfg.MaxDelegationsPerNpub = 1000
	}
	contract, err := registry.NewChannelRegistry(cfg.Registry, backend)
	if err != nil {
		return nil, err
	}
	t := &Tower{
		cfg:      cfg,
		store:    store,
		backend:  backend,
		contract: contract,
		txmgr:    txmgr,
		gaveUp:   make(map[closeEvent]struct{}),
	}
	// On a shared manager the node's watcher has already claimed Alarm for
	// the wallet log; chain onto it rather than skipping — a tower challenge
	// stalling near its deadline is the one loss-capable alert the tower
	// exists to raise, and it must reach the operator-facing stream.
	prev := t.txmgr.Alarm
	t.txmgr.Alarm = func(format string, args ...any) {
		if prev != nil {
			prev(format, args...)
		}
		t.alarm(format, args...)
	}
	return t, nil
}

func (t *Tower) alarm(format string, args ...any) {
	if t.Alarm != nil {
		t.Alarm(format, args...)
	}
}

// HandleDelegation processes one 21906: policy-gate the sender, verify the
// state is dual-signed by the channel's on-chain participants, keep max-seq,
// and return the 21907 receipt.
func (t *Tower) HandleDelegation(ctx context.Context, msg protocol.TowerDelegationMsg, senderNpub string) (*protocol.TowerReceiptMsg, error) {
	if !t.cfg.Delegators[senderNpub] {
		if !t.cfg.OpenRegistration {
			return nil, fmt.Errorf("towerd: %s is not a configured delegator", senderNpub)
		}
		n, err := t.store.DelegationCount(senderNpub)
		if err != nil {
			return nil, err
		}
		if n >= t.cfg.MaxDelegationsPerNpub {
			return nil, fmt.Errorf("towerd: delegation cap reached for %s", senderNpub)
		}
	}

	st, err := protocol.FromWire(msg.State)
	if err != nil {
		return nil, err
	}
	if st.Key.ChainID != t.cfg.ChainID || st.Key.Registry != t.cfg.Registry {
		return nil, fmt.Errorf("towerd: delegation for a registry this tower does not watch")
	}
	if !st.Complete() {
		return nil, fmt.Errorf("towerd: delegated state is not dual-signed")
	}

	// The signatures must recover to the channel's on-chain participants —
	// a delegation is only useful if the contract will accept it.
	onchain, err := t.contract.GetChannel(&bind.CallOpts{Context: ctx}, new(big.Int).SetUint64(st.Key.ChannelID))
	if err != nil {
		return nil, err
	}
	if onchain.ParticipantA == (util.Address{}) {
		return nil, fmt.Errorf("towerd: channel %d does not exist on-chain", st.Key.ChannelID)
	}
	digest, err := st.Digest()
	if err != nil {
		return nil, err
	}
	if protocol.VerifySignedBy(digest, st.SigA, onchain.ParticipantA) != nil ||
		protocol.VerifySignedBy(digest, st.SigB, onchain.ParticipantB) != nil {
		return nil, fmt.Errorf("towerd: signatures do not match on-chain participants")
	}

	kept, err := t.store.PutDelegation(proofstore.Delegation{State: st, DelegatorNpub: senderNpub})
	if err != nil {
		return nil, err
	}
	return &protocol.TowerReceiptMsg{
		V:         1,
		ChannelID: strconv.FormatUint(st.Key.ChannelID, 10),
		Registry:  strings.ToLower(st.Key.Registry.Hex()),
		ChainID:   st.Key.ChainID,
		Seq:       strconv.FormatUint(kept, 10),
		OK:        true,
	}, nil
}

// Tick scans confirmed CloseStarted events since the watermark and
// challenges any close that is stale against a held delegation. Returns the
// confirmed head acted on.
func (t *Tower) Tick(ctx context.Context) (uint64, error) {
	header, err := t.backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, err
	}
	head := header.Number.Uint64()
	if head+1 < t.cfg.Confirmations {
		return head, nil
	}
	cutoff := head - (t.cfg.Confirmations - 1)

	t.txmgr.Tick(ctx, head)

	from, err := t.store.TowerWatermark(t.cfg.ChainID, t.cfg.Registry.Hex())
	if err != nil {
		return head, err
	}
	if from+1 > cutoff {
		return head, nil
	}

	// All CloseStarted events on the registry, not just own channels.
	iter, err := t.contract.FilterCloseStarted(&bind.FilterOpts{Context: ctx, Start: from + 1, End: &cutoff}, nil, nil)
	if err != nil {
		return head, err
	}
	// The watermark may only advance past events that were reacted to:
	// react() is the tower's sole evaluation of a CloseStarted, so skipping
	// a transiently failed one would silently drop its challenge window.
	// firstFailed pins the watermark so the failed range is re-scanned,
	// for as long as a retry could still land a challenge (retryable).
	var firstFailed uint64
	for iter.Next() {
		ev := iter.Event
		key := proofstore.ChannelKey{
			ChainID:   t.cfg.ChainID,
			Registry:  t.cfg.Registry,
			ChannelID: ev.ChannelId.Uint64(),
		}
		ce := closeEvent{key: key, block: ev.Raw.BlockNumber}
		if t.hasGivenUp(ce) {
			continue
		}
		err := t.react(ctx, key, head)
		if err == nil {
			continue
		}
		if !errors.Is(err, errQuarantined) { // that one alarmed when it was quarantined
			t.alarm("tower react on %s: %v", key, err)
		}
		if why := t.retryable(ctx, key, head); why != "" {
			t.alarm("giving up on close of %s at block %d (%s): %v", key, ev.Raw.BlockNumber, why, err)
			t.giveUp(ce)
			continue
		}
		if firstFailed == 0 || ev.Raw.BlockNumber < firstFailed {
			firstFailed = ev.Raw.BlockNumber
		}
	}
	if err := iter.Error(); err != nil {
		return head, err // incomplete scan: keep the old watermark
	}
	mark := cutoff
	if firstFailed > 0 {
		mark = firstFailed - 1
	}
	if err := t.store.SetTowerWatermark(t.cfg.ChainID, t.cfg.Registry.Hex(), mark); err != nil {
		return head, err
	}
	t.pruneGivenUp(mark)
	return head, nil
}

// closeEvent identifies one CloseStarted event by channel and block.
type closeEvent struct {
	key   proofstore.ChannelKey
	block uint64
}

func (t *Tower) hasGivenUp(ce closeEvent) bool {
	t.gaveUpMu.Lock()
	defer t.gaveUpMu.Unlock()
	_, ok := t.gaveUp[ce]
	return ok
}

func (t *Tower) giveUp(ce closeEvent) {
	t.gaveUpMu.Lock()
	defer t.gaveUpMu.Unlock()
	t.gaveUp[ce] = struct{}{}
}

// pruneGivenUp drops events at or below the watermark, which no scan
// revisits.
func (t *Tower) pruneGivenUp(mark uint64) {
	t.gaveUpMu.Lock()
	defer t.gaveUpMu.Unlock()
	for ce := range t.gaveUp {
		if ce.block <= mark {
			delete(t.gaveUp, ce)
		}
	}
}

// errQuarantined marks a close whose delegation record is in quarantine:
// the tower held material for this channel and cannot evaluate the close
// with it. Tick keeps the watermark pinned while a repaired or re-sent
// delegation could still be honored.
var errQuarantined = errors.New("towerd: delegation record quarantined")

// retryable reports why re-scanning a failed CloseStarted can no longer
// help ("" while it still can): the channel has left the Closing state, or
// the challenge deadline has passed. An unreadable chain view keeps the
// retry, since that is the transient case the pin exists for.
func (t *Tower) retryable(ctx context.Context, key proofstore.ChannelKey, head uint64) (giveUp string) {
	onchain, err := t.contract.GetChannel(&bind.CallOpts{Context: ctx}, new(big.Int).SetUint64(key.ChannelID))
	if err != nil {
		return ""
	}
	if onchain.State != 2 {
		return "channel no longer closing"
	}
	if deadline := onchain.CloseInitiatedAtBlock.Uint64() + uint64(onchain.ChallengePeriodBlocks); head > deadline {
		return fmt.Sprintf("challenge deadline %d passed unevaluated", deadline)
	}
	return ""
}

// react evaluates one closing channel against the delegation store.
func (t *Tower) react(ctx context.Context, key proofstore.ChannelKey, head uint64) error {
	deleg, err := t.store.Delegation(key)
	if errors.Is(err, proofstore.ErrQuarantined) {
		return errQuarantined
	}
	if errors.Is(err, proofstore.ErrNotFound) {
		return nil // nobody delegated this channel: not our watch
	}
	if errors.Is(err, proofstore.ErrCorrupt) {
		// The bytes are present and will fail the same way on every
		// re-read. Move them aside so a fresh delegation can land and the
		// operator can inspect them; the close stays pinned meanwhile.
		q, qerr := t.store.QuarantineDelegation(key, err)
		if qerr != nil {
			return qerr
		}
		// The alarm carries the bytes: the quarantine CLI opens the store
		// this running tower holds locked, so it only works once the tower
		// is stopped.
		var raw []byte
		if q != nil {
			raw = q.Raw
		}
		t.alarm("quarantined undecodable delegation for %s: %v; raw record (%d bytes, base64) %s; the delegator may re-send ('tower quarantine list/clear' with the tower stopped)",
			key, err, len(raw), base64.StdEncoding.EncodeToString(raw))
		return errQuarantined
	}
	if err != nil {
		// A failing READ is not an absent delegation: swallowing it would
		// advance the watermark past a close this tower never evaluated.
		return err
	}

	onchain, err := t.contract.GetChannel(&bind.CallOpts{Context: ctx}, new(big.Int).SetUint64(key.ChannelID))
	if err != nil {
		return err
	}
	if onchain.State != 2 { // not Closing (already settled or coop-closed)
		t.txmgr.Done("towerchallenge:" + key.String())
		return nil
	}
	st := deleg.State
	if st.Seq <= onchain.ClosingSeq {
		t.txmgr.Done("towerchallenge:" + key.String())
		return nil
	}
	deadline := onchain.CloseInitiatedAtBlock.Uint64() + uint64(onchain.ChallengePeriodBlocks)
	if head > deadline {
		t.alarm("stale close on %s expired unchallenged (delegated seq %d > on-chain %d)", key, st.Seq, onchain.ClosingSeq)
		return nil
	}

	// Dust policy: skip when the victim-side difference between the
	// on-chain closing state and the delegated one is below the floor.
	if t.cfg.MinDiscrepancyWei != nil && t.cfg.MinDiscrepancyWei.Sign() > 0 {
		balAClosing, _ := registry.Settlement(
			onchain.DepositA, onchain.DepositB, onchain.WithdrawnA, onchain.WithdrawnB,
			onchain.ClosingTransferredAB, onchain.ClosingTransferredBA)
		balADelegated, _ := registry.Settlement(
			onchain.DepositA, onchain.DepositB, onchain.WithdrawnA, onchain.WithdrawnB,
			st.TransferredAtoB.BigInt(), st.TransferredBtoA.BigInt())
		diff := new(big.Int).Sub(balAClosing, balADelegated)
		if diff.Sign() < 0 {
			diff.Neg(diff)
		}
		if diff.Cmp(t.cfg.MinDiscrepancyWei) < 0 {
			return nil
		}
	}

	t.alarm("challenging stale close on %s: delegated seq %d > on-chain %d", key, st.Seq, onchain.ClosingSeq)
	return t.txmgr.Submit(ctx, "towerchallenge:"+key.String(), head, deadline,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			return t.contract.Challenge(auth, new(big.Int).SetUint64(key.ChannelID), st.ContractProof(), st.SigA, st.SigB)
		})
}

// Route dispatches delegations to the tower watching the message's registry
// (multi-registry deployments).
func Route(towers []*Tower) func(ctx context.Context, msg protocol.TowerDelegationMsg, sender string) (*protocol.TowerReceiptMsg, error) {
	return func(ctx context.Context, msg protocol.TowerDelegationMsg, sender string) (*protocol.TowerReceiptMsg, error) {
		for _, t := range towers {
			if msg.ChainID == t.cfg.ChainID && util.HexToAddress(msg.Registry) == t.cfg.Registry {
				return t.HandleDelegation(ctx, msg, sender)
			}
		}
		return nil, fmt.Errorf("towerd: no tower watches registry %s (chain %s)", msg.Registry, msg.ChainID)
	}
}
