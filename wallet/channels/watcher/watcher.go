// Package watcher is the chain-facing loop (Part 3 §7): it credits deposits
// and withdrawals at confirmation depth, tracks channel status from
// canonical logs, auto-challenges stale closes with the latest complete
// state, and settles own channels after the deadline.
//
// Transactions go through the keyed TxManager: nonce-pinned, fee-bumped,
// and resubmitted until mined — the challenge path never fire-and-forgets.
// Polling scan against a bind.ContractBackend is fine at 10-minute blocks.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	parallax "github.com/ParallaxProtocol/parallax/v2"

	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
)

// ChannelState mirrors the contract enum.
const (
	stateNonExistent = 0
	stateOpen        = 1
	stateClosing     = 2
)

// alarmBlocksBeforeDeadline is the hard-alarm threshold: a challenge still
// unmined this close to the deadline is the one loss-capable failure
// (Part 3 §13).
const alarmBlocksBeforeDeadline = 12

// Config wires one watcher to one registry deployment.
type Config struct {
	ChainID       string // decimal, must match the stored ChannelKeys
	Registry      util.Address
	Confirmations uint64 // act on logs at this depth (default 3)
}

// Watcher watches one registry for every channel in the store that belongs
// to it. txmgr MAY be nil for a watch-only instance (no challenge/settle);
// everything submitting with one key on one chain MUST share one manager
// (channeld owns it per chain, the tower reuses it) so nonce allocation is
// never split across managers.
type Watcher struct {
	cfg      Config
	store    *proofstore.Store
	backend  TxBackend
	contract *registry.ChannelRegistry
	txmgr    *TxManager

	// Combined-scan topics: one eth_getLogs per channel per tick covers all
	// six event kinds instead of six separate round trips.
	scanTopics                                                               []util.Hash
	evOpened, evDeposit, evWithdraw, evCloseStarted, evSettled, evCoopClosed util.Hash

	// Alarm receives operator-grade alerts (stale close observed, challenge
	// window nearly exhausted). Optional.
	Alarm func(format string, args ...any)
}

func New(cfg Config, store *proofstore.Store, backend TxBackend, txmgr *TxManager) (*Watcher, error) {
	if cfg.Confirmations == 0 {
		cfg.Confirmations = 3
	}
	contract, err := registry.NewChannelRegistry(cfg.Registry, backend)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		cfg:      cfg,
		store:    store,
		backend:  backend,
		contract: contract,
		txmgr:    txmgr,
	}
	abi, err := registry.ChannelRegistryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	w.evOpened = abi.Events["ChannelOpened"].ID
	w.evDeposit = abi.Events["ChannelDeposit"].ID
	w.evWithdraw = abi.Events["ChannelWithdraw"].ID
	w.evCloseStarted = abi.Events["CloseStarted"].ID
	w.evSettled = abi.Events["Settled"].ID
	w.evCoopClosed = abi.Events["CooperativeClosed"].ID
	w.scanTopics = []util.Hash{w.evOpened, w.evDeposit, w.evWithdraw, w.evCloseStarted, w.evSettled, w.evCoopClosed}
	if txmgr != nil && txmgr.Alarm == nil {
		txmgr.Alarm = func(format string, args ...any) { w.alarm(format, args...) }
	}
	return w, nil
}

// TxManager exposes the transaction manager (the tower shares it).
func (w *Watcher) TxManager() *TxManager { return w.txmgr }

func (w *Watcher) alarm(format string, args ...any) {
	if w.Alarm != nil {
		w.Alarm(format, args...)
	}
}

// Tick performs one scan-and-act pass and returns the confirmed head it
// acted on.
func (w *Watcher) Tick(ctx context.Context) (uint64, error) {
	header, err := w.backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, err
	}
	head := header.Number.Uint64()
	if head+1 < w.cfg.Confirmations {
		return head, nil
	}
	cutoff := head - (w.cfg.Confirmations - 1) // logs at or below are confirmed

	if w.txmgr != nil {
		w.txmgr.Tick(ctx, head)
	}
	channels, err := w.store.ListChannels()
	if err != nil {
		return head, err
	}
	// One failing channel must not starve the rest: every channel gets its
	// scan-and-act pass each tick, and the failures are reported joined.
	var errs []error
	for _, meta := range channels {
		if meta.Key.ChainID != w.cfg.ChainID || meta.Key.Registry != w.cfg.Registry {
			continue
		}
		if meta.Status == proofstore.StatusSettled {
			continue
		}
		if err := w.scanChannel(ctx, meta, cutoff); err != nil {
			errs = append(errs, fmt.Errorf("scan channel %s: %w", meta.Key, err))
			continue // an unscanned channel must not be acted on blindly
		}
		if err := w.actOnChannel(ctx, meta.Key, head); err != nil {
			errs = append(errs, fmt.Errorf("act on channel %s: %w", meta.Key, err))
		}
	}
	return head, errors.Join(errs...)
}

// scanChannel advances the confirmed-log watermark, crediting funding
// figures idempotently (cumulative totals are set, never added — a re-scan
// recomputes, never patches). One combined query covers every event kind;
// any retrieval or decode failure keeps the old watermark — advancing it
// past an unread log would skip it forever, and for CloseStarted that is a
// never-challenged stale close.
func (w *Watcher) scanChannel(ctx context.Context, meta proofstore.ChannelMeta, cutoff uint64) error {
	dep, err := w.store.Deposits(meta.Key)
	if err != nil {
		return err
	}
	from := dep.LastScannedBlock + 1
	if dep.LastScannedBlock == 0 {
		from = meta.OpenedAtBlock
	}
	if from > cutoff {
		return nil
	}
	chanTopic := util.BigToHash(new(big.Int).SetUint64(meta.Key.ChannelID))
	logs, err := w.backend.FilterLogs(ctx, parallax.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(cutoff),
		Addresses: []util.Address{w.cfg.Registry},
		Topics:    [][]util.Hash{w.scanTopics, {chanTopic}},
	})
	if err != nil {
		return err
	}

	// participantIsA resolves an event participant to a column: the only
	// addresses the store knows are the peer's and, by elimination, ours.
	participantIsA := func(participant util.Address) bool {
		if participant == meta.PeerAddress {
			return meta.Role == proofstore.RoleB
		}
		return meta.Role == proofstore.RoleA
	}

	for _, lg := range logs {
		if lg.Removed || len(lg.Topics) == 0 {
			continue
		}
		switch lg.Topics[0] {
		case w.evOpened:
			ev, err := w.contract.ParseChannelOpened(lg)
			if err != nil {
				return err
			}
			dep.DepositA = proofstore.NewU256(ev.Deposit)

		case w.evDeposit:
			ev, err := w.contract.ParseChannelDeposit(lg)
			if err != nil {
				return err
			}
			if participantIsA(ev.Participant) {
				dep.DepositA = proofstore.NewU256(ev.NewTotal)
			} else {
				dep.DepositB = proofstore.NewU256(ev.NewTotal)
			}

		case w.evWithdraw:
			ev, err := w.contract.ParseChannelWithdraw(lg)
			if err != nil {
				return err
			}
			if participantIsA(ev.Participant) {
				dep.WithdrawnA = proofstore.NewU256(ev.TotalWithdrawn)
			} else {
				dep.WithdrawnB = proofstore.NewU256(ev.TotalWithdrawn)
			}

		case w.evCloseStarted:
			ev, err := w.contract.ParseCloseStarted(lg)
			if err != nil {
				return err
			}
			if err := w.store.UpdateMeta(meta.Key, func(m *proofstore.ChannelMeta) {
				m.Status = proofstore.StatusClosing
			}); err != nil {
				return err
			}
			// Always alert on a stale close, even when auto-challenge will
			// succeed (Part 3 §13).
			if latest, lerr := w.store.LatestState(meta.Key); lerr == nil && ev.Seq < latest.Seq {
				w.alarm("stale CloseStarted on %s: on-chain seq %d < local %d (closer %s)",
					meta.Key, ev.Seq, latest.Seq, ev.Closer.Hex())
			}

		case w.evSettled, w.evCoopClosed:
			if err := w.store.UpdateMeta(meta.Key, func(m *proofstore.ChannelMeta) {
				m.Status = proofstore.StatusSettled
				m.FrozenUntilBlock = 0
				m.PendingClose = nil
			}); err != nil {
				return err
			}
		}
	}

	dep.LastScannedBlock = cutoff
	return w.store.PutDeposits(meta.Key, dep)
}

// actOnChannel reads the authoritative contract state and, when the channel
// is disputing, challenges with the latest complete state and settles after
// the deadline.
func (w *Watcher) actOnChannel(ctx context.Context, key proofstore.ChannelKey, head uint64) error {
	meta, err := w.store.Meta(key)
	if err != nil {
		return err
	}
	if meta.Status != proofstore.StatusClosing || w.txmgr == nil {
		return nil
	}

	onchain, err := w.contract.GetChannel(&bind.CallOpts{Context: ctx}, new(big.Int).SetUint64(key.ChannelID))
	if err != nil {
		return err
	}
	switch onchain.State {
	case stateNonExistent:
		// Deleted on-chain: settled (or coop-closed) and already handled by
		// the log scan once confirmed; nothing to act on.
		return nil
	case stateClosing:
	default:
		return nil
	}

	deadline := onchain.CloseInitiatedAtBlock.Uint64() + uint64(onchain.ChallengePeriodBlocks)

	latest, err := w.store.LatestState(key)
	if err != nil {
		// No complete state: nothing to challenge with; settle when due.
		latest = proofstore.SignedState{}
	}

	if latest.Seq > onchain.ClosingSeq && head <= deadline {
		return w.txmgr.Submit(ctx, "challenge:"+key.String(), head, deadline,
			func(auth *bind.TransactOpts) (*types.Transaction, error) {
				return w.contract.Challenge(auth, new(big.Int).SetUint64(key.ChannelID), latest.ContractProof(), latest.SigA, latest.SigB)
			})
	}
	if latest.Seq <= onchain.ClosingSeq {
		// Someone's challenge (ours or a tower's) took effect.
		w.txmgr.Done("challenge:" + key.String())
	}

	if head > deadline {
		return w.txmgr.Submit(ctx, "settle:"+key.String(), head, 0,
			func(auth *bind.TransactOpts) (*types.Transaction, error) {
				return w.contract.Settle(auth, new(big.Int).SetUint64(key.ChannelID))
			})
	}
	return nil
}

// DedupeKeyFor names outbound-queue entries the watcher settles implicitly.
func DedupeKeyFor(kind int, key proofstore.ChannelKey, seq uint64) string {
	return strconv.Itoa(kind) + ":" + key.String() + ":" + strconv.FormatUint(seq, 10)
}
