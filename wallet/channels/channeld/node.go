package channeld

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/keys"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/nostrmod"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/watcher"
)

// Backend is the chain access a Node needs; *client.Client satisfies it, and
// so does the simulated backend in tests.
type Backend interface {
	bind.ContractBackend
	bind.DeployBackend // receipt lookups for WaitMined
}

// Node wires the channel subsystem together for one wallet identity.
type Node struct {
	Cfg    Config
	Store  *proofstore.Store
	Engine *protocol.Engine
	Signer protocol.Signer

	NostrPriv string // hex
	SelfPub   string // x-only hex

	Pool        *nostrmod.Pool
	Transmitter *nostrmod.Transmitter
	Watchers    []*watcher.Watcher

	// TransmitInterval paces the outbound queue drain (default 1s; the
	// per-item backoff still governs retransmission).
	TransmitInterval time.Duration

	// OnPayment fires when an inbound payment completes against an invoice
	// (merchant webhooks, Part 3 §9). Called on the dispatcher goroutine.
	OnPayment func(invoiceID string, state *proofstore.SignedState)

	// DelegationHandler, when set (tower mode), processes inbound 21906
	// messages and returns the 21907 receipt.
	DelegationHandler func(ctx context.Context, msg protocol.TowerDelegationMsg, sender string) (*protocol.TowerReceiptMsg, error)

	backend Backend
	evmKey  *ecdsa.PrivateKey // retained for on-chain verbs (open/close/withdraw)
	txmgrs  map[string]*watcher.TxManager
	log     *slog.Logger

	// publishBackup publishes the self-backup snapshot (swappable in tests).
	publishBackup func(ctx context.Context) error
	backupMu      sync.Mutex
	backupRunning bool
	backupDirty   bool

	// inflight tracks on-chain submissions running off the dispatcher, keyed
	// by verb and channel, so a retransmitted proposal or ACK does not
	// broadcast a second transaction while the first is unmined.
	inflightMu sync.Mutex
	inflight   map[string]bool
}

// TxManagerFor returns the shared per-chain transaction manager (nil when
// the node is offline or the chain is unknown). Everything submitting with
// this node's key on a chain — watchers, the tower daemon — MUST go through
// this one manager, or their nonce allocations race and one transaction
// silently replaces the other.
func (n *Node) TxManagerFor(chainID string) *watcher.TxManager {
	return n.txmgrs[chainID]
}

// EVMKey exposes the wallet key for on-chain transaction building.
func (n *Node) EVMKey() *ecdsa.PrivateKey { return n.evmKey }

// Backend exposes the chain backend (nil for offline nodes).
func (n *Node) Backend() Backend { return n.backend }

// New assembles a node from configuration, the EVM key, and a data
// directory holding the proof store. The Nostr identity is derived from the
// EVM key (Part 3 §3); backend MAY be nil for offline verbs (QR, restore).
func New(cfg Config, dataDir string, evmPriv *ecdsa.PrivateKey, backend Backend, logger *slog.Logger) (*Node, error) {
	if logger == nil {
		logger = slog.Default()
	}
	store, err := proofstore.Open(filepath.Join(dataDir, "channels.db"))
	if err != nil {
		return nil, err
	}

	nk, err := keys.DeriveNostrKey(crypto.FromECDSA(evmPriv))
	if err != nil {
		store.Close()
		return nil, err
	}
	nostrPriv := hex.EncodeToString(nk.Priv[:])
	selfPub := hex.EncodeToString(nk.PubX[:])

	signer := protocol.NewKeySigner(evmPriv)
	maxInflight, _ := cfg.MaxInflight()
	engine := protocol.New(store, signer, protocol.Config{
		PushPayments:           cfg.Merchant.PushPayments,
		MaxInflightWei:         maxInflight,
		CoopCloseHorizonBlocks: cfg.Channels.CoopCloseHorizonBlocks,
	})

	n := &Node{
		Cfg:       cfg,
		Store:     store,
		Engine:    engine,
		Signer:    signer,
		NostrPriv: nostrPriv,
		SelfPub:   selfPub,
		backend:   backend,
		evmKey:    evmPriv,
		log:       logger,
	}

	n.Pool = nostrmod.NewPool(nostrmod.GoNostrDialer, cfg.AllRelays(), selfPub, nostrmod.PoolConfig{})
	n.Transmitter = nostrmod.NewTransmitter(store, n.Pool, nostrPriv)
	n.publishBackup = func(ctx context.Context) error {
		_, err := nostrmod.PublishBackup(ctx, n.Store, n.Pool, n.NostrPriv)
		return err
	}

	if backend != nil {
		n.txmgrs = make(map[string]*watcher.TxManager)
		for label, entries := range cfg.Registries {
			for _, e := range entries {
				chainID := strconv.FormatUint(e.ChainID, 10)
				txmgr := n.txmgrs[chainID]
				if txmgr == nil {
					txmgr = watcher.NewTxManager(backend, evmPriv, new(big.Int).SetUint64(e.ChainID))
					n.txmgrs[chainID] = txmgr
				}
				w, err := watcher.New(watcher.Config{
					ChainID:       chainID,
					Registry:      util.HexToAddress(e.Address),
					Confirmations: cfg.Node.Confirmations,
				}, store, backend, txmgr)
				if err != nil {
					store.Close()
					return nil, fmt.Errorf("channeld: registry %s: %w", label, err)
				}
				w.Alarm = func(format string, args ...any) {
					logger.Error("channel alarm", "msg", fmt.Sprintf(format, args...))
				}
				n.Watchers = append(n.Watchers, w)
			}
		}
	}
	return n, nil
}

// Close releases the store.
func (n *Node) Close() error {
	return n.Store.Close()
}

// Run starts the long-lived loops: relay pool, transmitter, watcher ticks,
// and the inbound dispatcher. Blocks until ctx is done.
func (n *Node) Run(ctx context.Context, watcherInterval time.Duration) {
	transmitInterval := n.TransmitInterval
	if transmitInterval == 0 {
		transmitInterval = time.Second
	}
	go n.Pool.Run(ctx)
	go n.Transmitter.Run(ctx, transmitInterval, func(item proofstore.OutboundItem) {
		n.log.Warn("outbound gave up", "kind", item.Kind, "dedupe", item.DedupeKey)
		if item.Kind == protocol.KindProposal {
			// Give-up on a proposal leaves the channel poisoned (Part 3 §5).
			if key, _, ok := channelKeyFromDedupe(item.DedupeKey); ok {
				if err := n.Engine.MarkPoisoned(key); err != nil {
					n.log.Error("mark poisoned", "err", err)
				}
			}
		}
	})
	if len(n.Watchers) > 0 {
		go n.watchLoop(ctx, watcherInterval)
	}
	if n.Cfg.Backup.Enabled || len(n.Cfg.Channels.Towers.Npubs) > 0 {
		// Reconnect catch-up (Part 2 §11.2): state that completed offline
		// (QR) gets parked on the relays and delegated to the towers as soon
		// as we are back. Delegation runs regardless of the backup switch —
		// it is loss protection, not backup.
		go func() {
			for i := 0; i < 30; i++ {
				if n.Pool.Healthy() > 0 {
					n.afterCompletion(ctx, nil)
					return
				}
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	n.dispatchLoop(ctx)
}

func (n *Node) watchLoop(ctx context.Context, interval time.Duration) {
	tick := func() {
		for _, w := range n.Watchers {
			head, err := w.Tick(ctx)
			if err != nil {
				// Partial per-channel failures still return a valid head.
				n.log.Error("watcher tick", "err", err)
			}
			if head > 0 {
				n.unfreezeExpired(head)
			}
		}
	}
	tick() // sync immediately at start: one-shot CLI verbs rely on it
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			tick()
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) unfreezeExpired(head uint64) {
	metas, err := n.Store.ListChannels()
	if err != nil {
		return
	}
	for _, meta := range metas {
		if meta.FrozenUntilBlock != 0 && head > meta.FrozenUntilBlock {
			if err := n.Engine.Unfreeze(meta.Key, head); err != nil {
				n.log.Error("unfreeze", "channel", meta.Key.String(), "err", err)
			}
		}
		if meta.PendingWithdraw != nil || meta.PeerPendingWithdraw != nil {
			if err := n.Engine.SweepWithdraw(meta.Key, head); err != nil {
				n.log.Error("withdraw sweep", "channel", meta.Key.String(), "err", err)
			}
		}
	}
}

// dispatchLoop unwraps inbound gift wraps and routes rumors to the engine.
func (n *Node) dispatchLoop(ctx context.Context) {
	for {
		select {
		case wrap := <-n.Pool.Events():
			rumor, sender, err := nostrmod.Unwrap(wrap, n.NostrPriv)
			if err != nil {
				continue // not for us / garbage; relays are untrusted
			}
			if err := n.handleRumor(ctx, rumor, sender); err != nil {
				n.log.Warn("rumor rejected", "kind", rumor.Kind, "err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) handleRumor(ctx context.Context, rumor nostr.Event, sender string) error {
	// The head is fetched per branch, not up front: only the proposal kinds
	// consult it, and an eager fetch costs every ACK, NACK, invoice, and
	// tower message an RPC round trip for nothing.
	switch rumor.Kind {
	case protocol.KindProposal:
		var msg protocol.ProposalMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		// Check 6 judges withdraw vouchers by expiry, and the freeze check
		// by block: an online node whose RPC is failing must defer rather
		// than count an expired voucher as live at nowBlock 0 and NACK (and
		// poison) a valid payment. The peer retransmits.
		nowBlock, err := n.requireHead(ctx)
		if err != nil {
			return fmt.Errorf("%w; deferring proposal for channel %s", err, msg.State.ChannelID)
		}
		res, err := n.Engine.HandleProposal(msg, sender, nowBlock, time.Now().Unix())
		if err != nil {
			return err
		}
		if res.InvoicePaid != "" && n.OnPayment != nil {
			n.OnPayment(res.InvoicePaid, res.Completed)
		}
		if res.Rebase != 0 {
			st, serr := protocol.FromWire(msg.State)
			if serr != nil {
				return serr
			}
			if err := n.rebaseProposal(st.Key, res.Rebase, nowBlock); err != nil {
				return err
			}
		}
		return n.reactToResult(ctx, res, sender, msg.State.ChannelID, protocol.KindAck)

	case protocol.KindAck:
		var msg protocol.AckMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		keys := n.channelsForPeer(msg.ChannelID, sender)
		if len(keys) == 0 {
			return fmt.Errorf("ack for unknown channel %s", msg.ChannelID)
		}
		var lastErr error
		for _, key := range keys {
			complete, err := n.Engine.HandleAck(key, msg)
			if err != nil {
				lastErr = err
				continue
			}
			n.settleOutbound(protocol.KindProposal, key, complete.Seq)
			n.afterCompletion(ctx, complete)
			return nil
		}
		return lastErr

	case protocol.KindNack:
		var msg protocol.NackMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		// NACKs carry no verifiable state, so sender scoping is the whole
		// authorization: only the counterparty of a matching channel may
		// poison it. HandleNack matches on seq alone, which cannot separate
		// same-peer channels sharing the bare id across coexisting
		// registries — the message's registry qualifier does.
		candidates := n.channelsForPeer(msg.ChannelID, sender)
		if msg.Registry != "" {
			// A present qualifier must parse — treating a malformed one as
			// unqualified would bypass the scoping and poison whichever
			// same-peer twin holds a journaled state at this seq.
			if !util.IsHexAddress(msg.Registry) {
				return fmt.Errorf("nack with malformed registry %q", msg.Registry)
			}
			reg := util.HexToAddress(msg.Registry)
			var scoped []proofstore.ChannelKey
			for _, key := range candidates {
				if key.Registry == reg && (msg.ChainID == "" || key.ChainID == msg.ChainID) {
					scoped = append(scoped, key)
				}
			}
			candidates = scoped
		}
		for _, key := range candidates {
			poisoned, err := n.Engine.HandleNack(key, msg)
			if err != nil {
				return err
			}
			if poisoned {
				exposure, _ := n.Engine.PoisonedExposure(key)
				n.log.Warn("channel poisoned by NACK", "channel", key.String(),
					"reason", msg.Reason, "exposureWei", exposure)
				// Seq alone cannot tell a legacy unqualified NACK's target
				// apart from its same-peer twins; poison one channel, not all.
				return nil
			}
		}
		return nil

	case protocol.KindCoopCloseProposal:
		var msg protocol.CoopCloseProposalMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		// Countersigning freezes us until the proposal's expiry, and only a
		// head view can judge the expiry and freeze-horizon checks. An online
		// node whose RPC is failing must defer, not process with nowBlock 0 —
		// that would skip both checks and hand an authenticated peer a
		// permanent-freeze grenade. The peer retransmits until a delivery
		// finds a healthy RPC; genuinely offline nodes take the QR path.
		nowBlock, err := n.requireHead(ctx)
		if err != nil {
			return fmt.Errorf("%w; deferring coop-close proposal for channel %s", err, msg.ChannelID)
		}
		res, ready, err := n.Engine.HandleCoopCloseProposal(msg, sender, nowBlock)
		if err != nil {
			return err
		}
		// Settle on-chain first: we hold the complete pair, and submission
		// must not depend on the relay accepting our countersignature.
		if ready != nil {
			n.submitCoopClose(ctx, ready)
		}
		return n.reactToResult(ctx, res, sender, msg.ChannelID, protocol.KindCoopCloseAck)

	case protocol.KindCoopCloseAck:
		var msg protocol.AckMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		var lastErr error
		for _, key := range n.channelsForPeer(msg.ChannelID, sender) {
			ready, err := n.Engine.HandleCoopCloseAck(key, msg)
			if err != nil {
				lastErr = err
				continue
			}
			n.settleOutbound(protocol.KindCoopCloseProposal, key, 0)
			n.submitCoopClose(ctx, ready)
			return nil
		}
		return lastErr

	case protocol.KindInvoice:
		var msg protocol.InvoiceMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		return n.handleInvoice(msg, sender)

	case protocol.KindWithdrawProposal:
		var msg protocol.WithdrawProposalMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		// Same head requirement as coop-close proposals: the expiry check is
		// meaningless at nowBlock 0, and a far-future pending withdraw blocks
		// re-proposals until it expires.
		nowBlock, err := n.requireHead(ctx)
		if err != nil {
			return fmt.Errorf("%w; deferring withdraw proposal for channel %s", err, msg.ChannelID)
		}
		res, ready, err := n.Engine.HandleWithdrawProposal(msg, sender, nowBlock)
		if err != nil {
			return err
		}
		// The proposer is the payee and submits; the responder only returns
		// the countersignature. (ready is the responder's copy of the pair,
		// unused here.)
		_ = ready
		return n.reactToResult(ctx, res, sender, msg.ChannelID, protocol.KindWithdrawAck)

	case protocol.KindWithdrawAck:
		var msg protocol.AckMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		var lastErr error
		for _, key := range n.channelsForPeer(msg.ChannelID, sender) {
			ready, err := n.Engine.HandleWithdrawAck(key, msg)
			if err != nil {
				lastErr = err
				continue
			}
			n.settleOutbound(protocol.KindWithdrawProposal, key, 0)
			if n.backend != nil {
				// Not loss-capable on failure: retry on the next ack
				// retransmission or re-propose after expiry.
				n.submitAsync("withdraw", key, func() error { return n.SubmitWithdraw(ctx, ready) })
			}
			return nil
		}
		return lastErr

	case protocol.KindTowerDelegation:
		if n.DelegationHandler == nil {
			return nil // not running a tower
		}
		var msg protocol.TowerDelegationMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		receipt, err := n.DelegationHandler(ctx, msg, sender)
		if err != nil {
			return err
		}
		return n.sendDirect(ctx, sender, protocol.KindTowerReceipt, receipt, msg.ChannelID)

	case protocol.KindTowerReceipt:
		// Queued delegations are the loss protection for offline periods, so
		// only the towers this node delegates to may settle them.
		if !n.isConfiguredTower(sender) {
			return nil
		}
		var msg protocol.TowerReceiptMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		seq, err := strconv.ParseUint(msg.Seq, 10, 64)
		if err != nil {
			return nil
		}
		id, err := strconv.ParseUint(msg.ChannelID, 10, 64)
		if err != nil {
			return nil
		}
		// A receipt acknowledges the tower holds state at msg.Seq (its kept
		// max), so it settles every queued delegation at or below that seq —
		// for the acknowledging tower only: the other configured towers still
		// need their deliveries.
		items, err := n.Store.OutboundAll()
		if err != nil {
			return err
		}
		// Candidates: this tower, this bare id, plus whatever qualifiers the
		// receipt carries (older towers omit Registry/ChainID). If the
		// remainder still spans more than one registry deployment, the bare
		// id cannot say which channel the tower acknowledged — and its
		// kept-seq is meaningless across registries — so settling would
		// silently cancel loss protection. Fail closed: the queue keeps
		// retransmitting, and a current tower answers qualified.
		type delegation struct {
			item proofstore.OutboundItem
			seq  uint64
		}
		var cands []delegation
		deployments := make(map[string]bool)
		for _, item := range items {
			if item.Kind != protocol.KindTowerDelegation || item.ToNpub != sender {
				continue
			}
			key, itemSeq, ok := channelKeyFromDedupe(item.DedupeKey)
			if !ok || key.ChannelID != id {
				continue
			}
			if msg.Registry != "" && !strings.EqualFold(msg.Registry, key.Registry.Hex()) {
				continue
			}
			if msg.ChainID != "" && msg.ChainID != key.ChainID {
				continue
			}
			deployments[key.ChainID+":"+strings.ToLower(key.Registry.Hex())] = true
			cands = append(cands, delegation{item, itemSeq})
		}
		if len(deployments) > 1 {
			n.log.Warn("ignoring tower receipt: bare channel id is ambiguous across coexisting registries",
				"tower", sender, "channel", msg.ChannelID)
			return nil
		}
		for _, c := range cands {
			if c.seq > seq {
				continue
			}
			if err := n.Store.RemoveOutbound(c.item.ID); err != nil {
				n.log.Error("outbound cleanup", "err", err)
			}
		}
		return nil

	case protocol.KindHandshake:
		var msg protocol.HandshakeMsg
		if err := json.Unmarshal([]byte(rumor.Content), &msg); err != nil {
			return err
		}
		return n.handleHandshake(ctx, msg, sender)

	default:
		return nil // invoices/tower kinds arrive with later phases
	}
}

// reactToResult transmits the engine's response (direct sends, no queue:
// ACKs and NACKs are re-issued idempotently on duplicate proposals instead
// of retransmitted).
func (n *Node) reactToResult(ctx context.Context, res protocol.Result, peer string, channelID string, ackKind int) error {
	if res.Completed != nil {
		n.afterCompletion(ctx, res.Completed)
	}
	if res.Completed != nil {
		// Our own proposals below the completed seq are dead (the peer's
		// re-issue above a same-seq conflict, Part 2 §7.5); stop
		// retransmitting them. A payment intent they carried is the
		// caller's to re-issue at a fresh seq.
		for _, seq := range res.Voided {
			n.settleOutbound(protocol.KindProposal, res.Completed.Key, seq)
			n.log.Info("own proposal voided by a higher completed state; local intent needs rebase",
				"channel", res.Completed.Key.String(), "seq", seq, "completed", res.Completed.Seq)
		}
	}
	var payload any
	var kind int
	switch {
	case res.Ack != nil:
		payload, kind = res.Ack, ackKind
	case res.Nack != nil:
		n.log.Warn("nacking inbound message", "channel", channelID,
			"re", res.Nack.Re, "reason", res.Nack.Reason, "detail", res.Nack.Detail)
		payload, kind = res.Nack, protocol.KindNack
	default:
		return nil
	}
	return n.sendDirect(ctx, peer, kind, payload, channelID)
}

func (n *Node) sendDirect(ctx context.Context, peer string, kind int, payload any, channelID string) error {
	content, err := protocol.EncodePayload(payload)
	if err != nil {
		return err
	}
	rumor := nostr.Event{
		Kind:      kind,
		Content:   content,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{nostr.Tag{"ch", channelID}},
	}
	wrap, err := nostrmod.Wrap(rumor, peer, n.NostrPriv)
	if err != nil {
		return err
	}
	if n.Pool.Publish(ctx, wrap) == 0 {
		return fmt.Errorf("no relay accepted kind %d", kind)
	}
	return nil
}

// afterCompletion runs after every completed state change: self-backup
// (Part 2 §6.10) and tower delegation (Part 2 §9). state MAY be nil (bulk
// catch-up: delegate the latest state of every channel).
func (n *Node) afterCompletion(ctx context.Context, state *proofstore.SignedState) {
	if n.Cfg.Backup.Enabled {
		n.requestBackup(ctx)
	}
	if len(n.Cfg.Channels.Towers.Npubs) == 0 {
		return
	}
	if state != nil {
		n.delegate(*state)
		return
	}
	metas, err := n.Store.ListChannels()
	if err != nil {
		return
	}
	for _, meta := range metas {
		if meta.Status == proofstore.StatusSettled {
			continue
		}
		if latest, err := n.Store.LatestState(meta.Key); err == nil {
			n.delegate(latest)
		}
	}
}

// requestBackup runs the self-backup off the calling goroutine: the
// snapshot marshals the whole store and round-trips the relays, and the
// dispatcher must not sit behind that for every completed payment.
// Completions arriving while a backup is in flight coalesce into a single
// trailing run — the backup is a whole-store snapshot, so the last one
// covers them all. Best-effort like the synchronous version was (errors
// logged); tower delegation, the loss protection, stays on the queue.
func (n *Node) requestBackup(ctx context.Context) {
	n.backupMu.Lock()
	if n.backupRunning {
		n.backupDirty = true
		n.backupMu.Unlock()
		return
	}
	n.backupRunning = true
	n.backupMu.Unlock()
	go func() {
		for {
			if err := n.publishBackup(ctx); err != nil {
				n.log.Error("self-backup", "err", err)
			}
			n.backupMu.Lock()
			if !n.backupDirty {
				n.backupRunning = false
				n.backupMu.Unlock()
				return
			}
			n.backupDirty = false
			n.backupMu.Unlock()
		}
	}()
}

// delegate queues a 21906 for every configured tower; retransmission stops
// on the 21907 receipt.
func (n *Node) delegate(st proofstore.SignedState) {
	msg := protocol.TowerDelegationMsg{
		V:         1,
		Registry:  strings.ToLower(st.Key.Registry.Hex()),
		ChainID:   st.Key.ChainID,
		ChannelID: strconv.FormatUint(st.Key.ChannelID, 10),
		State:     protocol.ToWire(st),
	}
	content, err := protocol.EncodePayload(msg)
	if err != nil {
		n.log.Error("delegation encode", "err", err)
		return
	}
	now := time.Now().Unix()
	for _, npub := range n.Cfg.Channels.Towers.Npubs {
		_, err := n.Store.EnqueueOutbound(proofstore.OutboundItem{
			DedupeKey: watcher.DedupeKeyFor(protocol.KindTowerDelegation, st.Key, st.Seq),
			ToNpub:    npub,
			Kind:      protocol.KindTowerDelegation,
			Content:   content,
			Tags:      [][]string{{"ch", msg.ChannelID}},
			RumorTime: now,
			ExpiresAt: now + 24*3600,
		})
		if err != nil {
			n.log.Error("delegation enqueue", "err", err)
		}
	}
}

// rebaseProposal re-issues our proposal at seq, which lost a same-seq
// conflict (Part 2 §7.5), one seq higher. The invoice id rides only in the
// queued rumor, so it is recovered from there before that item is settled;
// the new proposal is queued before the old one is dropped, so a crash in
// between leaves at worst both queued. The peer retransmits its conflicting
// proposal, so this runs repeatedly: RebaseProposal returns the same
// re-issue, and it is queued only once.
func (n *Node) rebaseProposal(key proofstore.ChannelKey, seq, nowBlock uint64) error {
	items, err := n.Store.OutboundAll()
	if err != nil {
		return err
	}
	queued := make(map[string]bool, len(items))
	invoiceID := ""
	for _, item := range items {
		queued[item.DedupeKey] = true
		if item.DedupeKey != watcher.DedupeKeyFor(protocol.KindProposal, key, seq) {
			continue
		}
		var old protocol.ProposalMsg
		if json.Unmarshal([]byte(item.Content), &old) == nil {
			invoiceID = old.InvoiceID
		}
	}
	prop, err := n.Engine.RebaseProposal(key, seq, invoiceID, nowBlock)
	if err != nil {
		return fmt.Errorf("rebase seq %d on channel %s: %w", seq, key, err)
	}
	newSeq, err := strconv.ParseUint(prop.State.Seq, 10, 64)
	if err != nil {
		return err
	}
	if !queued[watcher.DedupeKeyFor(protocol.KindProposal, key, newSeq)] {
		if err := n.enqueueProposal(key, prop); err != nil {
			return err
		}
	}
	n.settleOutbound(protocol.KindProposal, key, seq)
	n.log.Info("tiebreak: re-issued own proposal above the conflict",
		"channel", key.String(), "lost", seq, "seq", prop.State.Seq)
	return nil
}

func (n *Node) settleOutbound(kind int, key proofstore.ChannelKey, seq uint64) {
	if _, err := n.Store.RemoveOutboundByDedupe(watcher.DedupeKeyFor(kind, key, seq)); err != nil {
		n.log.Error("outbound cleanup", "err", err)
	}
}

func (n *Node) submitCoopClose(ctx context.Context, ready *protocol.CoopCloseReady) {
	n.log.Info("cooperative close fully signed",
		"channel", ready.Key.String(), "balanceA", ready.BalanceA, "balanceB", ready.BalanceB)
	if n.backend == nil {
		return // offline node: the counterparty submits, or the CLI does later
	}
	// Not loss-capable on failure: the counterparty holds the same pair and
	// the freeze holds until expiry either way.
	n.submitAsync("coopclose", ready.Key, func() error { return n.SubmitCoopClose(ctx, ready) })
}

// submitAsync runs an on-chain submission off the calling goroutine, at
// most one per verb and channel at a time. Submission waits for the
// transaction to mine — at least a block, so >=10 minutes of wall clock —
// and is reached from the dispatcher's call path: it must not hold up every
// other channel's inbound processing meanwhile (any counterparty could
// trigger that stall at will by proposing a close). The engine re-returns
// the ready pair for every retransmitted proposal or ACK, and each
// submission takes a fresh nonce, so without the single-flight gate a
// retransmission during that wait would broadcast a second transaction
// that reverts behind the first. Failures are logged; every caller has a
// retry path (the peer's retransmission, or the CLI).
func (n *Node) submitAsync(verb string, key proofstore.ChannelKey, submit func() error) {
	id := verb + ":" + key.String()
	n.inflightMu.Lock()
	if n.inflight[id] {
		n.inflightMu.Unlock()
		n.log.Debug("submission already in flight", "id", id)
		return
	}
	if n.inflight == nil {
		n.inflight = make(map[string]bool)
	}
	n.inflight[id] = true
	n.inflightMu.Unlock()
	go func() {
		defer func() {
			n.inflightMu.Lock()
			delete(n.inflight, id)
			n.inflightMu.Unlock()
		}()
		if err := submit(); err != nil {
			n.log.Error(verb+" submission", "channel", key.String(), "err", err)
		}
	}()
}

// channelsForPeer resolves a bare wire channel id against the store, scoped
// to the authenticated sender. A bare id is NOT globally unique — coexisting
// registries each number channels from 1 — so resolution must never pick the
// first store entry; scoping to the sender both disambiguates and doubles as
// the counterparty check for ack/nack kinds that carry no signed state.
// Handlers try every candidate: the per-message verification (state hash,
// journal seq) selects the one the message belongs to.
func (n *Node) channelsForPeer(channelID, sender string) []proofstore.ChannelKey {
	id, err := strconv.ParseUint(channelID, 10, 64)
	if err != nil {
		return nil
	}
	metas, err := n.Store.ListChannels()
	if err != nil {
		return nil
	}
	var keys []proofstore.ChannelKey
	for _, meta := range metas {
		if meta.Key.ChannelID == id && meta.PeerNpub == sender {
			keys = append(keys, meta.Key)
		}
	}
	return keys
}

// isConfiguredTower reports whether sender is one of the towers this node
// delegates to.
func (n *Node) isConfiguredTower(sender string) bool {
	for _, npub := range n.Cfg.Channels.Towers.Npubs {
		if npub == sender {
			return true
		}
	}
	return false
}

// requireHead returns the chain head for verbs whose checks are meaningless
// without one (expiries, freeze horizons, voucher liveness). A node with no
// backend reports 0 with no error — offline, where the QR path's nowBlock 0
// is by design. An online node whose RPC fails gets the error, so the
// caller defers rather than signing or judging against head 0.
func (n *Node) requireHead(ctx context.Context) (uint64, error) {
	if n.backend == nil {
		return 0, nil
	}
	header, err := n.backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("chain head unavailable: %w", err)
	}
	return header.Number.Uint64(), nil
}

// headBlock is requireHead for verbs that tolerate an unknown head as 0.
func (n *Node) headBlock(ctx context.Context) uint64 {
	head, _ := n.requireHead(ctx)
	return head
}

// channelKeyFromDedupe parses watcher.DedupeKeyFor's
// "<kind>:<chainId>:<registry>:<channelId>:<seq>" format.
func channelKeyFromDedupe(dedupe string) (proofstore.ChannelKey, uint64, bool) {
	parts := strings.Split(dedupe, ":")
	if len(parts) != 5 || !util.IsHexAddress(parts[2]) {
		return proofstore.ChannelKey{}, 0, false
	}
	channelID, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil {
		return proofstore.ChannelKey{}, 0, false
	}
	seq, err := strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		return proofstore.ChannelKey{}, 0, false
	}
	return proofstore.ChannelKey{
		ChainID:   parts[1],
		Registry:  util.HexToAddress(parts[2]),
		ChannelID: channelID,
	}, seq, true
}
