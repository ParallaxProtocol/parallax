package channeld

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind/backends"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
)

// newTestNodeWith is newTestNode with a config hook applied before assembly.
func newTestNodeWith(t *testing.T, h *hub, mutate func(*Config)) *Node {
	t.Helper()
	return newTestNodeWithBackend(t, h, nil, mutate)
}

// newTestNodeWithBackend is newTestNodeWith over a chain backend (nil for
// an offline node).
func newTestNodeWithBackend(t *testing.T, h *hub, backend Backend, mutate func(*Config)) *Node {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Registries = map[string][]RegistryEntry{
		"v1": {{Address: e2eKey.Registry.Hex(), ChainID: 2110}},
	}
	cfg.Nostr.Relays = []string{"wss://hub"}
	cfg.Merchant.PushPayments = true
	if mutate != nil {
		mutate(&cfg)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	n, err := New(cfg, t.TempDir(), key, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	n.Pool = newHubPool(h, n.SelfPub)
	n.Transmitter = newHubTransmitter(n)
	return n
}

func encodeRumor(t *testing.T, kind int, payload any) nostr.Event {
	t.Helper()
	content, err := protocol.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	return nostr.Event{Kind: kind, Content: content}
}

var attackerNpub = strings.Repeat("ab", 32)

// decoyKey shares e2eKey's bare channel id on a coexisting registry that
// sorts before it in the store, so first-match resolution picks it.
var decoyKey = proofstore.ChannelKey{
	ChainID:   "2110",
	Registry:  util.HexToAddress("0x0000000000000000000000000000000000001111"),
	ChannelID: 1,
}

// addDecoyChannel gives the node a second open channel with the same bare id
// as e2eKey, against a different peer on a different registry.
func addDecoyChannel(t *testing.T, n *Node) {
	t.Helper()
	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	err = n.Store.CreateChannel(proofstore.ChannelMeta{
		Key:             decoyKey,
		Role:            proofstore.RoleA,
		Status:          proofstore.StatusOpen,
		PeerNpub:        strings.Repeat("cd", 32),
		PeerAddress:     crypto.PubkeyToAddress(peerKey.PublicKey),
		ChallengePeriod: 144,
	})
	if err != nil {
		t.Fatal(err)
	}
	deposits := proofstore.Deposits{
		DepositA:         proofstore.NewU256(big.NewInt(10e9)),
		DepositB:         proofstore.NewU256(big.NewInt(5e9)),
		LastScannedBlock: 1,
	}
	if err := n.Store.PutDeposits(decoyKey, deposits); err != nil {
		t.Fatal(err)
	}
}

// TestNackRequiresPeerSender: a NACK from anyone but the channel
// counterparty must not poison the channel (griefing DoS).
func TestNackRequiresPeerSender(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)

	if _, err := alice.Engine.ProposePayment(e2eKey, big.NewInt(1e9), "", 0); err != nil {
		t.Fatal(err)
	}
	nackMsg := protocol.NackMsg{V: 1, ChannelID: "1", Re: "21902", Seq: "1", Reason: protocol.NackPolicy}
	rumor := encodeRumor(t, protocol.KindNack, nackMsg)

	if err := alice.handleRumor(context.Background(), rumor, attackerNpub); err != nil {
		t.Logf("attacker nack rejected: %v", err)
	}
	meta, err := alice.Store.Meta(e2eKey)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Poisoned {
		t.Fatal("channel poisoned by a NACK from a non-counterparty sender")
	}

	// The genuine counterparty's NACK still lands.
	if err := alice.handleRumor(context.Background(), rumor, bob.SelfPub); err != nil {
		t.Fatal(err)
	}
	meta, _ = alice.Store.Meta(e2eKey)
	if !meta.Poisoned {
		t.Fatal("counterparty NACK ignored")
	}
}

// TestAckRoutesAcrossCoexistingRegistries: the bare wire channel id is only
// unique per counterparty; with two registries both holding id 1, the ACK
// must complete the proposal on the sender's channel, not stall against the
// first store entry.
func TestAckRoutesAcrossCoexistingRegistries(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)
	addDecoyChannel(t, alice)

	amount := big.NewInt(3e9)
	prop, err := alice.Engine.ProposePayment(e2eKey, amount, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bob.Engine.HandleProposal(*prop, alice.SelfPub, 0, time.Now().Unix())
	if err != nil || res.Ack == nil {
		t.Fatalf("bob did not ack: %+v %v", res, err)
	}

	rumor := encodeRumor(t, protocol.KindAck, res.Ack)
	if err := alice.handleRumor(context.Background(), rumor, bob.SelfPub); err != nil {
		t.Fatalf("ack misrouted: %v", err)
	}
	latest, err := alice.Store.LatestState(e2eKey)
	if err != nil || latest.Seq != 1 {
		t.Fatalf("payment did not complete on the sender's channel: %+v %v", latest, err)
	}
}

// TestNackRoutesAcrossCoexistingRegistries: a NACK from bob must only ever
// poison the channel alice shares with bob, never the same-id channel on the
// coexisting registry.
func TestNackRoutesAcrossCoexistingRegistries(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)
	addDecoyChannel(t, alice)

	// Outstanding seq-1 proposals on both channels.
	if _, err := alice.Engine.ProposePayment(decoyKey, big.NewInt(1e9), "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Engine.ProposePayment(e2eKey, big.NewInt(1e9), "", 0); err != nil {
		t.Fatal(err)
	}

	nackMsg := protocol.NackMsg{V: 1, ChannelID: "1", Re: "21902", Seq: "1", Reason: protocol.NackPolicy}
	rumor := encodeRumor(t, protocol.KindNack, nackMsg)
	if err := alice.handleRumor(context.Background(), rumor, bob.SelfPub); err != nil {
		t.Fatal(err)
	}

	decoyMeta, _ := alice.Store.Meta(decoyKey)
	if decoyMeta.Poisoned {
		t.Fatal("bob's NACK poisoned the coexisting registry's channel")
	}
	meta, _ := alice.Store.Meta(e2eKey)
	if !meta.Poisoned {
		t.Fatal("bob's NACK did not poison bob's channel")
	}
}

// TestChannelRefResolution: user-supplied bare ids must fail closed when
// coexisting registries share the id; the qualified form disambiguates.
func TestChannelRefResolution(t *testing.T) {
	h := newHub()
	alice := newTestNode(t, h, nil)
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)
	addDecoyChannel(t, alice)

	if _, err := alice.ChannelKeyByID(1); !errors.Is(err, ErrAmbiguousChannel) {
		t.Fatalf("ambiguous bare id resolved: %v", err)
	}
	for _, want := range []proofstore.ChannelKey{e2eKey, decoyKey} {
		key, err := alice.ParseChannelRef(want.String())
		if err != nil || key != want {
			t.Fatalf("qualified ref %s: %+v %v", want, key, err)
		}
	}
	// A unique bare id still resolves.
	key, err := bob.ParseChannelRef("1")
	if err != nil || key != e2eKey {
		t.Fatalf("unique bare id: %+v %v", key, err)
	}
	if _, err := bob.ParseChannelRef("7"); err == nil {
		t.Fatal("unknown id resolved")
	}
}

// fakeSig is a structurally valid 65-byte signature (delegation queueing
// does not re-verify; the tower does).
var fakeSig = bytes.Repeat([]byte{0x11}, 65)

func dualSignedFake(seq uint64) proofstore.SignedState {
	return proofstore.SignedState{
		Key:             e2eKey,
		Seq:             seq,
		TransferredAtoB: proofstore.NewU256(big.NewInt(3e9)),
		TransferredBtoA: proofstore.NewU256(nil),
		LockedAmount:    proofstore.NewU256(nil),
		SigA:            fakeSig,
		SigB:            fakeSig,
	}
}

// TestTowerReceiptRequiresTowerSender: only a configured tower may settle a
// queued delegation, and a receipt settles the acknowledging tower's copy
// only — the other tower still needs its delivery.
func TestTowerReceiptRequiresTowerSender(t *testing.T) {
	tower1 := strings.Repeat("01", 32)
	tower2 := strings.Repeat("02", 32)
	h := newHub()
	alice := newTestNodeWith(t, h, func(cfg *Config) {
		cfg.Channels.Towers.Npubs = []string{tower1, tower2}
	})
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)

	alice.delegate(dualSignedFake(1))
	if n, _ := alice.Store.OutboundLen(); n != 2 {
		t.Fatalf("delegations queued: %d", n)
	}

	receipt := protocol.TowerReceiptMsg{V: 1, ChannelID: "1", Seq: "1", OK: true}
	rumor := encodeRumor(t, protocol.KindTowerReceipt, receipt)

	// An arbitrary Nostr identity must not be able to cancel the queue.
	if err := alice.handleRumor(context.Background(), rumor, attackerNpub); err != nil {
		t.Logf("attacker receipt rejected: %v", err)
	}
	if n, _ := alice.Store.OutboundLen(); n != 2 {
		t.Fatalf("attacker receipt cancelled delegations: %d left", n)
	}

	// Tower 1's receipt settles tower 1's copy only.
	if err := alice.handleRumor(context.Background(), rumor, tower1); err != nil {
		t.Fatal(err)
	}
	items, err := alice.Store.OutboundAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ToNpub != tower2 {
		t.Fatalf("tower 2's delegation not preserved: %+v", items)
	}
}

// TestTowerReceiptSettlesLowerSeqs: a receipt naming a higher kept seq (the
// tower already holds newer state) settles any lower queued delegation
// instead of leaving it retransmitting until its 24h give-up.
func TestTowerReceiptSettlesLowerSeqs(t *testing.T) {
	tower1 := strings.Repeat("01", 32)
	h := newHub()
	alice := newTestNodeWith(t, h, func(cfg *Config) {
		cfg.Channels.Towers.Npubs = []string{tower1}
	})
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)

	alice.delegate(dualSignedFake(3))
	receipt := protocol.TowerReceiptMsg{V: 1, ChannelID: "1", Seq: "5", OK: true}
	if err := alice.handleRumor(context.Background(), encodeRumor(t, protocol.KindTowerReceipt, receipt), tower1); err != nil {
		t.Fatal(err)
	}
	if n, _ := alice.Store.OutboundLen(); n != 0 {
		t.Fatalf("delegation at seq 3 not settled by kept-seq-5 receipt: %d queued", n)
	}
}

// TestTowerReceiptWithoutRegistryFailsClosedAcrossRegistries: a receipt that
// omits the registry qualifier (older towers) matches on the bare channel id
// alone, but the bare id is not unique across coexisting registries — the
// receipt must not settle a delegation for a channel the tower never
// acknowledged, silently cancelling its loss protection. A qualified receipt
// settles exactly its registry's copy.
func TestTowerReceiptWithoutRegistryFailsClosedAcrossRegistries(t *testing.T) {
	tower1 := strings.Repeat("01", 32)
	h := newHub()
	alice := newTestNodeWith(t, h, func(cfg *Config) {
		cfg.Channels.Towers.Npubs = []string{tower1}
	})
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)
	addDecoyChannel(t, alice) // same bare id as e2eKey on a coexisting registry

	alice.delegate(dualSignedFake(1))
	decoySt := dualSignedFake(1)
	decoySt.Key = decoyKey
	alice.delegate(decoySt)
	if n, _ := alice.Store.OutboundLen(); n != 2 {
		t.Fatalf("delegations queued: %d", n)
	}

	// An unqualified receipt cannot say which registry's channel 1 it
	// acknowledges: neither delegation may be settled.
	receipt := protocol.TowerReceiptMsg{V: 1, ChannelID: "1", Seq: "1", OK: true}
	if err := alice.handleRumor(context.Background(), encodeRumor(t, protocol.KindTowerReceipt, receipt), tower1); err != nil {
		t.Fatal(err)
	}
	if n, _ := alice.Store.OutboundLen(); n != 2 {
		t.Fatalf("registry-less receipt settled delegations across coexisting registries: %d left", n)
	}

	// The qualified form settles only its registry's copy.
	receipt.Registry = strings.ToLower(e2eKey.Registry.Hex())
	receipt.ChainID = e2eKey.ChainID
	if err := alice.handleRumor(context.Background(), encodeRumor(t, protocol.KindTowerReceipt, receipt), tower1); err != nil {
		t.Fatal(err)
	}
	items, err := alice.Store.OutboundAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !strings.Contains(items[0].DedupeKey, decoyKey.Registry.Hex()) {
		t.Fatalf("qualified receipt did not settle exactly its registry's delegation: %+v", items)
	}
}

// TestWatchersShareTxManagerPerChain: everything submitting with the node's
// key on one chain must share a single transaction manager, or nonce
// allocations race and one transaction silently replaces another.
func TestWatchersShareTxManagerPerChain(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	backend := backends.NewSimulatedBackend(validation.GenesisAlloc{}, 30_000_000)
	defer backend.Close()

	cfg := DefaultConfig()
	cfg.Registries = map[string][]RegistryEntry{
		"v1": {{Address: "0x0000000000000000000000000000000000001111", ChainID: 1337}},
		"v2": {{Address: "0x0000000000000000000000000000000000002222", ChainID: 1337}},
	}
	cfg.Nostr.Relays = []string{"wss://hub"}
	n, err := New(cfg, t.TempDir(), key, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	if len(n.Watchers) != 2 {
		t.Fatalf("watchers: %d", len(n.Watchers))
	}
	mgr := n.TxManagerFor("1337")
	if mgr == nil {
		t.Fatal("no shared manager for chain 1337")
	}
	for _, w := range n.Watchers {
		if w.TxManager() != mgr {
			t.Fatal("watcher runs its own transaction manager")
		}
	}
}

// TestTowerCatchUpWithoutBackup: reconnect catch-up must delegate
// QR/offline-completed states to configured towers even when relay
// self-backup is disabled — delegation is loss protection, not backup.
func TestTowerCatchUpWithoutBackup(t *testing.T) {
	tower1 := strings.Repeat("01", 32)
	h := newHub()
	alice := newTestNodeWith(t, h, func(cfg *Config) {
		cfg.Backup.Enabled = false
		cfg.Channels.Towers.Npubs = []string{tower1}
	})
	bob := newTestNode(t, h, nil)
	linkChannel(t, alice, bob)

	// A state completed offline (QR countersign) before this session.
	if err := alice.Store.PutComplete(dualSignedFake(1)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go alice.Run(ctx, time.Hour)

	waitUntil(t, 5*time.Second, "delegation queued on reconnect", func() bool {
		items, _ := alice.Store.OutboundAll()
		for _, item := range items {
			if item.Kind == protocol.KindTowerDelegation && item.ToNpub == tower1 {
				return true
			}
		}
		return false
	})
}
