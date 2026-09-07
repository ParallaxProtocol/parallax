package towerd_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	parallax "github.com/ParallaxProtocol/parallax/v2"
	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind/backends"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/channeld"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/chantest"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/nostrmod"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/towerd"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/watcher"
)

func lax(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }

func newNode(t *testing.T, h *chantest.Hub, key *ecdsa.PrivateKey, backend channeld.Backend, regAddr util.Address, towerNpubs []string) *channeld.Node {
	t.Helper()
	cfg := channeld.DefaultConfig()
	cfg.Registries = map[string][]channeld.RegistryEntry{"v1": {{Address: regAddr.Hex(), ChainID: 1337}}}
	cfg.Nostr.Relays = []string{"wss://hub"}
	cfg.Merchant.PushPayments = true
	cfg.Backup.Enabled = false
	cfg.Channels.Towers.Npubs = towerNpubs

	node, err := channeld.New(cfg, t.TempDir(), key, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	node.Pool = nostrmod.NewPool(h.Dialer(), []string{"wss://hub"}, node.SelfPub, nostrmod.PoolConfig{})
	node.Transmitter = nostrmod.NewTransmitter(node.Store, node.Pool, node.NostrPriv)
	node.TransmitInterval = 5 * time.Millisecond
	return node
}

func waitUntil(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestTowerChallengesScriptedCheater is the Phase D exit gate: the victim
// pays, delegates to the tower over the relay, then goes OFFLINE; the
// cheater force-closes with a stale state; the unattended tower challenges
// promptly and, after settle, the penalty burns and the tower collects the
// on-chain refund.
func TestTowerChallengesScriptedCheater(t *testing.T) {
	alicePriv, _ := crypto.GenerateKey() // cheater, participant A
	bobPriv, _ := crypto.GenerateKey()   // victim, participant B
	towerPriv, _ := crypto.GenerateKey() // tower operator
	alice := crypto.PubkeyToAddress(alicePriv.PublicKey)
	bob := crypto.PubkeyToAddress(bobPriv.PublicKey)
	towerAddr := crypto.PubkeyToAddress(towerPriv.PublicKey)

	backend := backends.NewSimulatedBackend(validation.GenesisAlloc{
		alice:     {Balance: lax(100)},
		bob:       {Balance: lax(100)},
		towerAddr: {Balance: lax(10)}, // challenge gas
	}, 30_000_000)
	defer backend.Close()
	auth, err := bind.NewKeyedTransactorWithChainID(alicePriv, big.NewInt(1337))
	if err != nil {
		t.Fatal(err)
	}
	regAddr, _, contract, err := registry.DeployChannelRegistry(auth, backend, big.NewInt(1e16))
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // auto-miner
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				backend.Commit()
			case <-ctx.Done():
				return
			}
		}
	}()

	h := chantest.NewHub()
	towerNode := newNode(t, h, towerPriv, backend, regAddr, nil)
	nodeA := newNode(t, h, alicePriv, backend, regAddr, nil)
	nodeB := newNode(t, h, bobPriv, backend, regAddr, []string{towerNode.SelfPub})

	// Production wiring: the tower shares the channel node's per-chain
	// transaction manager (same key, one nonce allocator).
	tower, err := towerd.New(towerd.Config{
		ChainID:       "1337",
		Registry:      regAddr,
		Confirmations: 3,
		Delegators:    map[string]bool{nodeB.SelfPub: true},
	}, towerNode.Store, backend, towerNode.TxManagerFor("1337"))
	if err != nil {
		t.Fatal(err)
	}
	var alarms []string
	tower.Alarm = func(format string, args ...any) { alarms = append(alarms, format) }
	towerNode.DelegationHandler = tower.HandleDelegation

	bobCtx, bobCancel := context.WithCancel(ctx)
	aliceCtx, aliceCancel := context.WithCancel(ctx)
	go nodeA.Run(aliceCtx, 50*time.Millisecond)
	go nodeB.Run(bobCtx, 50*time.Millisecond)
	go towerNode.Run(ctx, time.Hour)
	go func() { // unattended tower loop
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := tower.Tick(ctx); err != nil {
					t.Log("tower tick:", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	waitUntil(t, 3*time.Second, "relays connected", func() bool {
		return nodeA.Pool.Healthy() == 1 && nodeB.Pool.Healthy() == 1 && towerNode.Pool.Healthy() == 1
	})

	// Open, fund, pay: alice pays bob 3 LAX at seq 1.
	key, err := nodeA.OpenChannel(ctx, 1337, regAddr, bob, nodeB.SelfPub, lax(10), 40)
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "handshake + deposits", func() bool {
		da, _ := nodeA.Store.Deposits(key)
		db, _ := nodeB.Store.Deposits(key)
		return da.DepositA.BigInt().Cmp(lax(10)) == 0 && db.DepositA.BigInt().Cmp(lax(10)) == 0
	})
	if err := nodeA.Pay(ctx, key, lax(3), ""); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, "payment completion", func() bool {
		lb, err := nodeB.Store.LatestState(key)
		return err == nil && lb.Seq == 1
	})

	// Bob's node delegates automatically; the tower verifies against the
	// chain, stores it, and its receipt drains bob's queue.
	waitUntil(t, 10*time.Second, "delegation held by tower", func() bool {
		d, err := towerNode.Store.Delegation(key)
		return err == nil && d.State.Seq == 1
	})
	waitUntil(t, 10*time.Second, "delegation receipt drained bob's queue", func() bool {
		n, _ := nodeB.Store.OutboundLen()
		return n == 0
	})

	// THE VICTIM GOES OFFLINE — and the cheater's node too (her own watcher
	// would otherwise self-challenge; the point here is the unattended
	// tower being the only defender).
	bobCancel()
	aliceCancel()
	time.Sleep(100 * time.Millisecond)

	// The cheater force-closes with no proof, claiming her full 10 LAX back.
	tx, err := contract.StartCloseNoProof(auth, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bind.WaitMined(ctx, backend, tx); err != nil {
		t.Fatal(err)
	}

	// The unattended tower detects and challenges with the delegated seq 1.
	waitUntil(t, 15*time.Second, "tower challenge effective", func() bool {
		onchain, err := contract.GetChannel(nil, big.NewInt(1))
		return err == nil && onchain.ClosingSeq == 1 && onchain.LastChallenger == towerAddr
	})

	// Roll past the 40-block deadline and settle (anyone may; the cheater's
	// own key does it here).
	waitUntil(t, 30*time.Second, "deadline passed", func() bool {
		onchain, err := contract.GetChannel(nil, big.NewInt(1))
		if err != nil {
			return false
		}
		head, _ := backend.HeaderByNumber(ctx, nil)
		return head.Number.Uint64() > onchain.CloseInitiatedAtBlock.Uint64()+uint64(onchain.ChallengePeriodBlocks)
	})
	bobBefore, _ := backend.BalanceAt(ctx, bob, nil)
	towerBefore, _ := backend.BalanceAt(ctx, towerAddr, nil)
	tx, err = contract.Settle(auth, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bind.WaitMined(ctx, backend, tx); err != nil {
		t.Fatal(err)
	}

	// Outcome: bob made whole (3 LAX), tower earned exactly the refund,
	// cheater paid the 20% penalty on her 3 LAX over-claim (claimed 10,
	// truth 7 -> D=3, P=0.6).
	bobAfter, _ := backend.BalanceAt(ctx, bob, nil)
	towerAfter, _ := backend.BalanceAt(ctx, towerAddr, nil)
	if got := new(big.Int).Sub(bobAfter, bobBefore); got.Cmp(lax(3)) != 0 {
		t.Fatalf("victim payout: %s", got)
	}
	refund := big.NewInt(1e16)
	towerDelta := new(big.Int).Sub(towerAfter, towerBefore)
	if towerDelta.Cmp(refund) != 0 {
		t.Fatalf("tower refund: %s want %s", towerDelta, refund)
	}
	if len(alarms) == 0 {
		t.Fatal("tower never alarmed about the stale close")
	}
}

// flakyCallBackend injects failures into contract view calls (GetChannel),
// simulating a transiently failing RPC during react().
type flakyCallBackend struct {
	watcher.TxBackend
	fail atomic.Bool
}

func (b *flakyCallBackend) CallContract(ctx context.Context, msg parallax.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if b.fail.Load() {
		return nil, errors.New("injected rpc failure")
	}
	return b.TxBackend.CallContract(ctx, msg, blockNumber)
}

func dualSignedState(t *testing.T, key proofstore.ChannelKey, seq uint64, tAB *big.Int, alicePriv, bobPriv *ecdsa.PrivateKey) proofstore.SignedState {
	t.Helper()
	st := proofstore.SignedState{
		Key:             key,
		Seq:             seq,
		TransferredAtoB: proofstore.NewU256(tAB),
		TransferredBtoA: proofstore.NewU256(nil),
		LockedAmount:    proofstore.NewU256(nil),
	}
	digest, err := st.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if st.SigA, err = protocol.NewKeySigner(alicePriv).SignDigest(digest); err != nil {
		t.Fatal(err)
	}
	if st.SigB, err = protocol.NewKeySigner(bobPriv).SignDigest(digest); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestTickRescansFailedReactRange: a CloseStarted event whose react() failed
// transiently (RPC error) must be scanned again on the next tick — advancing
// the watermark past it would silently drop the challenge and let the stale
// close settle.
func TestTickRescansFailedReactRange(t *testing.T) {
	alicePriv, _ := crypto.GenerateKey() // cheater
	bobPriv, _ := crypto.GenerateKey()   // delegator (victim)
	towerPriv, _ := crypto.GenerateKey()
	alice := crypto.PubkeyToAddress(alicePriv.PublicKey)
	bob := crypto.PubkeyToAddress(bobPriv.PublicKey)
	towerAddr := crypto.PubkeyToAddress(towerPriv.PublicKey)

	backend := backends.NewSimulatedBackend(validation.GenesisAlloc{
		alice: {Balance: lax(100)}, bob: {Balance: lax(100)}, towerAddr: {Balance: lax(10)},
	}, 30_000_000)
	defer backend.Close()
	auth, err := bind.NewKeyedTransactorWithChainID(alicePriv, big.NewInt(1337))
	if err != nil {
		t.Fatal(err)
	}
	regAddr, _, contract, err := registry.DeployChannelRegistry(auth, backend, big.NewInt(1e16))
	if err != nil {
		t.Fatal(err)
	}
	auth.Value = lax(10)
	if _, err := contract.Open(auth, bob, 36); err != nil {
		t.Fatal(err)
	}
	auth.Value = nil
	backend.Commit()

	flaky := &flakyCallBackend{TxBackend: backend}
	store, err := proofstore.Open(filepath.Join(t.TempDir(), "tower.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tower, err := towerd.New(towerd.Config{
		ChainID:       "1337",
		Registry:      regAddr,
		Confirmations: 3,
		Delegators:    map[string]bool{"bob-npub": true},
	}, store, flaky, watcher.NewTxManager(flaky, towerPriv, big.NewInt(1337)))
	if err != nil {
		t.Fatal(err)
	}
	tower.Alarm = func(format string, args ...any) { t.Logf("alarm: "+format, args...) }

	key := proofstore.ChannelKey{ChainID: "1337", Registry: regAddr, ChannelID: 1}
	latest := dualSignedState(t, key, 5, lax(3), alicePriv, bobPriv)
	if _, err := tower.HandleDelegation(context.Background(), protocol.TowerDelegationMsg{
		V:         1,
		Registry:  strings.ToLower(regAddr.Hex()),
		ChainID:   "1337",
		ChannelID: "1",
		State:     protocol.ToWire(latest),
	}, "bob-npub"); err != nil {
		t.Fatal(err)
	}

	// Alice force-closes at stale seq 2.
	stale := dualSignedState(t, key, 2, lax(1), alicePriv, bobPriv)
	if _, err := contract.StartClose(auth, big.NewInt(1), stale.ContractProof(), stale.SigA, stale.SigB); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		backend.Commit()
	}

	// Tick 1: the RPC fails while reacting to the confirmed CloseStarted.
	flaky.fail.Store(true)
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Logf("tick during outage: %v", err)
	}
	flaky.fail.Store(false)

	// Tick 2: the RPC is back; the event must be re-scanned and challenged.
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.Commit() // mine the challenge

	onchain, err := contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.ClosingSeq != 5 || onchain.LastChallenger != towerAddr {
		t.Fatalf("failed react range never re-scanned: on-chain seq %d challenger %s",
			onchain.ClosingSeq, onchain.LastChallenger.Hex())
	}
}

// TestTowerAlarmReceivesSharedManagerAlerts: in tower mode the tower shares
// the channel node's per-chain manager, whose Alarm the node's watcher has
// already claimed. The tower's operator-facing alarm stream (TOWER ALARM on
// stderr) must still receive manager alerts — a tower challenge stalling
// unmined near its deadline is the one loss-capable alert the tower exists
// to raise.
func TestTowerAlarmReceivesSharedManagerAlerts(t *testing.T) {
	towerPriv, _ := crypto.GenerateKey()
	backend := backends.NewSimulatedBackend(validation.GenesisAlloc{}, 30_000_000)
	defer backend.Close()
	regAddr := util.HexToAddress("0x00000000000000000000000000000000000021ff")

	store, err := proofstore.Open(filepath.Join(t.TempDir(), "tower.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Production order (channeld.New): the watcher wires itself to the
	// shared manager first, then the tower daemon attaches.
	mgr := watcher.NewTxManager(backend, towerPriv, big.NewInt(1337))
	w, err := watcher.New(watcher.Config{ChainID: "1337", Registry: regAddr}, store, backend, mgr)
	if err != nil {
		t.Fatal(err)
	}
	_ = w
	tower, err := towerd.New(towerd.Config{ChainID: "1337", Registry: regAddr}, store, backend, mgr)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	tower.Alarm = func(format string, args ...any) { got = append(got, format) }

	mgr.Alarm("transaction %s still unmined with %d blocks to deadline", "towerchallenge:x", 3)
	if len(got) == 0 {
		t.Fatal("manager alarm never reached the tower's alarm stream")
	}
}

// TestTowerRejectsBadDelegations covers the intake gate.
func TestTowerRejectsBadDelegations(t *testing.T) {
	alicePriv, _ := crypto.GenerateKey()
	bobPriv, _ := crypto.GenerateKey()
	towerPriv, _ := crypto.GenerateKey()
	alice := crypto.PubkeyToAddress(alicePriv.PublicKey)
	bob := crypto.PubkeyToAddress(bobPriv.PublicKey)

	backend := backends.NewSimulatedBackend(validation.GenesisAlloc{
		alice: {Balance: lax(100)}, bob: {Balance: lax(100)},
	}, 30_000_000)
	defer backend.Close()
	auth, _ := bind.NewKeyedTransactorWithChainID(alicePriv, big.NewInt(1337))
	regAddr, _, contract, err := registry.DeployChannelRegistry(auth, backend, big.NewInt(1e16))
	if err != nil {
		t.Fatal(err)
	}
	auth.Value = lax(5)
	if _, err := contract.Open(auth, bob, 40); err != nil {
		t.Fatal(err)
	}
	auth.Value = nil
	backend.Commit()

	h := chantest.NewHub()
	nodeA := newNode(t, h, alicePriv, backend, regAddr, nil)
	nodeB := newNode(t, h, bobPriv, backend, regAddr, nil)
	towerStore := newNode(t, h, towerPriv, backend, regAddr, nil).Store

	tower, err := towerd.New(towerd.Config{
		ChainID:       "1337",
		Registry:      regAddr,
		Confirmations: 3,
		Delegators:    map[string]bool{nodeB.SelfPub: true},
	}, towerStore, backend, watcher.NewTxManager(backend, towerPriv, big.NewInt(1337)))
	if err != nil {
		t.Fatal(err)
	}

	_ = nodeA

	// Unknown sender is refused outright.
	if _, err := tower.HandleDelegation(context.Background(), protocolDelegation(regAddr, 1), "mallory"); err == nil {
		t.Fatal("unknown delegator accepted")
	}
	// Known sender, but garbage signatures: refused against the chain.
	if _, err := tower.HandleDelegation(context.Background(), protocolDelegation(regAddr, 1), nodeB.SelfPub); err == nil {
		t.Fatal("garbage signatures accepted")
	}
	// Nonexistent channel: refused.
	if _, err := tower.HandleDelegation(context.Background(), protocolDelegation(regAddr, 99), nodeB.SelfPub); err == nil {
		t.Fatal("nonexistent channel accepted")
	}
}

// protocolDelegation builds a syntactically valid 21906 with garbage
// signatures for the given channel.
func protocolDelegation(regAddr util.Address, channelID uint64) protocol.TowerDelegationMsg {
	fake := "0x" + strings.Repeat("11", 64) + "1b" // 65 bytes, v=27
	return protocol.TowerDelegationMsg{
		V:         1,
		Registry:  strings.ToLower(regAddr.Hex()),
		ChainID:   "1337",
		ChannelID: strconv.FormatUint(channelID, 10),
		State: protocol.WireState{
			ChannelID:       strconv.FormatUint(channelID, 10),
			Registry:        strings.ToLower(regAddr.Hex()),
			ChainID:         "1337",
			Seq:             "1",
			TransferredAtoB: "5",
			TransferredBtoA: "0",
			LocksRoot:       util.Hash{}.Hex(),
			LockedAmount:    "0",
			SigA:            fake,
			SigB:            fake,
		},
	}
}
