package towerd_test

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind/backends"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/towerd"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/watcher"
)

// lossyBackend accepts but loses every SendTransaction while drop is set
// (node restart without journal, eviction).
type lossyBackend struct {
	watcher.TxBackend
	mu   sync.Mutex
	drop bool
	lost int
}

func (b *lossyBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.drop {
		b.lost++
		return nil
	}
	return b.TxBackend.SendTransaction(ctx, tx)
}

func (b *lossyBackend) setDrop(drop bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.drop = drop
}

// reevalEnv is channel 1 (alice: 10 LAX, 36-block window) watched by a
// tower whose store survives restarts.
type reevalEnv struct {
	backend   *backends.SimulatedBackend
	lossy     *lossyBackend
	contract  *registry.ChannelRegistry
	regAddr   util.Address
	alicePriv *ecdsa.PrivateKey
	bobPriv   *ecdsa.PrivateKey
	towerPriv *ecdsa.PrivateKey
	auth      *bind.TransactOpts
	store     *proofstore.Store
	key       proofstore.ChannelKey
	cfg       towerd.Config
}

func newReevalEnv(t *testing.T) *reevalEnv {
	t.Helper()
	e := &reevalEnv{}
	e.alicePriv, _ = crypto.GenerateKey()
	e.bobPriv, _ = crypto.GenerateKey()
	e.towerPriv, _ = crypto.GenerateKey()
	e.backend = backends.NewSimulatedBackend(validation.GenesisAlloc{
		crypto.PubkeyToAddress(e.alicePriv.PublicKey): {Balance: lax(100)},
		crypto.PubkeyToAddress(e.bobPriv.PublicKey):   {Balance: lax(100)},
		crypto.PubkeyToAddress(e.towerPriv.PublicKey): {Balance: lax(10)},
	}, 30_000_000)
	t.Cleanup(func() { e.backend.Close() })
	e.lossy = &lossyBackend{TxBackend: e.backend}
	var err error
	if e.auth, err = bind.NewKeyedTransactorWithChainID(e.alicePriv, big.NewInt(1337)); err != nil {
		t.Fatal(err)
	}
	if e.regAddr, _, e.contract, err = registry.DeployChannelRegistry(e.auth, e.backend, big.NewInt(1e16)); err != nil {
		t.Fatal(err)
	}
	e.auth.Value = lax(10)
	if _, err := e.contract.Open(e.auth, crypto.PubkeyToAddress(e.bobPriv.PublicKey), 36); err != nil {
		t.Fatal(err)
	}
	e.auth.Value = nil
	e.backend.Commit()
	if e.store, err = proofstore.Open(filepath.Join(t.TempDir(), "tower.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.store.Close() })
	e.key = proofstore.ChannelKey{ChainID: "1337", Registry: e.regAddr, ChannelID: 1}
	e.cfg = towerd.Config{ChainID: "1337", Registry: e.regAddr, Confirmations: 3,
		Delegators: map[string]bool{"bob-npub": true}}
	return e
}

// newTower models a (re)started tower process: a fresh in-memory
// transaction manager over the same persistent store.
func (e *reevalEnv) newTower(t *testing.T) *towerd.Tower {
	t.Helper()
	tw, err := towerd.New(e.cfg, e.store, e.lossy, watcher.NewTxManager(e.lossy, e.towerPriv, big.NewInt(1337)))
	if err != nil {
		t.Fatal(err)
	}
	tw.Alarm = func(format string, args ...any) { t.Logf("alarm: "+format, args...) }
	return tw
}

func (e *reevalEnv) delegate(t *testing.T, tw *towerd.Tower, seq uint64, tAB *big.Int) {
	t.Helper()
	st := dualSignedState(t, e.key, seq, tAB, e.alicePriv, e.bobPriv)
	if _, err := tw.HandleDelegation(context.Background(), protocol.TowerDelegationMsg{
		V: 1, Registry: strings.ToLower(e.regAddr.Hex()), ChainID: "1337", ChannelID: "1",
		State: protocol.ToWire(st),
	}, "bob-npub"); err != nil {
		t.Fatal(err)
	}
}

// staleClose has alice force-close at seq 2 (1 LAX transferred), confirms
// it, and returns the challenge deadline.
func (e *reevalEnv) staleClose(t *testing.T) uint64 {
	t.Helper()
	stale := dualSignedState(t, e.key, 2, lax(1), e.alicePriv, e.bobPriv)
	if _, err := e.contract.StartClose(e.auth, big.NewInt(1), stale.ContractProof(), stale.SigA, stale.SigB); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e.backend.Commit()
	}
	on, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	return on.CloseInitiatedAtBlock.Uint64() + uint64(on.ChallengePeriodBlocks)
}

// tickUntil drives the tower block by block to the deadline and returns the
// on-chain closing seq there.
func (e *reevalEnv) tickUntil(t *testing.T, tw *towerd.Tower, deadline uint64) uint64 {
	t.Helper()
	for e.backend.Blockchain().CurrentBlock().Number().Uint64() < deadline {
		if _, err := tw.Tick(context.Background()); err != nil {
			t.Logf("tick: %v", err)
		}
		e.backend.Commit()
	}
	on, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	return on.ClosingSeq
}

// TestTowerChallengesDelegationArrivingAfterScan: a delegation landing
// after the tower's scan has passed the CloseStarted (relay backlog, tower
// downtime, the victim's queue retransmitting) must still be challenged
// inside the window. react() used to run only for events in the scan
// range, and the watermark had already moved on.
func TestTowerChallengesDelegationArrivingAfterScan(t *testing.T) {
	e := newReevalEnv(t)
	tw := e.newTower(t)
	deadline := e.staleClose(t)
	if _, err := tw.Tick(context.Background()); err != nil { // scans the close, nothing held
		t.Fatal(err)
	}
	e.delegate(t, tw, 5, lax(3))
	if seq := e.tickUntil(t, tw, deadline); seq != 5 {
		t.Fatalf("on-chain seq %d at the deadline, want 5: late delegation never challenged", seq)
	}
}

// TestTowerReevaluatesAfterDustSkip: a dust skip is a judgement on the
// delegation held at the time, not on the close. A larger delegation
// arriving inside the window must be challenged.
func TestTowerReevaluatesAfterDustSkip(t *testing.T) {
	e := newReevalEnv(t)
	e.cfg.MinDiscrepancyWei = lax(1)
	tw := e.newTower(t)
	// Seq 3 moves 1.5 LAX: 0.5 LAX over the stale close, below the floor.
	e.delegate(t, tw, 3, new(big.Int).Div(lax(3), big.NewInt(2)))
	deadline := e.staleClose(t)
	if _, err := tw.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	on, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if on.ClosingSeq != 2 {
		t.Fatalf("dust close challenged: on-chain seq %d", on.ClosingSeq)
	}
	e.delegate(t, tw, 9, lax(8)) // 7 LAX discrepancy
	if seq := e.tickUntil(t, tw, deadline); seq != 9 {
		t.Fatalf("on-chain seq %d at the deadline, want 9: the earlier dust skip was final", seq)
	}
}

// TestTowerRestartResubmitsLostChallenge: challenge intents live only in
// the transaction manager's memory while the watermark is persisted past
// the close. A tower restarted after its challenge broadcast was lost must
// re-derive the challenge from the chain and its delegation store.
func TestTowerRestartResubmitsLostChallenge(t *testing.T) {
	e := newReevalEnv(t)
	tw := e.newTower(t)
	e.delegate(t, tw, 5, lax(3))
	deadline := e.staleClose(t)
	e.lossy.setDrop(true)
	if _, err := tw.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.lossy.setDrop(false)
	if e.lossy.lost == 0 {
		t.Fatal("tower never submitted the challenge")
	}
	mark, err := e.store.TowerWatermark("1337", e.regAddr.Hex())
	if err != nil {
		t.Fatal(err)
	}
	on, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if mark < on.CloseInitiatedAtBlock.Uint64() {
		t.Fatalf("watermark %d still below the close at %d: restart would rescan it anyway", mark, on.CloseInitiatedAtBlock)
	}

	tw = e.newTower(t) // the tower process restarts
	if seq := e.tickUntil(t, tw, deadline); seq != 5 {
		t.Fatalf("on-chain seq %d at the deadline, want 5: restarted tower never retried the challenge", seq)
	}
}
