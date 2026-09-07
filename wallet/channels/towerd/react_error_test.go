package towerd_test

import (
	"context"
	"encoding/json"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind/backends"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/towerd"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/watcher"
)

// TestReactErrorKeepsWatermark: react() must distinguish "nobody delegated
// this channel" (ErrNotFound — not our watch) from a failing delegation READ
// (I/O error, corrupt record). Treating every store error as not-delegated
// let the watermark advance past a CloseStarted the tower never evaluated,
// silently dropping the challenge the delegator paid for — the exact loss
// the tower exists to prevent.
func TestReactErrorKeepsWatermark(t *testing.T) {
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

	dbPath := filepath.Join(t.TempDir(), "tower.db")
	store, err := proofstore.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := towerd.Config{
		ChainID:       "1337",
		Registry:      regAddr,
		Confirmations: 3,
		Delegators:    map[string]bool{"bob-npub": true},
	}
	newTower := func(store *proofstore.Store) *towerd.Tower {
		tower, err := towerd.New(cfg, store, backend, watcher.NewTxManager(backend, towerPriv, big.NewInt(1337)))
		if err != nil {
			t.Fatal(err)
		}
		tower.Alarm = func(format string, args ...any) { t.Logf("alarm: "+format, args...) }
		return tower
	}

	key := proofstore.ChannelKey{ChainID: "1337", Registry: regAddr, ChannelID: 1}
	latest := dualSignedState(t, key, 5, lax(3), alicePriv, bobPriv)
	if _, err := newTower(store).HandleDelegation(context.Background(), protocol.TowerDelegationMsg{
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

	// overwrite rewrites the delegation record on disk, bypassing the store
	// (which refuses to write anything invalid).
	overwrite := func(raw []byte) *proofstore.Store {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := bolt.Open(dbPath, 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("towerdb")).Put([]byte(key.String()), raw)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = proofstore.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}

	// Tick 1: the delegation record fails to read (corrupt bytes).
	tower := newTower(overwrite([]byte("{corrupt")))
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Logf("tick over corrupt record: %v", err)
	}

	// Tick 2: the record is intact again (restored from a replica, say);
	// the CloseStarted must be re-scanned and challenged.
	good, err := json.Marshal(proofstore.Delegation{State: latest, DelegatorNpub: "bob-npub"})
	if err != nil {
		t.Fatal(err)
	}
	tower = newTower(overwrite(good))
	defer store.Close()
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.Commit() // mine the challenge

	onchain, err := contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.ClosingSeq != 5 || onchain.LastChallenger != towerAddr {
		t.Fatalf("failed delegation read advanced the watermark past the close: on-chain seq %d challenger %s",
			onchain.ClosingSeq, onchain.LastChallenger.Hex())
	}
}
