package towerd_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
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

const corruptChallengePeriod = 36

// corruptEnv is a tower holding one delegation for a channel that its
// counterparty then force-closes at a stale seq, with the delegation record
// overwritten by undecodable bytes on disk.
type corruptEnv struct {
	backend   *backends.SimulatedBackend
	contract  *registry.ChannelRegistry
	regAddr   util.Address
	towerAddr util.Address
	towerPriv *ecdsa.PrivateKey
	store     *proofstore.Store
	key       proofstore.ChannelKey
	latest    proofstore.SignedState
	closeBlk  uint64
	alarms    *[]string
	newTower  func() *towerd.Tower
	delegate  func(*towerd.Tower)
	watermark func() uint64
}

func newCorruptEnv(t *testing.T) *corruptEnv { return buildCorruptEnv(t, false) }

// earlyCloseChannel is the optional second channel: long challenge period,
// force-closed before channel 1, its delegation also corrupted on disk, so
// its quarantine pins the watermark below channel 1's close for long after
// channel 1's own deadline.
const (
	earlyCloseChannel = 2
	earlyClosePeriod  = 1000
)

func buildCorruptEnv(t *testing.T, earlyClose bool) *corruptEnv {
	t.Helper()
	alicePriv, _ := crypto.GenerateKey() // cheater
	bobPriv, _ := crypto.GenerateKey()   // delegator (victim)
	towerPriv, _ := crypto.GenerateKey()
	alice := crypto.PubkeyToAddress(alicePriv.PublicKey)
	bob := crypto.PubkeyToAddress(bobPriv.PublicKey)
	towerAddr := crypto.PubkeyToAddress(towerPriv.PublicKey)

	backend := backends.NewSimulatedBackend(validation.GenesisAlloc{
		alice: {Balance: lax(100)}, bob: {Balance: lax(100)}, towerAddr: {Balance: lax(10)},
	}, 30_000_000)
	t.Cleanup(func() { backend.Close() })
	auth, err := bind.NewKeyedTransactorWithChainID(alicePriv, big.NewInt(1337))
	if err != nil {
		t.Fatal(err)
	}
	regAddr, _, contract, err := registry.DeployChannelRegistry(auth, backend, big.NewInt(1e16))
	if err != nil {
		t.Fatal(err)
	}
	auth.Value = lax(10)
	if _, err := contract.Open(auth, bob, corruptChallengePeriod); err != nil {
		t.Fatal(err)
	}
	if earlyClose {
		if _, err := contract.Open(auth, bob, earlyClosePeriod); err != nil {
			t.Fatal(err)
		}
	}
	auth.Value = nil
	backend.Commit()

	dbPath := filepath.Join(t.TempDir(), "tower.db")
	store, err := proofstore.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := towerd.Config{
		ChainID:       "1337",
		Registry:      regAddr,
		Confirmations: 3,
		Delegators:    map[string]bool{"bob-npub": true},
	}
	alarms := &[]string{}
	env := &corruptEnv{backend: backend, contract: contract, regAddr: regAddr, towerAddr: towerAddr, towerPriv: towerPriv, store: store, alarms: alarms}
	env.newTower = func() *towerd.Tower {
		tower, err := towerd.New(cfg, store, backend, watcher.NewTxManager(backend, towerPriv, big.NewInt(1337)))
		if err != nil {
			t.Fatal(err)
		}
		tower.Alarm = func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			t.Logf("alarm: %s", msg)
			*alarms = append(*alarms, msg)
		}
		return tower
	}
	env.watermark = func() uint64 {
		mark, err := store.TowerWatermark("1337", regAddr.Hex())
		if err != nil {
			t.Fatal(err)
		}
		return mark
	}

	env.key = proofstore.ChannelKey{ChainID: "1337", Registry: regAddr, ChannelID: 1}
	env.latest = dualSignedState(t, env.key, 5, lax(3), alicePriv, bobPriv)
	env.delegate = func(tower *towerd.Tower) {
		if _, err := tower.HandleDelegation(context.Background(), protocol.TowerDelegationMsg{
			V:         1,
			Registry:  strings.ToLower(regAddr.Hex()),
			ChainID:   "1337",
			ChannelID: "1",
			State:     protocol.ToWire(env.latest),
		}, "bob-npub"); err != nil {
			t.Fatal(err)
		}
	}
	env.delegate(env.newTower())

	key2 := proofstore.ChannelKey{ChainID: "1337", Registry: regAddr, ChannelID: earlyCloseChannel}
	if earlyClose {
		latest2 := dualSignedState(t, key2, 5, lax(3), alicePriv, bobPriv)
		if _, err := env.newTower().HandleDelegation(context.Background(), protocol.TowerDelegationMsg{
			V:         1,
			Registry:  strings.ToLower(regAddr.Hex()),
			ChainID:   "1337",
			ChannelID: fmt.Sprint(earlyCloseChannel),
			State:     protocol.ToWire(latest2),
		}, "bob-npub"); err != nil {
			t.Fatal(err)
		}
		stale2 := dualSignedState(t, key2, 2, lax(1), alicePriv, bobPriv)
		if _, err := contract.StartClose(auth, big.NewInt(earlyCloseChannel), stale2.ContractProof(), stale2.SigA, stale2.SigB); err != nil {
			t.Fatal(err)
		}
		backend.Commit()
	}

	// Alice force-closes at stale seq 2.
	stale := dualSignedState(t, env.key, 2, lax(1), alicePriv, bobPriv)
	if _, err := contract.StartClose(auth, big.NewInt(1), stale.ContractProof(), stale.SigA, stale.SigB); err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	env.closeBlk = backend.Blockchain().CurrentBlock().Number().Uint64()
	backend.Commit()
	backend.Commit() // CloseStarted confirmed

	// Overwrite the delegation record on disk, bypassing the store (which
	// refuses to write anything invalid).
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(dbPath, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if earlyClose {
			if err := tx.Bucket([]byte("towerdb")).Put([]byte(key2.String()), []byte("{corrupt")); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte("towerdb")).Put([]byte(env.key.String()), []byte("{corrupt"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if env.store, err = proofstore.Open(dbPath); err != nil {
		t.Fatal(err)
	}
	store = env.store
	return env
}

func (e *corruptEnv) alarmed(substr string) bool {
	for _, a := range *e.alarms {
		if strings.Contains(a, substr) {
			return true
		}
	}
	return false
}

// TestReactErrorKeepsWatermark: react() must distinguish "nobody delegated
// this channel" (ErrNotFound — not our watch) from a delegation record
// that no longer decodes. Treating every store error as not-delegated let
// the watermark advance past a CloseStarted the tower never evaluated,
// silently dropping the challenge the delegator paid for — the exact loss
// the tower exists to prevent. The bad record goes to quarantine (so the
// delegator's re-send can land) and the close stays pinned until then.
func TestReactErrorKeepsWatermark(t *testing.T) {
	e := newCorruptEnv(t)

	// Tick 1: the delegation record fails to decode.
	tower := e.newTower()
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatalf("tick over corrupt record: %v", err)
	}
	if mark := e.watermark(); mark != e.closeBlk-1 {
		t.Fatalf("watermark %d after corrupt read, want pinned at %d", mark, e.closeBlk-1)
	}
	q, err := e.store.QuarantinedDelegation(e.key)
	if err != nil || string(q.Raw) != "{corrupt" {
		t.Fatalf("record not quarantined: %+v %v", q, err)
	}
	if !e.alarmed("quarantined undecodable delegation") {
		t.Fatalf("no quarantine alarm: %q", *e.alarms)
	}
	// The CLI cannot open the store while the tower runs, so the alarm
	// itself carries the bytes.
	if !e.alarmed(base64.StdEncoding.EncodeToString([]byte("{corrupt"))) {
		t.Fatalf("quarantine alarm lacks the raw record: %q", *e.alarms)
	}

	// Tick 2: still nothing to evaluate with; the pin holds without
	// re-alarming.
	before := len(*e.alarms)
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mark := e.watermark(); mark != e.closeBlk-1 {
		t.Fatalf("watermark %d on the quarantined tick, want %d", mark, e.closeBlk-1)
	}
	if len(*e.alarms) != before {
		t.Fatalf("quarantined close re-alarmed every tick: %q", (*e.alarms)[before:])
	}

	// The delegator re-sends its state; the CloseStarted must be
	// re-scanned and challenged.
	e.delegate(tower)
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.backend.Commit() // mine the challenge

	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.ClosingSeq != 5 || onchain.LastChallenger != e.towerAddr {
		t.Fatalf("failed delegation read advanced the watermark past the close: on-chain seq %d challenger %s",
			onchain.ClosingSeq, onchain.LastChallenger.Hex())
	}
	if mark := e.watermark(); mark < e.closeBlk {
		t.Fatalf("watermark %d not released after the challenge", mark)
	}
}

// TestTickReleasesPinAfterChallengeDeadline: a failed evaluation pins the
// watermark only while a retry could still land a challenge. Once the
// close's challenge period has elapsed nothing the tower does can matter,
// so it alarms and lets the watermark advance instead of re-filtering an
// ever-growing range on every tick for the life of the record.
func TestTickReleasesPinAfterChallengeDeadline(t *testing.T) {
	e := newCorruptEnv(t)
	tower := e.newTower()
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mark := e.watermark(); mark != e.closeBlk-1 {
		t.Fatalf("watermark %d, want pinned at %d", mark, e.closeBlk-1)
	}

	// Mid-window: still pinned.
	for i := 0; i < corruptChallengePeriod/2; i++ {
		e.backend.Commit()
	}
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mark := e.watermark(); mark != e.closeBlk-1 {
		t.Fatalf("watermark %d mid-window, want %d", mark, e.closeBlk-1)
	}
	if e.alarmed("giving up") {
		t.Fatalf("gave up inside the challenge window: %q", *e.alarms)
	}

	// Past the deadline: released, with one give-up alarm.
	for i := 0; i < corruptChallengePeriod; i++ {
		e.backend.Commit()
	}
	head, err := tower.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cutoff := head - 2
	if mark := e.watermark(); mark != cutoff {
		t.Fatalf("watermark %d after the deadline, want cutoff %d", mark, cutoff)
	}
	if !e.alarmed("giving up on close") || !e.alarmed("challenge deadline") {
		t.Fatalf("no give-up alarm: %q", *e.alarms)
	}
	// The close was never challenged: the on-chain record is the stale one.
	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.ClosingSeq != 2 {
		t.Fatalf("on-chain seq %d, want the unchallenged stale 2", onchain.ClosingSeq)
	}
}

// TestTickKeepsPinWhenChainUnreadable: the give-up check consults the
// chain; if that read fails too, the failure is the transient kind the pin
// exists for, and the watermark must hold even past the deadline until a
// tick can actually see the chain.
func TestTickKeepsPinWhenChainUnreadable(t *testing.T) {
	e := newCorruptEnv(t)
	flaky := &flakyCallBackend{TxBackend: e.backend}
	tower, err := towerd.New(towerd.Config{
		ChainID: "1337", Registry: e.regAddr, Confirmations: 3,
		Delegators: map[string]bool{"bob-npub": true},
	}, e.store, flaky, watcher.NewTxManager(flaky, e.towerPriv, big.NewInt(1337)))
	if err != nil {
		t.Fatal(err)
	}
	tower.Alarm = func(format string, args ...any) { t.Logf("alarm: "+format, args...) }

	flaky.fail.Store(true)
	for i := 0; i < 2*corruptChallengePeriod; i++ {
		e.backend.Commit()
	}
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mark := e.watermark(); mark != e.closeBlk-1 {
		t.Fatalf("watermark %d with the chain unreadable, want pinned at %d", mark, e.closeBlk-1)
	}
	flaky.fail.Store(false)
	head, err := tower.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mark := e.watermark(); mark != head-2 {
		t.Fatalf("watermark %d once the chain is readable past the deadline, want %d", mark, head-2)
	}
}

// TestTickRemembersGivenUpCloses: a close the tower gave up on stays in the
// re-scanned range while an earlier close's retryable failure pins the
// watermark below it. It must not be re-evaluated and re-alarmed on every
// tick for as long as that pin holds.
func TestTickRemembersGivenUpCloses(t *testing.T) {
	e := buildCorruptEnv(t, true)
	tower := e.newTower()
	if _, err := tower.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < corruptChallengePeriod+1; i++ {
		e.backend.Commit()
	}
	countGiveUps := func() int {
		n := 0
		for _, a := range *e.alarms {
			if strings.Contains(a, "giving up on close") {
				n++
			}
		}
		return n
	}
	for i := 0; i < 3; i++ {
		if _, err := tower.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := countGiveUps(); n != 1 {
		t.Fatalf("give-up alarms over three pinned ticks: %d, want 1: %q", n, *e.alarms)
	}
	// The earlier close still holds the pin below channel 1's close.
	if mark := e.watermark(); mark >= e.closeBlk-1 {
		t.Fatalf("watermark %d, want pinned below %d by the early close", mark, e.closeBlk-1)
	}
}
