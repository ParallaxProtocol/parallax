package watcher

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind/backends"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
)

// droppingBackend swallows the first N SendTransaction calls (the mempool
// "loses" them) while recording every attempted gas price.
type droppingBackend struct {
	TxBackend
	mu        sync.Mutex
	dropFirst int
	attempts  []*big.Int
}

func (d *droppingBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attempts = append(d.attempts, new(big.Int).Set(tx.GasPrice()))
	if len(d.attempts) <= d.dropFirst {
		return nil // accepted but never mined
	}
	return d.TxBackend.SendTransaction(ctx, tx)
}

func (d *droppingBackend) attemptCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.attempts)
}

// TestTxManagerFeeBumpsUntilMined: the first two submissions vanish; the
// manager escalates the gas price on the same nonce until one lands.
func TestTxManagerFeeBumpsUntilMined(t *testing.T) {
	e := setupSim(t)
	dropping := &droppingBackend{TxBackend: e.backend, dropFirst: 2}
	mgr := NewTxManager(dropping, e.bobPriv, big.NewInt(1337))
	var alarms []string
	mgr.Alarm = func(format string, args ...any) { alarms = append(alarms, format) }

	// Bind the contract through the dropping backend: bind sends via the
	// contract's own backend, so interception must happen there.
	contract, err := registry.NewChannelRegistry(e.regAddr, dropping)
	if err != nil {
		t.Fatal(err)
	}
	head := uint64(10)
	// Intent: bob deposits into channel 1 (any state-changing call works).
	err = mgr.Submit(context.Background(), "deposit:test", head, 0,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}
	if dropping.attemptCount() != 1 {
		t.Fatalf("attempts after submit: %d", dropping.attemptCount())
	}

	// Two ticks past the bump threshold: two escalations; the third attempt
	// reaches the real backend.
	mgr.Tick(context.Background(), head+bumpAfterBlocks)
	mgr.Tick(context.Background(), head+2*bumpAfterBlocks)
	if dropping.attemptCount() != 3 {
		t.Fatalf("attempts after bumps: %d", dropping.attemptCount())
	}
	dropping.mu.Lock()
	p0, p1, p2 := dropping.attempts[0], dropping.attempts[1], dropping.attempts[2]
	dropping.mu.Unlock()
	if p1.Cmp(p0) <= 0 || p2.Cmp(p1) <= 0 {
		t.Fatalf("gas price not escalating: %s %s %s", p0, p1, p2)
	}
	want := new(big.Int).Div(new(big.Int).Mul(p0, big.NewInt(125)), big.NewInt(100))
	if p1.Cmp(want) != 0 {
		t.Fatalf("bump 1: got %s want %s", p1, want)
	}

	// Mine it; the next tick reaps the receipt.
	e.backend.Commit()
	mgr.Tick(context.Background(), head+2*bumpAfterBlocks+1)
	if mgr.Pending("deposit:test") {
		t.Fatal("intent still pending after mining")
	}
	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.DepositB.Cmp(lax(6)) != 0 { // 5 from setup + 1 now
		t.Fatalf("deposit not applied: %s", onchain.DepositB)
	}
}

// dropAfterFirstBackend lets the first SendTransaction through and swallows
// the rest: the original broadcast survives while every fee-bump replacement
// is lost.
type dropAfterFirstBackend struct {
	TxBackend
	mu   sync.Mutex
	sent int
}

func (d *dropAfterFirstBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent++
	if d.sent > 1 {
		return nil // accepted but never propagates
	}
	return d.TxBackend.SendTransaction(ctx, tx)
}

// TestTxManagerReapsEarlierAttempt: when an earlier attempt mines instead of
// the latest fee-bumped replacement, the intent must still be reaped — only
// checking the newest hash leaves it pending forever, resubmitting into
// "nonce too low" every tick.
func TestTxManagerReapsEarlierAttempt(t *testing.T) {
	e := setupSim(t)
	dropping := &dropAfterFirstBackend{TxBackend: e.backend}
	mgr := NewTxManager(dropping, e.bobPriv, big.NewInt(1337))

	contract, err := registry.NewChannelRegistry(e.regAddr, dropping)
	if err != nil {
		t.Fatal(err)
	}
	head := uint64(10)
	err = mgr.Submit(context.Background(), "deposit:test", head, 0,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}

	// A bump replaces the hash the manager watches, but the replacement is
	// lost and the ORIGINAL transaction mines.
	mgr.Tick(context.Background(), head+bumpAfterBlocks)
	e.backend.Commit()

	mgr.Tick(context.Background(), head+bumpAfterBlocks+1)
	if mgr.Pending("deposit:test") {
		t.Fatal("intent still pending after an earlier attempt mined")
	}
}

// laggingNonceBackend serves PendingNonceAt from a stale snapshot,
// simulating a node whose pending pool has not yet registered the
// previous broadcast (or a second manager on the same key).
type laggingNonceBackend struct {
	TxBackend
	nonce uint64
}

func (b *laggingNonceBackend) PendingNonceAt(ctx context.Context, account util.Address) (uint64, error) {
	return b.nonce, nil
}

// TestTxManagerDistinctNoncesOnLaggingBackend: nonce allocation must not
// trust PendingNonceAt alone — two intents allocated against a lagging view
// pick the same nonce, and the second transaction silently replaces the
// first (a challenge or settle that never lands).
func TestTxManagerDistinctNoncesOnLaggingBackend(t *testing.T) {
	e := setupSim(t)
	base, err := e.backend.PendingNonceAt(context.Background(), e.bob)
	if err != nil {
		t.Fatal(err)
	}
	lagging := &laggingNonceBackend{TxBackend: e.backend, nonce: base}
	mgr := NewTxManager(lagging, e.bobPriv, big.NewInt(1337))

	contract, err := registry.NewChannelRegistry(e.regAddr, lagging)
	if err != nil {
		t.Fatal(err)
	}
	var nonces []uint64
	submit := func(id string) {
		err := mgr.Submit(context.Background(), id, 10, 0,
			func(auth *bind.TransactOpts) (*types.Transaction, error) {
				nonces = append(nonces, auth.Nonce.Uint64())
				auth.Value = lax(1)
				return contract.Deposit(auth, big.NewInt(1))
			})
		if err != nil {
			t.Logf("submit %s: %v", id, err)
		}
	}
	submit("challenge:a")
	submit("settle:b")

	if len(nonces) != 2 {
		t.Fatalf("expected two builds, got %d", len(nonces))
	}
	if nonces[0] == nonces[1] {
		t.Fatalf("nonce collision: both intents allocated nonce %d", nonces[0])
	}
	if nonces[1] != nonces[0]+1 {
		t.Fatalf("nonces not sequential: %v", nonces)
	}
}

// TestTxManagerReleasesAbandonedNonce: an intent abandoned via Done whose
// transaction never mined (mempool eviction, bump cap reached) must release
// its nonce. A counter that only ratchets upward would leave a permanent gap
// at the lost nonce, wedging every later submission — including loss-capable
// challenges — behind a transaction that can never mine.
func TestTxManagerReleasesAbandonedNonce(t *testing.T) {
	e := setupSim(t)
	base, err := e.backend.PendingNonceAt(context.Background(), e.bob)
	if err != nil {
		t.Fatal(err)
	}
	// The pool never registers anything (broadcasts are lost), so the chain's
	// pending view stays at base throughout.
	lagging := &laggingNonceBackend{TxBackend: e.backend, nonce: base}
	dropping := &droppingBackend{TxBackend: lagging, dropFirst: 1000}
	mgr := NewTxManager(dropping, e.bobPriv, big.NewInt(1337))

	contract, err := registry.NewChannelRegistry(e.regAddr, dropping)
	if err != nil {
		t.Fatal(err)
	}
	var nonces []uint64
	submit := func(id string) {
		err := mgr.Submit(context.Background(), id, 10, 0,
			func(auth *bind.TransactOpts) (*types.Transaction, error) {
				nonces = append(nonces, auth.Nonce.Uint64())
				auth.Value = lax(1)
				return contract.Deposit(auth, big.NewInt(1))
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	submit("challenge:a")
	// The channel leaves Closing by other means; the caller abandons the
	// intent while its broadcast is lost forever.
	mgr.Done("challenge:a")
	submit("challenge:b")

	if len(nonces) != 2 {
		t.Fatalf("expected two builds, got %d", len(nonces))
	}
	if nonces[1] != nonces[0] {
		t.Fatalf("abandoned nonce %d not released: next intent allocated %d, which can never mine while %d is unfilled",
			nonces[0], nonces[1], nonces[0])
	}
}

// TestTxManagerConcurrentTicks: in tower mode the node's watch loop and the
// tower's tick loop drive the SAME shared per-chain manager from two
// goroutines, so Tick must be safe against itself: the bump path mutates
// per-intent state (gasPrice, bumps, txHashes) that a concurrent Tick reads.
// Run under -race.
func TestTxManagerConcurrentTicks(t *testing.T) {
	e := setupSim(t)
	dropping := &droppingBackend{TxBackend: e.backend, dropFirst: 1000} // never mines
	mgr := NewTxManager(dropping, e.bobPriv, big.NewInt(1337))

	contract, err := registry.NewChannelRegistry(e.regAddr, dropping)
	if err != nil {
		t.Fatal(err)
	}
	head := uint64(10)
	err = mgr.Submit(context.Background(), "deposit:test", head, 0,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				mgr.Tick(context.Background(), head+uint64(2*i))
			}
		}()
	}
	wg.Wait()
}

// TestTxManagerDeadlineAlarm: an unmined intent alarms as its deadline
// approaches.
func TestTxManagerDeadlineAlarm(t *testing.T) {
	e := setupSim(t)
	dropping := &droppingBackend{TxBackend: e.backend, dropFirst: 1000} // never lands
	mgr := NewTxManager(dropping, e.bobPriv, big.NewInt(1337))
	var alarmed bool
	mgr.Alarm = func(format string, args ...any) { alarmed = true }

	contract, err := registry.NewChannelRegistry(e.regAddr, dropping)
	if err != nil {
		t.Fatal(err)
	}
	head := uint64(10)
	deadline := head + 20
	err = mgr.Submit(context.Background(), "challenge:test", head, deadline,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}
	mgr.Tick(context.Background(), head+2)
	if alarmed {
		t.Fatal("alarmed too early")
	}
	mgr.Tick(context.Background(), deadline-alarmBlocksBeforeDeadline+1)
	if !alarmed {
		t.Fatal("no alarm near deadline")
	}
}

// erroringSendBackend fails SendTransaction outright while failing is set
// (an RPC outage: nothing reaches the mempool), recording the gas price of
// every send that goes through.
type erroringSendBackend struct {
	TxBackend
	mu      sync.Mutex
	failing bool
	sent    []*big.Int
	failed  int // sends refused while failing
}

func (b *erroringSendBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	b.mu.Lock()
	if b.failing {
		b.failed++
		b.mu.Unlock()
		return errInjectedOutage
	}
	b.sent = append(b.sent, new(big.Int).Set(tx.GasPrice()))
	b.mu.Unlock()
	return b.TxBackend.SendTransaction(ctx, tx)
}

var errInjectedOutage = errors.New("injected rpc outage")

// TestTxManagerBumpsSurviveRpcOutage: a fee bump must be consumed by a
// successful handoff to the RPC, not by the attempt. Consuming the budget on
// failed sends means a >20-block RPC outage exhausts all maxBumps with only
// the original low-fee transaction in the mempool — and no escalation ever
// happens once the RPC recovers, exactly when the stuck challenge needs it.
func TestTxManagerBumpsSurviveRpcOutage(t *testing.T) {
	e := setupSim(t)
	erroring := &erroringSendBackend{TxBackend: e.backend}
	mgr := NewTxManager(erroring, e.bobPriv, big.NewInt(1337))
	mgr.Alarm = func(format string, args ...any) {}

	contract, err := registry.NewChannelRegistry(e.regAddr, erroring)
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.Submit(context.Background(), "deposit:test", 10, 0,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}

	// The transaction never mines and the RPC goes down for well over
	// maxBumps' worth of bump-eligible ticks.
	erroring.mu.Lock()
	erroring.failing = true
	erroring.mu.Unlock()
	for head := uint64(12); head < 12+2*(maxBumps+2); head += bumpAfterBlocks {
		mgr.Tick(context.Background(), head)
	}
	erroring.mu.Lock()
	erroring.failing = false
	erroring.mu.Unlock()

	// RPC is back: the escalation must resume.
	mgr.Tick(context.Background(), 100)

	erroring.mu.Lock()
	defer erroring.mu.Unlock()
	if len(erroring.sent) < 2 {
		t.Fatalf("no fee bump reached the mempool after the outage: %d sends", len(erroring.sent))
	}
	last := erroring.sent[len(erroring.sent)-1]
	if last.Cmp(erroring.sent[0]) <= 0 {
		t.Fatalf("post-outage resubmission not escalated: first %s, last %s", erroring.sent[0], last)
	}
}

// TestTxManagerFailedBumpWaitsForNextBlock: a fee bump whose send fails for
// a non-benign reason is retried once per block, not on every tick. Ticks
// arrive every few seconds while blocks arrive every ten minutes, so an
// intent whose build fails deterministically (the channel was settled
// under a lingering challenge, so estimateGas reverts) would otherwise
// rebuild, fail, and alarm ~120 times per block for as long as it lives.
// A transient failure must not cost more than that one block: waiting a
// whole bump window would delay a challenge's escalation after the RPC
// recovers.
func TestTxManagerFailedBumpWaitsForNextBlock(t *testing.T) {
	e := setupSim(t)
	erroring := &erroringSendBackend{TxBackend: e.backend}
	mgr := NewTxManager(erroring, e.bobPriv, big.NewInt(1337))
	var alarms int
	mgr.Alarm = func(format string, args ...any) { alarms++ }

	contract, err := registry.NewChannelRegistry(e.regAddr, erroring)
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.Submit(context.Background(), "deposit:test", 10, 0,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}
	erroring.mu.Lock()
	erroring.failing = true
	erroring.mu.Unlock()

	failedAfter := func(head uint64) int {
		mgr.Tick(context.Background(), head)
		erroring.mu.Lock()
		defer erroring.mu.Unlock()
		return erroring.failed
	}
	// First bump-eligible head: one attempt, one alarm.
	if n := failedAfter(10 + bumpAfterBlocks); n != 1 {
		t.Fatalf("attempts after first bump window: %d, want 1", n)
	}
	// Ticks at the same head must not retry.
	if n := failedAfter(10 + bumpAfterBlocks); n != 1 {
		t.Fatalf("retried on a same-head tick: %d attempts", n)
	}
	// The next block retries exactly once more.
	if n := failedAfter(10 + bumpAfterBlocks + 1); n != 2 {
		t.Fatalf("attempts at the next block: %d, want 2", n)
	}
	if alarms != 2 {
		t.Fatalf("alarms: %d, want one per attempt (2)", alarms)
	}
	// The failed attempts consumed no bump budget: the escalation still has
	// its full allowance once sends go through again.
	mgr.mu.Lock()
	bumps := mgr.pending["deposit:test"].bumps
	mgr.mu.Unlock()
	if bumps != 0 {
		t.Fatalf("failed sends consumed %d bumps", bumps)
	}
}

// TestTxManagerFailedBumpRetriesEveryTickNearDeadline: inside the alarm
// window a deadline-bound intent (a challenge) cannot afford to wait for
// the next block after a failed send, so every tick retries.
func TestTxManagerFailedBumpRetriesEveryTickNearDeadline(t *testing.T) {
	e := setupSim(t)
	erroring := &erroringSendBackend{TxBackend: e.backend}
	mgr := NewTxManager(erroring, e.bobPriv, big.NewInt(1337))
	mgr.Alarm = func(format string, args ...any) {}

	contract, err := registry.NewChannelRegistry(e.regAddr, erroring)
	if err != nil {
		t.Fatal(err)
	}
	head := uint64(10)
	deadline := head + alarmBlocksBeforeDeadline + bumpAfterBlocks
	err = mgr.Submit(context.Background(), "challenge:test", head, deadline,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}
	erroring.mu.Lock()
	erroring.failing = true
	erroring.mu.Unlock()

	near := deadline - alarmBlocksBeforeDeadline + 1
	mgr.Tick(context.Background(), near)
	mgr.Tick(context.Background(), near)
	erroring.mu.Lock()
	n := erroring.failed
	erroring.mu.Unlock()
	if n != 2 {
		t.Fatalf("attempts on two ticks near the deadline: %d, want 2", n)
	}
}

// gethPoolBackend models a real node's txpool on top of the simulated
// backend (which rejects any nonce != pending): a lower nonce is refused
// with geth's "nonce too low", a higher nonce is "queued" (accepted, never
// mined until the gap fills; the sender must resend it), and the first
// dropN sends are accepted but lost (node restart without journal,
// eviction). It hides NonceAt, so the manager learns of a consumed nonce
// only from a resubmit; minedNonceBackend restores the lookup.
type gethPoolBackend struct {
	TxBackend
	mu     sync.Mutex
	dropN  int
	sent   int
	queued int
}

func (g *gethPoolBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sent++
	if g.sent <= g.dropN {
		return nil
	}
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		return err
	}
	pn, err := g.TxBackend.PendingNonceAt(ctx, from)
	if err != nil {
		return err
	}
	if tx.Nonce() < pn {
		return errors.New("nonce too low")
	}
	if tx.Nonce() > pn {
		g.queued++
		return nil
	}
	return g.TxBackend.SendTransaction(ctx, tx)
}

// minedNonceBackend is a gethPoolBackend that also serves NonceAt.
type minedNonceBackend struct {
	*gethPoolBackend
	sim *backends.SimulatedBackend
}

func (b *minedNonceBackend) NonceAt(ctx context.Context, account util.Address, blockNumber *big.Int) (uint64, error) {
	return b.sim.NonceAt(ctx, account, blockNumber)
}

// startStaleClose stores bob's seq-5 state, has alice force-close at stale
// seq 2, confirms it, and returns the challenge deadline.
func startStaleClose(t *testing.T, e *simEnv) uint64 {
	t.Helper()
	if err := e.store.PutComplete(e.dualSigned(t, 5, lax(3), new(big.Int))); err != nil {
		t.Fatal(err)
	}
	stale := e.dualSigned(t, 2, lax(1), new(big.Int))
	if _, err := e.contract.StartClose(e.aliceAuth, big.NewInt(1), stale.ContractProof(), stale.SigA, stale.SigB); err != nil {
		t.Fatal(err)
	}
	e.commit(3)
	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	return onchain.CloseInitiatedAtBlock.Uint64() + uint64(onchain.ChallengePeriodBlocks)
}

// tickUntilDeadline drives the watcher block by block up to the challenge
// deadline and returns the on-chain closing seq there, before any settle.
func tickUntilDeadline(t *testing.T, e *simEnv, w *Watcher, deadline uint64) uint64 {
	t.Helper()
	for e.backend.Blockchain().CurrentBlock().Number().Uint64() < deadline {
		_, _ = w.Tick(context.Background())
		e.commit(1)
	}
	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	return onchain.ClosingSeq
}

func newPoolWatcher(t *testing.T, e *simEnv, backend TxBackend) (*Watcher, *TxManager, *[]string) {
	t.Helper()
	mgr := NewTxManager(backend, e.bobPriv, big.NewInt(1337))
	w, err := New(Config{ChainID: "1337", Registry: e.regAddr, Confirmations: 3}, e.store, backend, mgr)
	if err != nil {
		t.Fatal(err)
	}
	alarms := &[]string{}
	w.Alarm = func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		t.Logf("alarm: %s", msg)
		*alarms = append(*alarms, msg)
	}
	return w, mgr, alarms
}

// TestTxManagerFillsLostTransactNonce: a Transact whose broadcast is lost
// and whose caller stops waiting is never resent, so its nonce reservation
// would stand as a gap every later intent queues behind: the auto-challenge
// sits unexecutable and the stale close settles. The manager must fill the
// missing nonce (without replaying the abandoned call) so the challenge
// lands inside the window.
func TestTxManagerFillsLostTransactNonce(t *testing.T) {
	e := setupSim(t)
	pool := &gethPoolBackend{TxBackend: e.backend, dropN: 1}
	w, mgr, alarms := newPoolWatcher(t, e, pool)
	contract, err := registry.NewChannelRegistry(e.regAddr, pool)
	if err != nil {
		t.Fatal(err)
	}

	// An ordinary channeld call through the shared manager: the broadcast
	// is lost and the caller's context expires.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	_, err = mgr.Transact(ctx, "deposit", func(auth *bind.TransactOpts) (*types.Transaction, error) {
		auth.Value = lax(1)
		return contract.Deposit(auth, big.NewInt(1))
	})
	cancel()
	if err == nil {
		t.Fatal("lost Transact reported mined")
	}

	deadline := startStaleClose(t, e)
	if seq := tickUntilDeadline(t, e, w, deadline); seq != 5 {
		t.Fatalf("on-chain seq %d at the deadline, want 5: challenge wedged behind the lost Transact nonce", seq)
	}
	filled := false
	for _, a := range *alarms {
		filled = filled || strings.Contains(a, "filling its nonce")
	}
	if !filled {
		t.Fatalf("no nonce-fill alarm: %q", *alarms)
	}
	// The abandoned deposit was not replayed.
	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.DepositB.Cmp(lax(5)) != 0 {
		t.Fatalf("abandoned deposit replayed: depositB %s", onchain.DepositB)
	}
}

// consumeBobNonce sends an unrelated transfer from bob's key outside the
// manager (the operator's other wallet) and mines it.
func consumeBobNonce(t *testing.T, e *simEnv) {
	t.Helper()
	nonce, err := e.backend.PendingNonceAt(context.Background(), e.bob)
	if err != nil {
		t.Fatal(err)
	}
	gp, err := e.backend.SuggestGasPrice(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := types.SignTx(types.NewTransaction(nonce, e.alice, big.NewInt(1), 21000, gp, nil),
		types.LatestSignerForChainID(big.NewInt(1337)), e.bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.backend.SendTransaction(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	e.commit(1)
}

// TestTxManagerNonceTooLowDropsIntent: the challenge's first broadcast is
// lost and another transaction on the same key consumes its nonce. Every
// fee bump then meets "nonce too low"; treating that as benign burned the
// bump budget and left the intent pending forever, and a pending id makes
// Submit a no-op, so the challenge was never re-nonced. The intent must be
// dropped (no bump counted) and resubmitted at a fresh nonce.
func TestTxManagerNonceTooLowDropsIntent(t *testing.T) {
	e := setupSim(t)
	pool := &gethPoolBackend{TxBackend: e.backend, dropN: 1}
	w, mgr, alarms := newPoolWatcher(t, e, pool)
	deadline := startStaleClose(t, e)

	if _, err := w.Tick(context.Background()); err != nil { // challenge sent, lost
		t.Fatal(err)
	}
	mgr.mu.Lock()
	lost := mgr.pending["challenge:"+e.key.String()].nonce
	mgr.mu.Unlock()
	consumeBobNonce(t, e)

	if seq := tickUntilDeadline(t, e, w, deadline); seq != 5 {
		t.Fatalf("on-chain seq %d at the deadline, want 5: challenge wedged on consumed nonce %d", seq, lost)
	}
	dropped := false
	for _, a := range *alarms {
		dropped = dropped || strings.Contains(a, "lost nonce")
	}
	if !dropped {
		t.Fatalf("no lost-nonce alarm: %q", *alarms)
	}
}

// TestTxManagerDropsIntentOnConsumedNonce: with a mined-nonce lookup the
// manager spots a consumed nonce on the next tick, without waiting for a
// bump to fail, and the challenge is re-nonced at once.
func TestTxManagerDropsIntentOnConsumedNonce(t *testing.T) {
	e := setupSim(t)
	pool := &minedNonceBackend{gethPoolBackend: &gethPoolBackend{TxBackend: e.backend, dropN: 1}, sim: e.backend}
	w, mgr, _ := newPoolWatcher(t, e, pool)
	startStaleClose(t, e)

	if _, err := w.Tick(context.Background()); err != nil { // challenge sent, lost
		t.Fatal(err)
	}
	id := "challenge:" + e.key.String()
	mgr.mu.Lock()
	lost := mgr.pending[id].nonce
	mgr.mu.Unlock()
	consumeBobNonce(t, e)

	// Inside the bump window: only the consumed-nonce check can act.
	if _, err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	mgr.mu.Lock()
	p, ok := mgr.pending[id]
	mgr.mu.Unlock()
	if !ok || p.nonce == lost {
		t.Fatalf("challenge not re-nonced past consumed nonce %d (pending %v)", lost, ok)
	}
	e.commit(1)
	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.ClosingSeq != 5 {
		t.Fatalf("on-chain seq %d after the re-nonced challenge, want 5", onchain.ClosingSeq)
	}
}

// TestTxManagerRebroadcastsPastBumpCap: once maxBumps is spent the intent
// is still resent at its final price, so a transaction lost from the pool
// after the last bump is not stranded with no attempt in flight.
func TestTxManagerRebroadcastsPastBumpCap(t *testing.T) {
	e := setupSim(t)
	dropping := &droppingBackend{TxBackend: e.backend, dropFirst: 1 + maxBumps}
	mgr := NewTxManager(dropping, e.bobPriv, big.NewInt(1337))
	contract, err := registry.NewChannelRegistry(e.regAddr, dropping)
	if err != nil {
		t.Fatal(err)
	}
	head := uint64(10)
	err = mgr.Submit(context.Background(), "deposit:test", head, 0,
		func(auth *bind.TransactOpts) (*types.Transaction, error) {
			auth.Value = lax(1)
			return contract.Deposit(auth, big.NewInt(1))
		})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= maxBumps+1; i++ {
		mgr.Tick(context.Background(), head+uint64(i)*bumpAfterBlocks)
	}
	dropping.mu.Lock()
	n := len(dropping.attempts)
	last, capped := dropping.attempts[n-1], dropping.attempts[n-2]
	dropping.mu.Unlock()
	if n != maxBumps+2 {
		t.Fatalf("attempts: %d, want %d (original, %d bumps, one rebroadcast)", n, maxBumps+2, maxBumps)
	}
	if last.Cmp(capped) != 0 {
		t.Fatalf("rebroadcast past the cap repriced: %s after %s", last, capped)
	}
	e.backend.Commit()
	mgr.Tick(context.Background(), head+uint64(maxBumps+2)*bumpAfterBlocks)
	if mgr.Pending("deposit:test") {
		t.Fatal("rebroadcast past the bump cap never mined")
	}
}
