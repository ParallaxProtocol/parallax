package watcher

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script/abi/bind"
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
