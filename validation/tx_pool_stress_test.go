// Copyright 2025-2026 The Parallax Protocol Authors
// This file is part of the parallax library.
//
// The parallax library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The parallax library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the parallax library. If not, see <http://www.gnu.org/licenses/>.

package validation

import (
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/kernel/xhash"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/support/event"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"
	"github.com/ParallaxProtocol/parallax/v2/validation/state"
)

// Stress test knobs. Every test in this file is skipped entirely under -short;
// tune the constants below to change the load.
const (
	stressPoolSeed int64 = 202608

	// TestStressPoolConcurrentIngest
	stressIngestTxs      = 16000
	stressIngestAccounts = 64
	stressIngestWorkers  = 8
	stressIngestBatch    = 100

	// TestStressPoolEvictionUnderPressure
	stressEvictGlobalSlots     = 512
	stressEvictGlobalQueue     = 512
	stressEvictAccountSlots    = 4
	stressEvictAccountQueue    = 32
	stressEvictWaves           = 10
	stressEvictAccountsPerWave = 128
	stressEvictBatch           = 256

	// TestStressPoolReorgChurn
	stressReorgFlips       = 200
	stressReorgForkBlocks  = 3
	stressReorgAccounts    = 8 // accounts per fork side
	stressReorgTxsPerAcct  = 6 // transactions held in the pool per account
	stressReorgSampleEvery = 20

	// TestStressPoolNonceGapsAndReplacements
	stressOpsCount       = 10000
	stressOpsAccounts    = 16
	stressOpsMaxPerAcct  = 700
	stressOpsPriceCap    = 1000000 // stop bumping a nonce beyond this price
	stressOpsSampleEvery = 500
)

// stressKey derives a deterministic private key from the given seeded source,
// so stress runs are reproducible (crypto.GenerateKey would use crypto/rand).
func stressKey(t *testing.T, rng *rand.Rand) (*ecdsa.PrivateKey, util.Address) {
	t.Helper()
	for i := 0; i < 128; i++ {
		var seed [32]byte
		rng.Read(seed[:])
		if key, err := crypto.ToECDSA(seed[:]); err == nil {
			return key, crypto.PubkeyToAddress(key.PublicKey)
		}
	}
	t.Fatal("could not derive a deterministic key from the seeded source")
	return nil, util.Address{}
}

// stressCheckNonceCoherence verifies the per account nonce invariants the pool
// actually guarantees: the pending list of every account is gap-free ascending,
// and any queued transactions sit strictly above the account's highest pending
// nonce. Note that the queue itself may legitimately contain nonce gaps (that
// is what the future queue is for), so no contiguity is asserted there.
func stressCheckNonceCoherence(t *testing.T, pool *TxPool, pending, queued map[util.Address]types.Transactions) {
	t.Helper()
	for addr, txs := range pending {
		for i := 1; i < len(txs); i++ {
			if txs[i].Nonce() != txs[i-1].Nonce()+1 {
				t.Fatalf("account %x: pending nonce gap: %d followed by %d", addr, txs[i-1].Nonce(), txs[i].Nonce())
			}
		}
		if q := queued[addr]; len(q) > 0 && len(txs) > 0 {
			if q[0].Nonce() <= txs[len(txs)-1].Nonce() {
				t.Fatalf("account %x: queued nonce %d not above pending max %d", addr, q[0].Nonce(), txs[len(txs)-1].Nonce())
			}
		}
	}
	// Content() flattens through txSortedMap, which sorts by nonce and holds
	// one tx per nonce key, so ordering checks on its output are vacuous.
	// Assert the underlying bookkeeping instead: every tx in the internal
	// pending and queue maps must be stored under its own nonce key.
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for addr, list := range pool.pending {
		for nonce, tx := range list.txs.items {
			if tx.Nonce() != nonce {
				t.Fatalf("account %x: pending tx with nonce %d stored under key %d", addr, tx.Nonce(), nonce)
			}
		}
	}
	for addr, list := range pool.queue {
		for nonce, tx := range list.txs.items {
			if tx.Nonce() != nonce {
				t.Fatalf("account %x: queued tx with nonce %d stored under key %d", addr, tx.Nonce(), nonce)
			}
		}
	}
}

// TestStressPoolConcurrentIngest hammers the pool from several goroutines with
// a deterministically shuffled stream of transactions from many accounts and
// verifies that no transaction is lost and the pool ends up fully consistent.
func TestStressPoolConcurrentIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	rng := rand.New(rand.NewSource(stressPoolSeed))

	statedb, _ := state.New(util.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{100000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.AccountSlots = 512
	config.AccountQueue = 512
	config.GlobalSlots = 2 * stressIngestTxs
	config.GlobalQueue = 2 * stressIngestTxs

	pool := NewTxPool(config, chainparams.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create the accounts and pre-sign every transaction with in-order nonces.
	perAccount := stressIngestTxs / stressIngestAccounts
	total := perAccount * stressIngestAccounts

	txs := make([]*types.Transaction, 0, total)
	for i := 0; i < stressIngestAccounts; i++ {
		key, addr := stressKey(t, rng)
		testAddBalance(pool, addr, big.NewInt(1000000000000))
		for n := 0; n < perAccount; n++ {
			txs = append(txs, transaction(uint64(n), 100000, key))
		}
	}
	// Deterministically shuffle the global submission order so nonces arrive
	// wildly out of order, both within and across the worker goroutines.
	rng.Shuffle(len(txs), func(i, j int) { txs[i], txs[j] = txs[j], txs[i] })

	workers := stressIngestWorkers
	if p := runtime.GOMAXPROCS(0); p < workers {
		workers = p
	}
	var (
		wg     sync.WaitGroup
		counts = make([]int, workers)
		fails  = make([]error, workers)
	)
	chunk := (len(txs) + workers - 1) / workers
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := min(lo+chunk, len(txs))
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func(w int, part []*types.Transaction) {
			defer wg.Done()
			for s := 0; s < len(part); s += stressIngestBatch {
				e := min(s+stressIngestBatch, len(part))
				for _, err := range pool.AddRemotesSync(part[s:e]) {
					if err != nil {
						if fails[w] == nil {
							fails[w] = err
						}
						continue
					}
					counts[w]++
				}
			}
		}(w, txs[lo:hi])
	}
	wg.Wait()

	added := 0
	for w := 0; w < workers; w++ {
		if fails[w] != nil {
			t.Fatalf("worker %d: unexpected add error: %v", w, fails[w])
		}
		added += counts[w]
	}
	if added != total {
		t.Fatalf("added transaction count mismatch: have %d, want %d", added, total)
	}
	// The pool was sized to hold everything, so pending+queued must equal the
	// successfully added count, and with all nonce runs complete nothing may
	// be left in the future queue.
	pending, queued := pool.Stats()
	if pending+queued != added {
		t.Fatalf("pool content mismatch: %d pending + %d queued != %d added", pending, queued, added)
	}
	if queued != 0 {
		t.Fatalf("queued transactions remained after full nonce runs: %d", queued)
	}
	// Cross-check Stats against Content and verify per account gap-free runs.
	pendingMap, queuedMap := pool.Content()
	contentTotal := 0
	for _, txs := range pendingMap {
		contentTotal += len(txs)
	}
	for _, txs := range queuedMap {
		contentTotal += len(txs)
	}
	if contentTotal != pending+queued {
		t.Fatalf("Stats/Content mismatch: content %d, stats %d", contentTotal, pending+queued)
	}
	if len(pendingMap) != stressIngestAccounts {
		t.Fatalf("pending account count mismatch: have %d, want %d", len(pendingMap), stressIngestAccounts)
	}
	for addr, txs := range pendingMap {
		if len(txs) != perAccount {
			t.Fatalf("account %x: pending count mismatch: have %d, want %d", addr, len(txs), perAccount)
		}
		if txs[0].Nonce() != 0 {
			t.Fatalf("account %x: pending does not start at base nonce: %d", addr, txs[0].Nonce())
		}
	}
	stressCheckNonceCoherence(t, pool, pendingMap, queuedMap)
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TestStressPoolEvictionUnderPressure floods a small pool with roughly 10x its
// capacity at varied gas prices and verifies the capacity limits, the per
// account nonce invariants and the price floor behavior of a full pool.
//
// Notes on what the implementation actually guarantees and is asserted here:
//   - total slots never exceed GlobalSlots+GlobalQueue (enforced in add), and
//     the queue never exceeds GlobalQueue after a reorg run (truncateQueue);
//     pending alone may exceed GlobalSlots when no account is above
//     AccountSlots (see TestTransactionPendingMinimumAllowance), so that is
//     deliberately not asserted;
//   - price-based eviction only happens on inserts into a full pool
//     (txPricedList.Discard drops the cheapest first, and cheaper-than-floor
//     incoming transactions are rejected with ErrUnderpriced). truncateQueue
//     evicts by account age and truncatePending by account size, neither by
//     price, so no percentile bound on surviving prices is guaranteed; the
//     floor property is asserted with explicit probes instead.
func TestStressPoolEvictionUnderPressure(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	rng := rand.New(rand.NewSource(stressPoolSeed))

	statedb, _ := state.New(util.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{100000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.GlobalSlots = stressEvictGlobalSlots
	config.GlobalQueue = stressEvictGlobalQueue
	config.AccountSlots = stressEvictAccountSlots
	config.AccountQueue = stressEvictAccountQueue

	pool := NewTxPool(config, chainparams.TestChainConfig, blockchain)
	defer pool.Stop()

	capacity := stressEvictGlobalSlots + stressEvictGlobalQueue

	checkCapacity := func(context string) {
		pending, queued := pool.Stats()
		if pending+queued > capacity {
			t.Fatalf("%s: pool overflows capacity: %d pending + %d queued > %d", context, pending, queued, capacity)
		}
		if queued > stressEvictGlobalQueue {
			t.Fatalf("%s: queue overflows allowance: %d > %d", context, queued, stressEvictGlobalQueue)
		}
	}
	// Flood the pool in waves of rising price bands. Every transaction is
	// priced at minPrice or above, which pins the floor probes below.
	const minPrice = int64(2)
	for wave := 0; wave < stressEvictWaves; wave++ {
		txs := make([]*types.Transaction, 0, stressEvictAccountsPerWave*8)
		for a := 0; a < stressEvictAccountsPerWave; a++ {
			key, addr := stressKey(t, rng)
			testAddBalance(pool, addr, big.NewInt(100000000000))
			// Four executable nonces and four gapped ones per account, so the
			// flood exercises both the pending pool and the future queue.
			for _, n := range []uint64{0, 1, 2, 3, 8, 9, 10, 11} {
				price := minPrice + int64(wave*10) + int64(rng.Intn(10))
				txs = append(txs, pricedTransaction(n, 100000, big.NewInt(price), key))
			}
		}
		rng.Shuffle(len(txs), func(i, j int) { txs[i], txs[j] = txs[j], txs[i] })

		for s := 0; s < len(txs); s += stressEvictBatch {
			e := min(s+stressEvictBatch, len(txs))
			for i, err := range pool.AddRemotesSync(txs[s:e]) {
				switch err {
				case nil, ErrUnderpriced, ErrTxPoolOverflow, ErrFutureReplacePending:
					// Gapped remote transactions may not evict pending ones
				default:
					t.Fatalf("wave %d: tx %d: unexpected add error: %v", wave, s+i, err)
				}
			}
			checkCapacity("mid-flood")
		}
	}
	// Verify the per account nonce invariants and that nothing below the
	// injected price minimum materialized out of thin air.
	pendingMap, queuedMap := pool.Content()
	stressCheckNonceCoherence(t, pool, pendingMap, queuedMap)
	for _, m := range []map[util.Address]types.Transactions{pendingMap, queuedMap} {
		for addr, txs := range m {
			for _, tx := range txs {
				if tx.GasPrice().Int64() < minPrice {
					t.Fatalf("account %x: surviving tx priced %v below injected minimum %d", addr, tx.GasPrice(), minPrice)
				}
			}
		}
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Top the pool up to exactly full capacity with well priced executable
	// transactions from fresh accounts (truncateQueue may have left it below
	// capacity), then probe the price floor of the full pool.
	const topUpPrice = 1000
	for i := 0; i < capacity; i++ {
		pending, queued := pool.Stats()
		if pending+queued >= capacity {
			break
		}
		key, addr := stressKey(t, rng)
		testAddBalance(pool, addr, big.NewInt(100000000000))
		if err := pool.addRemoteSync(pricedTransaction(0, 100000, big.NewInt(topUpPrice), key)); err != nil {
			t.Fatalf("top-up %d: failed to add transaction: %v", i, err)
		}
	}
	pending, queued := pool.Stats()
	if pending+queued != capacity {
		t.Fatalf("failed to fill pool to capacity: have %d, want %d", pending+queued, capacity)
	}
	// A full pool must reject a transaction priced below every survivor.
	cheapKey, cheapAddr := stressKey(t, rng)
	testAddBalance(pool, cheapAddr, big.NewInt(100000000000))
	cheapTx := pricedTransaction(0, 100000, big.NewInt(minPrice-1), cheapKey)
	if err := pool.addRemoteSync(cheapTx); err != ErrUnderpriced {
		t.Fatalf("adding underpriced tx to full pool: have %v, want %v", err, ErrUnderpriced)
	}
	if pool.Get(cheapTx.Hash()) != nil {
		t.Fatalf("underpriced transaction entered the full pool")
	}
	// And it must accept one priced above everything, evicting a cheaper one
	// while staying within capacity.
	richKey, richAddr := stressKey(t, rng)
	testAddBalance(pool, richAddr, big.NewInt(1000000000000))
	richTx := pricedTransaction(0, 100000, big.NewInt(5000), richKey)
	if err := pool.addRemoteSync(richTx); err != nil {
		t.Fatalf("adding well priced tx to full pool failed: %v", err)
	}
	if pool.Get(richTx.Hash()) == nil {
		t.Fatalf("well priced transaction missing from the pool")
	}
	checkCapacity("after probes")
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// stressForkChain is a blockChain mock backed by real blocks generated with
// GenerateChain. It knows every block of both forks (plus the common ancestor)
// so the pool's reset walk can traverse head flips, and it serves real states
// committed by the chain maker.
type stressForkChain struct {
	statedb state.Database
	blocks  map[util.Hash]*types.Block
	mu      sync.Mutex
	head    *types.Block
	feed    *event.Feed
}

func (c *stressForkChain) CurrentBlock() *types.Block {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}

func (c *stressForkChain) setHead(block *types.Block) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.head = block
}

func (c *stressForkChain) GetBlock(hash util.Hash, number uint64) *types.Block {
	return c.blocks[hash]
}

func (c *stressForkChain) StateAt(root util.Hash) (*state.StateDB, error) {
	return state.New(root, c.statedb, nil)
}

func (c *stressForkChain) SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription {
	return c.feed.Subscribe(ch)
}

// TestStressPoolReorgChurn builds two forks sharing an ancestor and flips the
// pool's head between the fork tips many times while transactions mined on
// both forks live in the pool. After every flip the pool must not contain any
// transaction mined on the current head, and every account's pending run must
// start exactly at its state nonce.
func TestStressPoolReorgChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	rng := rand.New(rand.NewSource(stressPoolSeed))
	db := rawdb.NewMemoryDatabase()

	type account struct {
		key  *ecdsa.PrivateKey
		addr util.Address
	}
	newAccounts := func(n int) []account {
		accs := make([]account, n)
		for i := range accs {
			accs[i].key, accs[i].addr = stressKey(t, rng)
		}
		return accs
	}
	// Two disjoint account sets: fork A mines set A transactions, fork B mines
	// set B transactions, so both forks' transactions can coexist in the pool.
	setA := newAccounts(stressReorgAccounts)
	setB := newAccounts(stressReorgAccounts)

	alloc := GenesisAlloc{}
	for _, acc := range append(append([]account{}, setA...), setB...) {
		alloc[acc.addr] = GenesisAccount{Balance: new(big.Int).SetUint64(chainparams.Ether)}
	}
	gspec := &Genesis{Config: chainparams.TestChainConfig, Alloc: alloc}
	genesis := gspec.MustCommit(db)

	// Price above the London initial base fee so the chain maker accepts the
	// transactions into blocks.
	gasPrice := big.NewInt(2 * chainparams.InitialBaseFee)
	signer := types.HomesteadSigner{}
	mkTxs := func(accs []account) [][]*types.Transaction {
		out := make([][]*types.Transaction, len(accs))
		for i, acc := range accs {
			out[i] = make([]*types.Transaction, stressReorgTxsPerAcct)
			for n := 0; n < stressReorgTxsPerAcct; n++ {
				tx, err := types.SignTx(types.NewTransaction(uint64(n), util.Address{1}, big.NewInt(100), chainparams.TxGas, gasPrice, nil), signer, acc.key)
				if err != nil {
					t.Fatalf("failed to sign transaction: %v", err)
				}
				out[i][n] = tx
			}
		}
		return out
	}
	txsA := mkTxs(setA)
	txsB := mkTxs(setB)

	// Each fork block mines one transaction per account of its side, so a fork
	// tip has the first stressReorgForkBlocks nonces of its side mined.
	buildFork := func(mined [][]*types.Transaction, coinbase util.Address) []*types.Block {
		blocks, _ := GenerateChain(chainparams.TestChainConfig, genesis, xhash.NewFaker(), db, stressReorgForkBlocks, func(i int, gen *BlockGen) {
			gen.SetCoinbase(coinbase)
			for _, txs := range mined {
				gen.AddTx(txs[i])
			}
		})
		return blocks
	}
	forkA := buildFork(txsA, util.Address{0xaa})
	forkB := buildFork(txsB, util.Address{0xbb})

	chain := &stressForkChain{
		statedb: state.NewDatabase(db),
		blocks:  map[util.Hash]*types.Block{genesis.Hash(): genesis},
		head:    genesis,
		feed:    new(event.Feed),
	}
	for _, block := range forkA {
		chain.blocks[block.Hash()] = block
	}
	for _, block := range forkB {
		chain.blocks[block.Hash()] = block
	}

	pool := NewTxPool(testTxPoolConfig, chainparams.TestChainConfig, chain)
	defer pool.Stop()

	// Inject every transaction of both sides; all are executable at genesis.
	all := make([]*types.Transaction, 0, 2*stressReorgAccounts*stressReorgTxsPerAcct)
	for _, txs := range append(append([][]*types.Transaction{}, txsA...), txsB...) {
		all = append(all, txs...)
	}
	for i, err := range pool.AddRemotesSync(all) {
		if err != nil {
			t.Fatalf("tx %d: failed to add: %v", i, err)
		}
	}
	if pending, queued := pool.Stats(); pending != len(all) || queued != 0 {
		t.Fatalf("initial pool content mismatch: %d pending, %d queued, want %d/0", pending, queued, len(all))
	}
	minedSet := func(txs [][]*types.Transaction) map[util.Hash]bool {
		set := make(map[util.Hash]bool)
		for _, acct := range txs {
			for n := 0; n < stressReorgForkBlocks; n++ {
				set[acct[n].Hash()] = true
			}
		}
		return set
	}
	var (
		tips      = [2]*types.Block{forkA[len(forkA)-1], forkB[len(forkB)-1]}
		mined     = [2]map[util.Hash]bool{minedSet(txsA), minedSet(txsB)}
		wantTotal = len(all) - stressReorgAccounts*stressReorgForkBlocks
		cur       = genesis
	)
	for flip := 0; flip < stressReorgFlips; flip++ {
		next := tips[flip%2]
		chain.setHead(next)
		<-pool.requestReset(cur.Header(), next.Header())
		cur = next

		// The pool must hold exactly the transactions not mined on this head:
		// the current side's unmined tail plus everything of the other side
		// (reinjected by the reorg walk on the way back).
		pendingMap, queuedMap := pool.Content()
		total := 0
		for _, m := range []map[util.Address]types.Transactions{pendingMap, queuedMap} {
			for addr, txs := range m {
				for _, tx := range txs {
					if mined[flip%2][tx.Hash()] {
						t.Fatalf("flip %d: account %x: tx %x mined on current head still in pool", flip, addr, tx.Hash())
					}
					total++
				}
			}
		}
		if total != wantTotal {
			t.Fatalf("flip %d: pool content mismatch: have %d, want %d", flip, total, wantTotal)
		}
		// Every account's pending run must start exactly at its state nonce.
		statedb, err := chain.StateAt(next.Root())
		if err != nil {
			t.Fatalf("flip %d: failed to open head state: %v", flip, err)
		}
		for addr, txs := range pendingMap {
			if nonce := statedb.GetNonce(addr); txs[0].Nonce() != nonce {
				t.Fatalf("flip %d: account %x: pending starts at %d, state nonce %d", flip, addr, txs[0].Nonce(), nonce)
			}
		}
		stressCheckNonceCoherence(t, pool, pendingMap, queuedMap)

		if flip%stressReorgSampleEvery == 0 {
			if err := validateTxPoolInternals(pool); err != nil {
				t.Fatalf("flip %d: pool internal state corrupted: %v", flip, err)
			}
		}
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// stressOpsModel is the shadow model of one account in the random op stream
// test: the latest accepted transaction per nonce plus bookkeeping to pick
// deterministic operations without iterating Go maps.
type stressOpsModel struct {
	key      *ecdsa.PrivateKey
	addr     util.Address
	txs      map[uint64]*types.Transaction // latest accepted tx per nonce
	nonces   []uint64                      // distinct nonces in insertion order
	maxNonce uint64
}

// firstGap returns the smallest nonce not yet occupied by the model.
func (m *stressOpsModel) firstGap() uint64 {
	for n := uint64(0); n <= m.maxNonce; n++ {
		if m.txs[n] == nil {
			return n
		}
	}
	return m.maxNonce + 1
}

// hasGap reports whether a queued-causing hole exists below the highest nonce.
func (m *stressOpsModel) hasGap() bool {
	return len(m.nonces) > 0 && m.firstGap() < m.maxNonce
}

// TestStressPoolNonceGapsAndReplacements runs a seeded random op stream of
// adds, valid replacements, underpriced replacements and gap fills against the
// pool while tracking a shadow model, then compares full pending/queued
// membership against the model.
func TestStressPoolNonceGapsAndReplacements(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	rng := rand.New(rand.NewSource(stressPoolSeed))

	statedb, _ := state.New(util.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{100000000, statedb, new(event.Feed)}

	// Size the pool so nothing is ever evicted: membership must be governed
	// purely by the add/replace/promote rules under test.
	config := testTxPoolConfig
	config.AccountSlots = 1024
	config.AccountQueue = 2048
	config.GlobalSlots = 65536
	config.GlobalQueue = 65536

	pool := NewTxPool(config, chainparams.TestChainConfig, blockchain)
	defer pool.Stop()

	priceBump := int64(config.PriceBump)

	accounts := make([]*stressOpsModel, stressOpsAccounts)
	for i := range accounts {
		key, addr := stressKey(t, rng)
		testAddBalance(pool, addr, big.NewInt(1000000000000000))
		accounts[i] = &stressOpsModel{key: key, addr: addr, txs: make(map[uint64]*types.Transaction)}
	}
	// verifyAccount compares the pool's view of one account against the shadow
	// model: the contiguous prefix from nonce 0 must be pending, the rest
	// queued, with exactly matching transaction hashes.
	verifyAccount := func(context string, m *stressOpsModel) {
		pending, queued := pool.ContentFrom(m.addr)
		prefix := m.firstGap()
		if uint64(len(pending)) != prefix {
			t.Fatalf("%s: account %x: pending count mismatch: have %d, want %d", context, m.addr, len(pending), prefix)
		}
		for i, tx := range pending {
			want := m.txs[uint64(i)]
			if want == nil || tx.Hash() != want.Hash() {
				t.Fatalf("%s: account %x: pending nonce %d mismatch", context, m.addr, i)
			}
		}
		if want := len(m.nonces) - int(prefix); len(queued) != want {
			t.Fatalf("%s: account %x: queued count mismatch: have %d, want %d", context, m.addr, len(queued), want)
		}
		for _, tx := range queued {
			if tx.Nonce() < prefix {
				t.Fatalf("%s: account %x: queued nonce %d below pending prefix %d", context, m.addr, tx.Nonce(), prefix)
			}
			want := m.txs[tx.Nonce()]
			if want == nil || tx.Hash() != want.Hash() {
				t.Fatalf("%s: account %x: queued nonce %d mismatch", context, m.addr, tx.Nonce())
			}
		}
	}
	addAt := func(m *stressOpsModel, nonce uint64) {
		price := 100 + int64(rng.Intn(100))
		tx := pricedTransaction(nonce, 100000, big.NewInt(price), m.key)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("op add: account %x nonce %d: unexpected error: %v", m.addr, nonce, err)
		}
		m.txs[nonce] = tx
		m.nonces = append(m.nonces, nonce)
		if nonce > m.maxNonce {
			m.maxNonce = nonce
		}
	}
	var adds, bumps, unders, gapFills int
	for op := 0; op < stressOpsCount; op++ {
		m := accounts[rng.Intn(len(accounts))]
		roll := rng.Intn(100)

		doAdd := func() {
			nonce := m.firstGap()
			if len(m.nonces) > 0 && rng.Intn(2) == 0 {
				nonce = m.maxNonce + 1 + uint64(rng.Intn(3)) // may open a gap
			}
			addAt(m, nonce)
			adds++
		}
		doUnderpriced := func() {
			nonce := m.nonces[rng.Intn(len(m.nonces))]
			old := m.txs[nonce].GasPrice().Int64()
			// One below the required bump threshold; the different gas limit
			// changes the hash even when the price ties an earlier attempt.
			newPrice := old*(100+priceBump)/100 - 1
			tx := pricedTransaction(nonce, 100001, big.NewInt(newPrice), m.key)
			if err := pool.addRemoteSync(tx); err != ErrReplaceUnderpriced {
				t.Fatalf("op underpriced: account %x nonce %d: have %v, want %v", m.addr, nonce, err, ErrReplaceUnderpriced)
			}
			unders++
		}
		doBump := func() {
			nonce := m.nonces[rng.Intn(len(m.nonces))]
			old := m.txs[nonce].GasPrice().Int64()
			if old > stressOpsPriceCap {
				// Keep prices bounded; exercise the failure path instead.
				doUnderpriced()
				return
			}
			newPrice := old * (100 + priceBump) / 100 // exactly at the bump threshold
			tx := pricedTransaction(nonce, 100000, big.NewInt(newPrice), m.key)
			if err := pool.addRemoteSync(tx); err != nil {
				t.Fatalf("op bump: account %x nonce %d: %d -> %d: unexpected error: %v", m.addr, nonce, old, newPrice, err)
			}
			m.txs[nonce] = tx
			bumps++
		}
		switch {
		case len(m.nonces) == 0:
			doAdd()
		case roll < 35 && len(m.nonces) < stressOpsMaxPerAcct:
			doAdd()
		case roll < 60:
			doBump()
		case roll < 85:
			doUnderpriced()
		default:
			if m.hasGap() {
				// Fill the lowest hole and check that the queued run behind it
				// is promoted exactly.
				addAt(m, m.firstGap())
				gapFills++
				verifyAccount("gap fill", m)
			} else if len(m.nonces) < stressOpsMaxPerAcct {
				doAdd()
			} else {
				doBump()
			}
		}
		if op%stressOpsSampleEvery == 0 {
			verifyAccount("sample", m)
			if err := validateTxPoolInternals(pool); err != nil {
				t.Fatalf("op %d: pool internal state corrupted: %v", op, err)
			}
		}
	}
	if adds == 0 || bumps == 0 || unders == 0 || gapFills == 0 {
		t.Fatalf("op mix did not exercise all paths: adds %d, bumps %d, underpriced %d, gap fills %d", adds, bumps, unders, gapFills)
	}
	t.Logf("ops executed: %d adds, %d bumps, %d underpriced, %d gap fills", adds, bumps, unders, gapFills)

	// Final full comparison of the pool against the shadow model.
	modelTotal := 0
	for _, m := range accounts {
		verifyAccount("final", m)
		modelTotal += len(m.nonces)
	}
	pending, queued := pool.Stats()
	if pending+queued != modelTotal {
		t.Fatalf("final pool size mismatch: %d pending + %d queued != %d modeled", pending, queued, modelTotal)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}
