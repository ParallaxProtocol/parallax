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

package fees

import (
	"context"
	"math"
	"math/big"
	"sort"
	"sync"

	parampkg "github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/rpc"
	"github.com/ParallaxProtocol/parallax/v2/support/event"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	lru "github.com/hashicorp/golang-lru"
)

// sampleNumber is the number of transactions sampled per block in the
// legacy percentile algorithm.
const sampleNumber = 3

// Constants for the Bitcoin Core-style fee estimator (used when
// EnableSmartFeeEstimator is true). Since Parallax has the same ~10 minute
// block target as Bitcoin, these parameters apply directly.
const (
	// FEE_SPACING in Bitcoin Core: 1.05 (5% geometric spacing).
	feeSpacing = 1.05

	// SHORT: decay 0.962, half-life ~18 blocks (~3 hours).
	shortBlockPeriods = 12
	shortScale        = 1
	shortDecay        = 0.962

	// MED: decay 0.9952, half-life ~144 blocks (~1 day).
	medBlockPeriods = 24
	medScale        = 2
	medDecay        = 0.9952

	// LONG: decay 0.99931, half-life ~1008 blocks (~1 week).
	longBlockPeriods = 42
	longScale        = 24
	longDecay        = 0.99931

	// Success thresholds for estimateSmartFee.
	halfSuccessPct   = 0.6  // 60% required at target/2
	successPct       = 0.85 // 85% required at target
	doubleSuccessPct = 0.95 // 95% required at 2*target

	// Minimum data thresholds.
	sufficientFeeTxs  = 0.1 // for medium and long horizons
	sufficientTxShort = 0.5 // for short horizon (needs more data due to faster decay)

	// OLDEST_ESTIMATE_HISTORY: max blocks of history before data is considered stale.
	oldestEstimateHistory = 6 * 1008 // ~6 weeks

	// uncongestedBlocks is how many recent blocks FloorWhenUncongested looks
	// at, and uncongestedFullness the share of their gas limit they may use
	// between them for block space to count as free.
	uncongestedBlocks   = 12
	uncongestedFullness = 0.5
)

var (
	DefaultMaxPrice    = big.NewInt(1000 * parampkg.GWei)
	DefaultIgnorePrice = big.NewInt(2 * parampkg.Wei)
)

// Config contains the configuration for the gas price oracle.
type Config struct {
	// Legacy percentile algorithm parameters.
	Blocks           int
	Percentile       int
	MaxHeaderHistory int
	MaxBlockHistory  int
	Default          *big.Int `toml:",omitempty"`
	MaxPrice         *big.Int `toml:",omitempty"`
	IgnorePrice      *big.Int `toml:",omitempty"`

	// EnableSmartFeeEstimator selects the fee estimation algorithm:
	//   false (default) — legacy percentile-based oracle (geth original).
	//   true             — Bitcoin Core-style estimateSmartFee.
	EnableSmartFeeEstimator bool `toml:",omitempty"`

	// Bucket range configuration for the smart fee estimator
	// (spacing is always 1.05 per Bitcoin Core).
	MinBucketFee *big.Int `toml:",omitempty"`
	MaxBucketFee *big.Int `toml:",omitempty"`

	// FloorWhenUncongested makes SuggestTipCap return the minimum price
	// (Default) while recent blocks have plenty of room and the pending
	// block does too, as any fee that clears the miners' minimum then
	// confirms in the next block. Fee estimators learn only from the fees
	// transactions actually pay, so on a quiet chain they cannot see that
	// lower fees would also confirm, and keep recommending whatever the few
	// senders paid, which, when those senders follow the recommendation,
	// never comes down. Estimates resume as blocks fill.
	FloorWhenUncongested bool `toml:",omitempty"`
}

// OracleBackend includes all necessary background APIs for oracle.
type OracleBackend interface {
	HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error)
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error)
	GetReceipts(ctx context.Context, hash util.Hash) (types.Receipts, error)
	PendingBlockAndReceipts() (*types.Block, types.Receipts)
	ChainConfig() *parampkg.ChainConfig
	SubscribeChainHeadEvent(ch chan<- validation.ChainHeadEvent) event.Subscription
	// Synced reports whether the node has finished its initial sync. The smart
	// fee estimator gates block ingestion on this so that historical blocks
	// replayed during sync do not pollute the bucket statistics with stale
	// fee data.
	Synced() bool
}

// TxPoolAccessor provides mempool access to the smart fee estimator.
// Get is used by the per-block sweep that detects ghost entries (txs that
// were tracked in the mempool but later evicted/replaced/expired without the
// estimator being notified). Pass a literal nil — never a typed nil pointer —
// for light clients or when smart fee is disabled.
type TxPoolAccessor interface {
	SubscribeNewTxsEvent(chan<- validation.NewTxsEvent) event.Subscription
	Get(hash util.Hash) *types.Transaction
}

// EstimateMeta contains metadata about a fee estimation result.
type EstimateMeta struct {
	// DataBlocks is the approximate number of blocks of data the estimator
	// has consumed since startup. Useful as a "warm-up" indicator.
	DataBlocks int

	// SuccessRate is a LOWER BOUND on the modeled confirmation probability
	// at the returned fee, drawn from the success threshold of whichever
	// sub-estimate (60% / 85% / 95% conservative) produced the maximum.
	// The true confirmation probability may be higher because the chosen
	// fee is the max of multiple sub-estimates and therefore satisfies the
	// thresholds of all sub-estimates whose value is ≤ the chosen fee.
	// Zero when the result came from the legacy fallback or when no
	// sub-estimate produced a value.
	SuccessRate float64

	// LegacyFallback is true if the smart fee estimator had insufficient
	// data and the result came from the legacy percentile oracle.
	LegacyFallback bool
}

// txStatsInfo records mempool entry info for a tracked transaction
// (used by the smart fee estimator).
type txStatsInfo struct {
	blockHeight uint64
	bucketIndex int
}

// Oracle recommends gas prices using either the legacy percentile algorithm
// (geth original) or the Bitcoin Core-style estimateSmartFee algorithm,
// depending on the EnableSmartFeeEstimator config.
type Oracle struct {
	backend OracleBackend
	txPool  TxPoolAccessor // may be nil

	enableSmartFee bool
	// floorWhenUncongested mirrors Config.FloorWhenUncongested.
	floorWhenUncongested bool

	// Common price bounds.
	maxPrice     *big.Int
	defaultPrice *big.Int

	// --- Legacy percentile algorithm fields ---
	checkBlocks int
	percentile  int
	ignorePrice *big.Int
	fetchLock   sync.Mutex

	// --- Smart fee algorithm fields ---
	bucketBounds []float64 // upper bounds, including +Inf as last element
	shortStats   *txConfirmStats
	medStats     *txConfirmStats
	longStats    *txConfirmStats

	stateLock           sync.RWMutex
	pendingTxs          map[util.Hash]txStatsInfo
	recentlyConfirmed   map[util.Hash]uint64 // hash -> blockHeight; dedup for late mempool gossip
	nBestSeenHeight     uint64
	firstRecordedHeight uint64
	// lastBlockHash is the hash of the most recently processed block. Used
	// to detect reorgs and chain rewinds: a new block whose ParentHash !=
	// lastBlockHash means the chain has diverged. Zero before the first
	// processed block.
	lastBlockHash util.Hash

	// Fields for FeeHistory backward compatibility.
	maxHeaderHistory, maxBlockHistory int
	historyCache                      *lru.Cache

	// Cached estimation results (used by both algorithms).
	cacheLock       sync.RWMutex
	lastHead        util.Hash
	lastPrice       *big.Int                    // legacy single-value cache
	cachedEstimates map[int]cachedSmartEstimate // smart fee per-target cache; key is the post-clamp confTarget

	// Lifecycle.
	closeCh chan struct{}

	// sweepCh signals the async eviction sweep goroutine to run a sweep.
	// Buffered with capacity 1 so signals coalesce: if a sweep is already
	// pending the second signal is silently dropped. Created only when
	// smart fee is enabled and txPool != nil.
	sweepCh chan struct{}
}

// cachedSmartEstimate holds a smart fee estimate together with the metadata
// computed for it. The pair is invalidated atomically (cleared on every new
// block) so the metadata is always consistent with the estimate it
// accompanies. LegacyFallback results are intentionally not cached.
type cachedSmartEstimate struct {
	estimate *big.Int
	meta     EstimateMeta
}

// NewOracle returns a new gas price oracle.
// The txPool parameter is optional; pass a literal nil for light clients or
// when smart fee estimation is disabled (EnableSmartFeeEstimator = false).
// Do not pass a typed nil pointer — the per-block eviction sweep guards on
// `oracle.txPool != nil`, which treats typed nils as non-nil.
func NewOracle(backend OracleBackend, txPool TxPoolAccessor, params Config) *Oracle {
	// Sanitize legacy percentile algorithm fields.
	blocks := params.Blocks
	if blocks < 1 {
		blocks = 1
		logging.Warn("Sanitizing invalid gasprice oracle sample blocks", "provided", params.Blocks, "updated", blocks)
	}
	percent := params.Percentile
	if percent < 0 {
		percent = 0
		logging.Warn("Sanitizing invalid gasprice oracle sample percentile", "provided", params.Percentile, "updated", percent)
	} else if percent > 100 {
		percent = 100
		logging.Warn("Sanitizing invalid gasprice oracle sample percentile", "provided", params.Percentile, "updated", percent)
	}
	maxHeaderHistory := params.MaxHeaderHistory
	if maxHeaderHistory < 1 {
		maxHeaderHistory = 1
	}
	maxBlockHistory := params.MaxBlockHistory
	if maxBlockHistory < 1 {
		maxBlockHistory = 1
	}

	// Sanitize prices.
	maxPrice := params.MaxPrice
	if maxPrice == nil || maxPrice.Int64() <= 0 {
		maxPrice = DefaultMaxPrice
		logging.Warn("Sanitizing invalid gasprice oracle price cap", "provided", params.MaxPrice, "updated", maxPrice)
	}
	ignorePrice := params.IgnorePrice
	if ignorePrice == nil || ignorePrice.Int64() <= 0 {
		ignorePrice = DefaultIgnorePrice
	}
	defaultPrice := params.Default
	if defaultPrice == nil || defaultPrice.Sign() <= 0 {
		defaultPrice = big.NewInt(1 * parampkg.GWei)
	}

	cache, _ := lru.New(2048)
	oracle := &Oracle{
		backend:              backend,
		txPool:               txPool,
		enableSmartFee:       params.EnableSmartFeeEstimator,
		floorWhenUncongested: params.FloorWhenUncongested,
		maxPrice:             maxPrice,
		defaultPrice:         defaultPrice,
		ignorePrice:          ignorePrice,
		checkBlocks:          blocks,
		percentile:           percent,
		maxHeaderHistory:     maxHeaderHistory,
		maxBlockHistory:      maxBlockHistory,
		historyCache:         cache,
		lastPrice:            new(big.Int).Set(defaultPrice),
		closeCh:              make(chan struct{}),
	}

	if params.EnableSmartFeeEstimator {
		// Initialize smart fee estimator state.
		minBucketFee := params.MinBucketFee
		if minBucketFee == nil || minBucketFee.Sign() <= 0 {
			// Default to the miner's minimum gas price — no point generating
			// buckets below fees that will never be mined.
			minBucketFee = defaultPrice
		}
		maxBucketFee := params.MaxBucketFee
		if maxBucketFee == nil || maxBucketFee.Sign() <= 0 {
			maxBucketFee = maxPrice
		}

		// Generate bucket boundaries with FEE_SPACING = 1.05.
		minFee := float64(minBucketFee.Int64())
		maxFee := float64(maxBucketFee.Int64())
		var bucketBounds []float64
		for boundary := minFee; boundary <= maxFee; boundary *= feeSpacing {
			bucketBounds = append(bucketBounds, boundary)
		}
		bucketBounds = append(bucketBounds, math.Inf(1)) // INF bucket

		oracle.bucketBounds = bucketBounds
		oracle.shortStats = newTxConfirmStats(bucketBounds, shortBlockPeriods, shortDecay, shortScale)
		oracle.medStats = newTxConfirmStats(bucketBounds, medBlockPeriods, medDecay, medScale)
		oracle.longStats = newTxConfirmStats(bucketBounds, longBlockPeriods, longDecay, longScale)
		oracle.pendingTxs = make(map[util.Hash]txStatsInfo)
		oracle.recentlyConfirmed = make(map[util.Hash]uint64)
		oracle.cachedEstimates = make(map[int]cachedSmartEstimate)

		logging.Info("Gas price oracle initialized (smart fee)",
			"buckets", len(bucketBounds),
			"spacing", feeSpacing,
			"minBucket", minBucketFee,
			"maxBucket", maxBucketFee,
			"shortPeriods", shortBlockPeriods,
			"medPeriods", medBlockPeriods,
			"longPeriods", longBlockPeriods,
		)
	} else {
		logging.Info("Gas price oracle initialized (legacy)",
			"blocks", blocks, "percentile", percent,
			"maxPrice", maxPrice, "ignorePrice", ignorePrice,
		)
	}

	// Subscribe to chain head events. The block loop runs in both modes:
	// - Legacy mode: only invalidates the historyCache on reorgs.
	// - Smart fee mode: also runs the bucket tracking pipeline.
	headEvent := make(chan validation.ChainHeadEvent, 1)
	backend.SubscribeChainHeadEvent(headEvent)
	go oracle.blockLoop(headEvent)

	// Subscribe to mempool tx events only when smart fee is enabled and we
	// have a tx pool to subscribe to. Also start the async eviction sweep
	// goroutine — sweeps run out-of-band so a slow sweep cannot block the
	// chainHeadFeed (event.Feed.Send is a blocking send).
	if params.EnableSmartFeeEstimator && txPool != nil {
		oracle.sweepCh = make(chan struct{}, 1)
		go oracle.sweepLoop()

		txEvent := make(chan validation.NewTxsEvent, 64)
		txPool.SubscribeNewTxsEvent(txEvent)
		go oracle.txLoop(txEvent)
	}

	return oracle
}

// Close shuts down the oracle goroutines.
func (oracle *Oracle) Close() {
	close(oracle.closeCh)
}

// blockLoop processes new blocks. In legacy mode it only invalidates the
// historyCache on reorgs. In smart fee mode it also runs the bucket tracking
// and signals the async eviction sweep.
func (oracle *Oracle) blockLoop(headEvent chan validation.ChainHeadEvent) {
	var lastHead util.Hash
	for {
		select {
		case ev := <-headEvent:
			block := ev.Block
			if block.ParentHash() != lastHead {
				oracle.historyCache.Purge()
			}
			lastHead = block.Hash()
			if oracle.enableSmartFee {
				oracle.processNewBlock(block)
				// Signal the async eviction sweep. Non-blocking send into
				// a buffered channel: if a sweep is already pending, the
				// signal coalesces. Decoupling the sweep from this loop
				// keeps a slow sweep from blocking the chainHeadFeed.Send
				// path that other subscribers (txpool, miner) share.
				if oracle.sweepCh != nil {
					select {
					case oracle.sweepCh <- struct{}{}:
					default:
					}
				}
			}
		case <-oracle.closeCh:
			return
		}
	}
}

// txLoop processes new mempool transactions (smart fee mode only).
func (oracle *Oracle) txLoop(txEvent chan validation.NewTxsEvent) {
	for {
		select {
		case ev := <-txEvent:
			oracle.processTransaction(ev.Txs)
		case <-oracle.closeCh:
			return
		}
	}
}

// sweepLoop runs the eviction sweep asynchronously after each block. The
// sweep itself uses a 3-phase pattern (snapshot → query → apply) to
// minimise the time stateLock is held compared to an inline sweep.
func (oracle *Oracle) sweepLoop() {
	for {
		select {
		case <-oracle.sweepCh:
			oracle.sweepEvictedTxs()
		case <-oracle.closeCh:
			return
		}
	}
}

// sweepEvictedTxs removes pendingTxs entries that are no longer in the
// txpool: txs that were tracked when entering the mempool but later
// evicted, replaced (RBF), or expired without the estimator being notified.
//
// Implementation uses a 3-phase pattern to minimise stateLock holding time:
//
//  1. Snapshot pendingTxs hashes under brief read lock.
//  2. Query the txpool without holding any oracle lock.
//  3. Re-acquire write lock to apply deletes, re-verifying each entry to
//     handle the case where it was confirmed (and removed by
//     processBlockTx) or re-added (a fresh NewTxsEvent re-tracked it)
//     between phases 1 and 3.
func (oracle *Oracle) sweepEvictedTxs() {
	if oracle.txPool == nil {
		return
	}

	// Phase 1: snapshot pending hashes under a brief read lock.
	oracle.stateLock.RLock()
	toCheck := make([]util.Hash, 0, len(oracle.pendingTxs))
	for hash := range oracle.pendingTxs {
		toCheck = append(toCheck, hash)
	}
	oracle.stateLock.RUnlock()

	if len(toCheck) == 0 {
		return
	}

	// Phase 2: query the txpool without holding stateLock. Other writers
	// (processNewBlock, processTransaction) can run concurrently with this
	// phase.
	toRemove := make([]util.Hash, 0)
	for _, hash := range toCheck {
		if oracle.txPool.Get(hash) == nil {
			toRemove = append(toRemove, hash)
		}
	}
	if len(toRemove) == 0 {
		return
	}

	// Phase 3: apply deletes under the write lock. Re-verify each entry —
	// it may have been confirmed (and removed by processBlockTx) or
	// re-added (a fresh NewTxsEvent re-tracked it) between phases 1 and 3.
	oracle.stateLock.Lock()
	defer oracle.stateLock.Unlock()
	for _, hash := range toRemove {
		if _, exists := oracle.pendingTxs[hash]; !exists {
			continue
		}
		if oracle.txPool.Get(hash) != nil {
			continue // re-added between phases
		}
		oracle.removeTx(hash, false)
	}
}

//
// =============================================================================
// Legacy percentile algorithm (original geth implementation)
// =============================================================================
//

// suggestTipCapLegacy is the original geth percentile-based gas price oracle.
// It samples sampleNumber transactions from each of the last checkBlocks blocks,
// sorts them by effective gas tip, and returns the configured percentile.
func (oracle *Oracle) suggestTipCapLegacy(ctx context.Context) (*big.Int, error) {
	head, _ := oracle.backend.HeaderByNumber(ctx, rpc.LatestBlockNumber)
	headHash := head.Hash()

	// Return cached price if still valid.
	oracle.cacheLock.RLock()
	lastHead, lastPrice := oracle.lastHead, oracle.lastPrice
	oracle.cacheLock.RUnlock()
	if headHash == lastHead {
		return new(big.Int).Set(lastPrice), nil
	}
	oracle.fetchLock.Lock()
	defer oracle.fetchLock.Unlock()

	// Re-check cache after acquiring fetch lock.
	oracle.cacheLock.RLock()
	lastHead, lastPrice = oracle.lastHead, oracle.lastPrice
	oracle.cacheLock.RUnlock()
	if headHash == lastHead {
		return new(big.Int).Set(lastPrice), nil
	}

	var (
		sent, exp int
		number    = head.Number.Uint64()
		result    = make(chan results, oracle.checkBlocks)
		quit      = make(chan struct{})
		txValues  []*big.Int
	)
	for sent < oracle.checkBlocks && number > 0 {
		go oracle.getBlockValues(ctx, types.MakeSigner(oracle.backend.ChainConfig(), big.NewInt(int64(number))), number, sampleNumber, oracle.ignorePrice, result, quit)
		sent++
		exp++
		number--
	}
	for exp > 0 {
		res := <-result
		if res.err != nil {
			close(quit)
			return new(big.Int).Set(lastPrice), res.err
		}
		exp--
		// Empty block or only miner txs: use last cached price as filler.
		if len(res.values) == 0 {
			res.values = []*big.Int{lastPrice}
		}
		// If too little data, query more blocks (up to 2*checkBlocks).
		if len(res.values) == 1 && len(txValues)+1+exp < oracle.checkBlocks*2 && number > 0 {
			go oracle.getBlockValues(ctx, types.MakeSigner(oracle.backend.ChainConfig(), big.NewInt(int64(number))), number, sampleNumber, oracle.ignorePrice, result, quit)
			sent++
			exp++
			number--
		}
		txValues = append(txValues, res.values...)
	}
	price := lastPrice
	if len(txValues) > 0 {
		sort.Sort(bigIntArray(txValues))
		price = txValues[(len(txValues)-1)*oracle.percentile/100]
	}
	if price.Cmp(oracle.maxPrice) > 0 {
		price = new(big.Int).Set(oracle.maxPrice)
	}
	oracle.cacheLock.Lock()
	oracle.lastHead = headHash
	oracle.lastPrice = price
	oracle.cacheLock.Unlock()

	return new(big.Int).Set(price), nil
}

type results struct {
	values []*big.Int
	err    error
}

type txSorter struct {
	txs     []*types.Transaction
	baseFee *big.Int
}

func newSorter(txs []*types.Transaction, baseFee *big.Int) *txSorter {
	return &txSorter{txs: txs, baseFee: baseFee}
}

func (s *txSorter) Len() int { return len(s.txs) }
func (s *txSorter) Swap(i, j int) {
	s.txs[i], s.txs[j] = s.txs[j], s.txs[i]
}

func (s *txSorter) Less(i, j int) bool {
	tip1, _ := s.txs[i].EffectiveGasTip(s.baseFee)
	tip2, _ := s.txs[j].EffectiveGasTip(s.baseFee)
	return tip1.Cmp(tip2) < 0
}

// getBlockValues samples up to `limit` transactions from a block, sorted
// ascending by effective tip, and sends them on the result channel.
func (oracle *Oracle) getBlockValues(ctx context.Context, signer types.Signer, blockNum uint64, limit int, ignoreUnder *big.Int, result chan results, quit chan struct{}) {
	block, err := oracle.backend.BlockByNumber(ctx, rpc.BlockNumber(blockNum))
	if block == nil {
		select {
		case result <- results{nil, err}:
		case <-quit:
		}
		return
	}
	txs := make([]*types.Transaction, len(block.Transactions()))
	copy(txs, block.Transactions())
	sorter := newSorter(txs, block.BaseFee())
	sort.Sort(sorter)

	var prices []*big.Int
	for _, tx := range sorter.txs {
		tip, _ := tx.EffectiveGasTip(block.BaseFee())
		if ignoreUnder != nil && tip.Cmp(ignoreUnder) == -1 {
			continue
		}
		sender, err := types.Sender(signer, tx)
		if err == nil && sender != block.Coinbase() {
			prices = append(prices, tip)
			if len(prices) >= limit {
				break
			}
		}
	}
	select {
	case result <- results{prices, nil}:
	case <-quit:
	}
}

type bigIntArray []*big.Int

func (s bigIntArray) Len() int           { return len(s) }
func (s bigIntArray) Less(i, j int) bool { return s[i].Cmp(s[j]) < 0 }
func (s bigIntArray) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

//
// =============================================================================
// Bitcoin Core-style smart fee algorithm
// =============================================================================
//

// processTransaction records new mempool transactions for tracking.
// Equivalent to Bitcoin Core's CBlockPolicyEstimator::processTransaction.
func (oracle *Oracle) processTransaction(txs []*types.Transaction) {
	// Drop mempool events while the node is still syncing. processNewBlock
	// is gated the same way; if we accept tx events here we'd anchor every
	// new entry to a stale nBestSeenHeight, and the eventual confirmation
	// would record `blocksToConfirm > maxConfirms`. record() then bumps
	// txCtAvg/feeRateAvg without updating confAvg, dragging the bucket's
	// success rate down for no reason. After Synced() flips, txs that were
	// in the pool during sync will still be picked up via processBlockTx's
	// unknown-tx path the first time they appear in a block.
	if !oracle.backend.Synced() {
		return
	}

	oracle.stateLock.Lock()
	defer oracle.stateLock.Unlock()

	for _, tx := range txs {
		hash := tx.Hash()
		if _, exists := oracle.pendingTxs[hash]; exists {
			continue
		}
		// Drop late mempool gossip for txs we already saw confirmed in a
		// block. Without this guard, processBlockTx's unknown-tx path would
		// have correctly recorded the confirmation, then this loop would
		// re-track the same hash as an unconfirmed ghost.
		if _, confirmed := oracle.recentlyConfirmed[hash]; confirmed {
			continue
		}

		gasPrice := tx.GasPrice()
		if gasPrice.Cmp(oracle.defaultPrice) < 0 {
			continue
		}

		feerate := float64(gasPrice.Int64())
		blockHeight := oracle.nBestSeenHeight

		bucketIdx := oracle.shortStats.newTx(blockHeight, feerate)
		oracle.medStats.newTx(blockHeight, feerate)
		oracle.longStats.newTx(blockHeight, feerate)

		oracle.pendingTxs[hash] = txStatsInfo{
			blockHeight: blockHeight,
			bucketIndex: bucketIdx,
		}

		logging.Debug("Fee estimator: tracking new mempool tx",
			"tx", hash.Hex()[:10], "gasPrice", gasPrice,
			"bucket", bucketIdx, "entryBlock", blockHeight,
		)
	}
}

// removeTx removes a transaction from tracking.
func (oracle *Oracle) removeTx(hash util.Hash, inBlock bool) bool {
	info, exists := oracle.pendingTxs[hash]
	if !exists {
		return false
	}

	oracle.shortStats.removeTx(info.blockHeight, oracle.nBestSeenHeight, info.bucketIndex, inBlock)
	oracle.medStats.removeTx(info.blockHeight, oracle.nBestSeenHeight, info.bucketIndex, inBlock)
	oracle.longStats.removeTx(info.blockHeight, oracle.nBestSeenHeight, info.bucketIndex, inBlock)
	delete(oracle.pendingTxs, hash)
	return true
}

// processBlockTx handles a single confirmed transaction from a block.
// Returns true if the transaction contributed a confirmation recording.
//
// There are two paths:
//
//  1. Known: the tx was previously seen via processTransaction. Remove it
//     from the unconfirmed tracking and record the confirmation latency.
//
//  2. Unknown: the block arrived before mempool gossip and the estimator
//     never saw the tx. Record it as a one-block confirmation directly via
//     `record(1, feerate)` — calling newTx+removeTx would cancel out
//     because removeTx(inBlock=true) is the inverse of newTx for the
//     unconfirmed counters.
//
// In both paths the hash is added to recentlyConfirmed so a late
// NewTxsEvent for the same tx is dropped instead of becoming a ghost.
func (oracle *Oracle) processBlockTx(blockHeight uint64, tx *types.Transaction) bool {
	hash := tx.Hash()
	info, exists := oracle.pendingTxs[hash]

	if exists {
		oracle.removeTx(hash, true)
		// Always remember the hash, even when we cannot record latency
		// (blocksToConfirm <= 0): a late NewTxsEvent must still be dropped.
		oracle.recentlyConfirmed[hash] = blockHeight

		blocksToConfirm := int(blockHeight) - int(info.blockHeight)
		if blocksToConfirm <= 0 {
			logging.Debug("Fee estimator: blocksToConfirm <= 0, ignoring", "hash", hash.Hex()[:10])
			return false
		}

		feerate := float64(tx.GasPrice().Int64())
		oracle.shortStats.record(blocksToConfirm, feerate)
		oracle.medStats.record(blocksToConfirm, feerate)
		oracle.longStats.record(blocksToConfirm, feerate)

		logging.Debug("Fee estimator: tracked tx confirmed",
			"tx", hash.Hex()[:10],
			"blocksToConfirm", blocksToConfirm,
			"gasPrice", tx.GasPrice(),
		)
		return true
	}

	// Unknown tx — block arrived before the mempool gossip. Treat it as a
	// one-block confirmation. Apply the same defaultPrice filter as
	// processTransaction so the two ingestion paths agree on which txs
	// influence the estimator.
	gasPrice := tx.GasPrice()
	if gasPrice.Cmp(oracle.defaultPrice) < 0 {
		return false
	}

	feerate := float64(gasPrice.Int64())
	oracle.shortStats.record(1, feerate)
	oracle.medStats.record(1, feerate)
	oracle.longStats.record(1, feerate)
	oracle.recentlyConfirmed[hash] = blockHeight

	logging.Debug("Fee estimator: untracked tx confirmed in block",
		"tx", hash.Hex()[:10],
		"gasPrice", gasPrice,
	)
	return true
}

// recentlyConfirmedRetention bounds how long a confirmed tx hash is
// remembered for late mempool gossip dedup. Far longer than any realistic
// gossip delay, but bounded so the map cannot grow without limit.
const recentlyConfirmedRetention = 12

// resetSmartFeeStateLocked clears all smart fee state and re-initializes
// the bucket statistics. Called when the chain rewinds (debug_setHead or a
// deep reorg) so that the oracle does not stay stranded at a height that
// the chain has moved away from.
//
// MUST be called with stateLock held for write.
func (oracle *Oracle) resetSmartFeeStateLocked() {
	logging.Warn("Fee estimator: resetting smart fee state",
		"oldHeight", oracle.nBestSeenHeight,
		"oldHead", oracle.lastBlockHash,
	)
	oracle.pendingTxs = make(map[util.Hash]txStatsInfo)
	oracle.recentlyConfirmed = make(map[util.Hash]uint64)
	oracle.nBestSeenHeight = 0
	oracle.firstRecordedHeight = 0
	oracle.lastBlockHash = util.Hash{}

	oracle.shortStats = newTxConfirmStats(oracle.bucketBounds, shortBlockPeriods, shortDecay, shortScale)
	oracle.medStats = newTxConfirmStats(oracle.bucketBounds, medBlockPeriods, medDecay, medScale)
	oracle.longStats = newTxConfirmStats(oracle.bucketBounds, longBlockPeriods, longDecay, longScale)

	// Invalidate the cached estimates. Same lock-order as processNewBlock:
	// stateLock (held by caller) → cacheLock.
	oracle.cacheLock.Lock()
	oracle.cachedEstimates = make(map[int]cachedSmartEstimate)
	oracle.cacheLock.Unlock()
}

// processNewBlock handles a new block: updates circular buffers, applies decay,
// and processes confirmed transactions.
// Equivalent to Bitcoin Core's CBlockPolicyEstimator::processBlock.
func (oracle *Oracle) processNewBlock(block *types.Block) {
	oracle.stateLock.Lock()
	defer oracle.stateLock.Unlock()

	blockHeight := block.NumberU64()
	blockHash := block.Hash()

	// Same hash → already processed, nothing to do.
	if blockHash == oracle.lastBlockHash {
		return
	}

	// Skip blocks while the node is still syncing. The downloader fires one
	// ChainHeadEvent per InsertChain batch during sync; processing those would
	// pollute the estimator with historical fee data that has nothing to do
	// with current market conditions. Once Synced() returns true it stays
	// true, so this gate only fires during initial sync. Advance
	// nBestSeenHeight so the first post-sync block is recognized as new.
	//
	// On a restart of an already-synced node, the very first live block may
	// also be skipped by this gate: handler.go fires the ChainHeadEvent for
	// that block before flipping acceptTxs. We accept the loss of one block
	// of recording data — the next block resumes normal processing.
	if !oracle.backend.Synced() {
		oracle.nBestSeenHeight = blockHeight
		oracle.lastBlockHash = blockHash
		return
	}

	// Chain rewind detection (#9). A new block at lower height than what we
	// have already processed means the chain has been forcibly moved
	// backwards — either via debug_setHead RPC, or a deep reorg whose
	// canonical tip lies below our recorded tip. Without this branch the
	// height check below would silently skip every subsequent block until
	// the chain re-caught up to oracle.nBestSeenHeight, leaving the
	// estimator stranded.
	if blockHeight < oracle.nBestSeenHeight {
		logging.Warn("Fee estimator: chain rewind detected, resetting state",
			"oldHeight", oracle.nBestSeenHeight, "newHeight", blockHeight,
			"oldHead", oracle.lastBlockHash, "newHead", blockHash,
		)
		oracle.resetSmartFeeStateLocked()
		// Fall through to process the new block from a clean slate.
	}

	// Same-height shallow reorg: the new block is at the same height as the
	// last processed block but has a different hash. Re-running clearCurrent
	// and updateMovingAverages at the same height would double-decay the
	// stats, so log and skip. The new chain's fork-point txs are missed —
	// same limitation as Bitcoin Core.
	if blockHeight == oracle.nBestSeenHeight && blockHeight != 0 {
		logging.Warn("Fee estimator: same-height reorg, skipping (would double-decay)",
			"height", blockHeight,
			"oldHead", oracle.lastBlockHash, "newHead", blockHash,
		)
		oracle.lastBlockHash = blockHash
		return
	}

	// Reorg detection for forward-progress reorgs (#8). The new block is
	// strictly higher than the previous head but its parent is not the
	// previous head — a longer-chain reorg replaced one or more recent
	// blocks. We process the new tip normally; intermediate blocks of the
	// new chain are not re-fetched (Bitcoin Core has the same limitation).
	if oracle.lastBlockHash != (util.Hash{}) && block.ParentHash() != oracle.lastBlockHash {
		logging.Warn("Fee estimator: forward reorg detected",
			"oldHeight", oracle.nBestSeenHeight, "newHeight", blockHeight,
			"oldHead", oracle.lastBlockHash, "newHead", blockHash,
			"newParent", block.ParentHash(),
		)
	}

	if blockHeight <= oracle.nBestSeenHeight {
		// Older or equal-height block that did not trigger any of the
		// branches above (e.g., very old straggler). Drop it.
		return
	}

	oracle.nBestSeenHeight = blockHeight
	oracle.lastBlockHash = blockHash

	oracle.shortStats.clearCurrent(blockHeight)
	oracle.medStats.clearCurrent(blockHeight)
	oracle.longStats.clearCurrent(blockHeight)

	oracle.shortStats.updateMovingAverages()
	oracle.medStats.updateMovingAverages()
	oracle.longStats.updateMovingAverages()

	countedTxs := 0
	for _, tx := range block.Transactions() {
		if oracle.processBlockTx(blockHeight, tx) {
			countedTxs++
		}
	}

	if oracle.firstRecordedHeight == 0 && countedTxs > 0 {
		oracle.firstRecordedHeight = blockHeight
		logging.Info("Fee estimator: first recorded height", "height", blockHeight)
	}

	// (eviction sweep removed from inline path; runs asynchronously via
	// sweepLoop, signaled by blockLoop after this function returns. This
	// keeps a slow sweep from blocking the chainHeadFeed.)

	// Prune the late-gossip dedup map. Entries older than
	// recentlyConfirmedRetention blocks are no longer load-bearing.
	if blockHeight > recentlyConfirmedRetention {
		cutoff := blockHeight - recentlyConfirmedRetention
		for h, confirmedAt := range oracle.recentlyConfirmed {
			if confirmedAt < cutoff {
				delete(oracle.recentlyConfirmed, h)
			}
		}
	}

	// Clean up very old pending entries as failures.
	if blockHeight > oldestEstimateHistory {
		cutoff := blockHeight - oldestEstimateHistory
		for hash, info := range oracle.pendingTxs {
			if info.blockHeight < cutoff {
				oracle.removeTx(hash, false)
			}
		}
	}

	logging.Debug("Fee estimator: block processed",
		"block", blockHeight,
		"confirmedTracked", countedTxs,
		"blockTxs", len(block.Transactions()),
		"pendingTracked", len(oracle.pendingTxs),
	)

	// Invalidate the smart-fee per-target cache. Do NOT touch lastHead /
	// lastPrice — those belong to the legacy percentile oracle's cache and
	// must be updated together (suggestTipCapLegacy is the only writer that
	// keeps them consistent). Writing lastHead here without lastPrice would
	// poison the legacy cache: a subsequent legacy fallback would see
	// headHash == lastHead, return the stale lastPrice (initialized to
	// defaultPrice), and never recompute.
	oracle.cacheLock.Lock()
	oracle.cachedEstimates = make(map[int]cachedSmartEstimate)
	oracle.cacheLock.Unlock()
}

func (oracle *Oracle) blockSpan() uint64 {
	if oracle.firstRecordedHeight == 0 {
		return 0
	}
	return oracle.nBestSeenHeight - oracle.firstRecordedHeight
}

func (oracle *Oracle) maxUsableEstimate() int {
	maxConf := oracle.longStats.getMaxConfirms()
	span := int(oracle.blockSpan())
	usable := span / 2
	if usable > maxConf {
		return maxConf
	}
	if usable < 1 {
		return 1
	}
	return usable
}

func (oracle *Oracle) estimateCombinedFee(confTarget int, successThreshold float64, checkShorterHorizon bool) float64 {
	estimate := float64(-1)

	if confTarget >= 1 && confTarget <= oracle.longStats.getMaxConfirms() {
		if confTarget <= oracle.shortStats.getMaxConfirms() {
			estimate = oracle.shortStats.estimateMedianVal(confTarget, sufficientTxShort, successThreshold, oracle.nBestSeenHeight)
		} else if confTarget <= oracle.medStats.getMaxConfirms() {
			estimate = oracle.medStats.estimateMedianVal(confTarget, sufficientFeeTxs, successThreshold, oracle.nBestSeenHeight)
		} else {
			estimate = oracle.longStats.estimateMedianVal(confTarget, sufficientFeeTxs, successThreshold, oracle.nBestSeenHeight)
		}

		if checkShorterHorizon {
			if confTarget > oracle.medStats.getMaxConfirms() {
				medMax := oracle.medStats.estimateMedianVal(oracle.medStats.getMaxConfirms(), sufficientFeeTxs, successThreshold, oracle.nBestSeenHeight)
				if medMax > 0 && (estimate == -1 || medMax < estimate) {
					estimate = medMax
				}
			}
			if confTarget > oracle.shortStats.getMaxConfirms() {
				shortMax := oracle.shortStats.estimateMedianVal(oracle.shortStats.getMaxConfirms(), sufficientTxShort, successThreshold, oracle.nBestSeenHeight)
				if shortMax > 0 && (estimate == -1 || shortMax < estimate) {
					estimate = shortMax
				}
			}
		}
	}
	return estimate
}

func (oracle *Oracle) estimateConservativeFee(doubleTarget int) float64 {
	estimate := float64(-1)

	if doubleTarget <= oracle.shortStats.getMaxConfirms() {
		estimate = oracle.medStats.estimateMedianVal(doubleTarget, sufficientFeeTxs, doubleSuccessPct, oracle.nBestSeenHeight)
	}
	if doubleTarget <= oracle.medStats.getMaxConfirms() {
		longEst := oracle.longStats.estimateMedianVal(doubleTarget, sufficientFeeTxs, doubleSuccessPct, oracle.nBestSeenHeight)
		if longEst > estimate {
			estimate = longEst
		}
	}
	return estimate
}

// clampConfTargetLocked applies the static + dynamic clamps that map a
// caller-supplied confTarget to its effective value. Two inputs that clamp
// to the same value compute identical estimates and should share a cache
// entry.
//
// MUST be called with stateLock held (Read or Write) — reads
// nBestSeenHeight and firstRecordedHeight via maxUsableEstimate.
//
// Returns (clamped, false) on success or (0, true) when the data is
// insufficient and the caller should fall back.
func (oracle *Oracle) clampConfTargetLocked(confTarget int) (int, bool) {
	maxTarget := oracle.longStats.getMaxConfirms()
	if confTarget <= 0 {
		confTarget = 2
	} else if confTarget > maxTarget {
		confTarget = maxTarget
	}
	if confTarget == 1 {
		confTarget = 2
	}
	if maxUsable := oracle.maxUsableEstimate(); confTarget > maxUsable {
		confTarget = maxUsable
	}
	if confTarget <= 1 {
		return 0, true
	}
	return confTarget, false
}

// estimateSmartFeeBitcoin returns the max of fee estimates calculated with:
//   - 60% threshold at target/2
//   - 85% threshold at target
//   - 95% threshold at 2*target
//   - conservative 95% at 2*target across longer horizons
//
// This is a direct port of Bitcoin Core's CBlockPolicyEstimator::estimateSmartFee.
//
// Cache coherency: this function holds stateLock.RLock from before the
// computation through the cache write back. processNewBlock — the only
// writer that clears the cache — requires stateLock.Lock (mutually
// exclusive with RLock), so it cannot interleave between a reader's
// compute and the corresponding cache write. The cache value is therefore
// always consistent with the state under which it was computed; the only
// "staleness" possible is the unavoidable one where a block has fired its
// ChainHeadEvent but blockLoop has not yet drained the channel.
//
// Cache key: the post-clamp confTarget is used as the cache key, so
// callers passing different inputs that clamp to the same effective target
// (e.g., 0, 1, 2 → 2) share a single cache entry instead of recomputing
// the same answer under three keys.
func (oracle *Oracle) estimateSmartFeeBitcoin(ctx context.Context, confTarget int) (*big.Int, *EstimateMeta, error) {
	logging.Info("Fee estimator: EstimateSmartFee called (smart fee)", "confTarget", confTarget)

	// Acquire stateLock first so we can compute the clamped target and use
	// it as the cache key. Lock order: stateLock → cacheLock, matching
	// processNewBlock so there is no inversion risk.
	oracle.stateLock.RLock()
	defer oracle.stateLock.RUnlock()

	clampedTarget, insufficient := oracle.clampConfTargetLocked(confTarget)
	if insufficient {
		logging.Info("Fee estimator: insufficient data (confTarget clamped to ≤1)", "default", oracle.defaultPrice)
		return new(big.Int).Set(oracle.defaultPrice), &EstimateMeta{LegacyFallback: true}, nil
	}

	// Cache lookup using the clamped target.
	oracle.cacheLock.RLock()
	if cached, ok := oracle.cachedEstimates[clampedTarget]; ok {
		oracle.cacheLock.RUnlock()
		logging.Info("Fee estimator: returning cached estimate", "confTarget", clampedTarget, "gasPrice", cached.estimate)
		// Copy the estimate to avoid the caller mutating the cached *big.Int.
		// The meta is a value type so the assignment already copies it.
		metaCopy := cached.meta
		return new(big.Int).Set(cached.estimate), &metaCopy, nil
	}
	oracle.cacheLock.RUnlock()

	confTarget = clampedTarget

	median := float64(-1)
	// Track the success threshold of whichever sub-estimate produced the
	// maximum. Reported via EstimateMeta.SuccessRate as a lower bound on
	// the modeled confirmation probability at the returned fee.
	winningSuccessRate := 0.0

	halfEst := oracle.estimateCombinedFee(confTarget/2, halfSuccessPct, true)
	if halfEst > median {
		median = halfEst
		winningSuccessRate = halfSuccessPct
	}

	actualEst := oracle.estimateCombinedFee(confTarget, successPct, true)
	if actualEst > median {
		median = actualEst
		winningSuccessRate = successPct
	}

	doubleEst := oracle.estimateCombinedFee(2*confTarget, doubleSuccessPct, true)
	if doubleEst > median {
		median = doubleEst
		winningSuccessRate = doubleSuccessPct
	}

	consEst := oracle.estimateConservativeFee(2 * confTarget)
	if consEst > median {
		median = consEst
		winningSuccessRate = doubleSuccessPct
	}

	logging.Info("Fee estimator: sub-estimates",
		"halfEst", halfEst, "actualEst", actualEst,
		"doubleEst", doubleEst, "consEst", consEst,
		"median", median,
	)

	// If all four sub-estimates returned -1, we have no data. Signal the
	// caller via LegacyFallback so it can substitute the legacy percentile
	// oracle result. Don't cache fallback results — the next call should
	// recompute once smart fee has accumulated data.
	if median < 0 {
		logging.Info("Fee estimator: no estimate available, signaling legacy fallback", "default", oracle.defaultPrice)
		return new(big.Int).Set(oracle.defaultPrice), &EstimateMeta{LegacyFallback: true}, nil
	}

	result := new(big.Int).SetInt64(int64(math.Round(median)))

	if result.Cmp(oracle.defaultPrice) < 0 {
		logging.Info("Fee estimator: clamping to minimum", "result", result, "floor", oracle.defaultPrice)
		result = new(big.Int).Set(oracle.defaultPrice)
	}
	if result.Cmp(oracle.maxPrice) > 0 {
		logging.Info("Fee estimator: clamping to maximum", "result", result, "cap", oracle.maxPrice)
		result = new(big.Int).Set(oracle.maxPrice)
	}

	logging.Info("Fee estimator: final result",
		"confTarget", confTarget, "gasPrice", result,
		"lastBlock", oracle.nBestSeenHeight,
		"blockSpan", oracle.blockSpan(),
		"pendingTracked", len(oracle.pendingTxs),
	)

	meta := EstimateMeta{
		DataBlocks:  int(oracle.blockSpan()),
		SuccessRate: winningSuccessRate,
	}

	// Cache the (estimate, meta) pair under the clamped target so the next
	// call sees the same metadata as a cache hit. The pair is invalidated
	// atomically by processNewBlock on every block.
	oracle.cacheLock.Lock()
	oracle.cachedEstimates[confTarget] = cachedSmartEstimate{
		estimate: new(big.Int).Set(result),
		meta:     meta,
	}
	oracle.cacheLock.Unlock()

	return new(big.Int).Set(result), &meta, nil
}

//
// =============================================================================
// Public API (dispatches based on enableSmartFee flag)
// =============================================================================
//

// blockSpaceFree reports whether the last uncongestedBlocks blocks used at
// most uncongestedFullness of their combined gas limit and the pending block,
// when there is one, is no fuller: then the next block has room for every
// transaction waiting and a minimum-price transaction confirms in it.
func (oracle *Oracle) blockSpaceFree(ctx context.Context) bool {
	head, err := oracle.backend.HeaderByNumber(ctx, rpc.LatestBlockNumber)
	if err != nil || head == nil {
		return false
	}
	var used, limit float64
	for number, i := head.Number.Uint64(), 0; i < uncongestedBlocks; number, i = number-1, i+1 {
		header, err := oracle.backend.HeaderByNumber(ctx, rpc.BlockNumber(number))
		if err != nil || header == nil {
			return false
		}
		used += float64(header.GasUsed)
		limit += float64(header.GasLimit)
		if number == 0 {
			break
		}
	}
	if limit == 0 || used > limit*uncongestedFullness {
		return false
	}
	if pending, _ := oracle.backend.PendingBlockAndReceipts(); pending != nil && pending.GasLimit() > 0 {
		if float64(pending.GasUsed()) > float64(pending.GasLimit())*uncongestedFullness {
			return false
		}
	}
	return true
}

// SuggestTipCap returns a tip cap so that newly created transactions have a
// high chance of being included in the next few blocks.
//
// With FloorWhenUncongested, it first returns the minimum price while block
// space is free (see blockSpaceFree): estimators cannot see that cheaper
// transactions would confirm when nobody sends them.
//
// When EnableSmartFeeEstimator is false, uses the legacy percentile algorithm.
// When true, uses the Bitcoin Core-style smart fee estimator with a 2-block
// confirmation target. If the smart fee estimator has insufficient data (cold
// start or sparse traffic), it automatically falls back to the legacy
// percentile oracle for a market-aware answer rather than returning the
// configured minimum.
func (oracle *Oracle) SuggestTipCap(ctx context.Context) (*big.Int, error) {
	if oracle.floorWhenUncongested && oracle.blockSpaceFree(ctx) {
		return new(big.Int).Set(oracle.defaultPrice), nil
	}
	if !oracle.enableSmartFee {
		return oracle.suggestTipCapLegacy(ctx)
	}
	estimate, meta, err := oracle.estimateSmartFeeBitcoin(ctx, 2)
	if err != nil {
		logging.Error("Fee estimator: SuggestTipCap failed", "err", err)
		return nil, err
	}
	if meta.LegacyFallback {
		logging.Info("Fee estimator: smart fee has no data, falling back to legacy oracle")
		if legacyEstimate, legacyErr := oracle.suggestTipCapLegacy(ctx); legacyErr == nil {
			return legacyEstimate, nil
		}
		// Legacy also failed; return the smart fee default as last resort.
	}
	return estimate, nil
}

// EstimateSmartFee returns a recommended gas price for a transaction to be
// confirmed within confTarget blocks, along with metadata.
//
// When EnableSmartFeeEstimator is true, this uses the Bitcoin Core algorithm.
// If the smart fee estimator has insufficient data, it falls back to the
// legacy percentile oracle and sets EstimateMeta.LegacyFallback = true.
// When EnableSmartFeeEstimator is false, the confTarget is ignored and the
// legacy percentile result is returned.
func (oracle *Oracle) EstimateSmartFee(ctx context.Context, confTarget int) (*big.Int, *EstimateMeta, error) {
	if oracle.enableSmartFee {
		estimate, meta, err := oracle.estimateSmartFeeBitcoin(ctx, confTarget)
		if err != nil {
			return nil, nil, err
		}
		if meta.LegacyFallback {
			logging.Info("Fee estimator: smart fee has no data, falling back to legacy oracle", "confTarget", confTarget)
			if legacyEstimate, legacyErr := oracle.suggestTipCapLegacy(ctx); legacyErr == nil {
				return legacyEstimate, &EstimateMeta{LegacyFallback: true}, nil
			}
			// Legacy also failed; return the smart fee default as last resort.
		}
		return estimate, meta, nil
	}
	// Legacy mode: ignore confTarget, return the percentile-based suggestion.
	tip, err := oracle.suggestTipCapLegacy(ctx)
	if err != nil {
		return nil, nil, err
	}
	return tip, &EstimateMeta{}, nil
}
