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
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/kernel/xhash"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/rpc"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/support/event"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"
)

const testHead = 32

type testBackend struct {
	chain   *validation.BlockChain
	pending bool
}

func (b *testBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if number > testHead {
		return nil, nil
	}
	if number == rpc.LatestBlockNumber {
		number = testHead
	}
	if number == rpc.PendingBlockNumber {
		if b.pending {
			number = testHead + 1
		} else {
			return nil, nil
		}
	}
	return b.chain.GetHeaderByNumber(uint64(number)), nil
}

func (b *testBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	if number > testHead {
		return nil, nil
	}
	if number == rpc.LatestBlockNumber {
		number = testHead
	}
	if number == rpc.PendingBlockNumber {
		if b.pending {
			number = testHead + 1
		} else {
			return nil, nil
		}
	}
	return b.chain.GetBlockByNumber(uint64(number)), nil
}

func (b *testBackend) GetReceipts(ctx context.Context, hash util.Hash) (types.Receipts, error) {
	return b.chain.GetReceiptsByHash(hash), nil
}

func (b *testBackend) PendingBlockAndReceipts() (*types.Block, types.Receipts) {
	if b.pending {
		block := b.chain.GetBlockByNumber(testHead + 1)
		return block, b.chain.GetReceiptsByHash(block.Hash())
	}
	return nil, nil
}

func (b *testBackend) ChainConfig() *chainparams.ChainConfig {
	return b.chain.Config()
}

func (b *testBackend) SubscribeChainHeadEvent(ch chan<- validation.ChainHeadEvent) event.Subscription {
	return nil
}

// Synced satisfies gasprice.OracleBackend. Tests are always considered synced
// so processNewBlock is exercised end-to-end without a sync gate.
func (b *testBackend) Synced() bool { return true }

func newTestBackend(t *testing.T, londonBlock *big.Int, pending bool) *testBackend {
	return newTestBackendWithGasLimit(t, londonBlock, pending, 0)
}

// newTestBackendWithGasLimit builds the test chain with a genesis gas limit,
// or the default when zero. Each block holds one 21000 gas transfer, so a
// small limit gives full blocks.
func newTestBackendWithGasLimit(t *testing.T, londonBlock *big.Int, pending bool, gasLimit uint64) *testBackend {
	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = *chainparams.TestChainConfig
		gspec  = &validation.Genesis{
			Config: &config,
			Alloc:  validation.GenesisAlloc{addr: {Balance: big.NewInt(math.MaxInt64)}},
		}
		signer = types.LatestSigner(gspec.Config)
	)
	config.LondonBlock = londonBlock
	if gasLimit > 0 {
		gspec.GasLimit = gasLimit
	}
	engine := xhash.NewFaker()
	db := rawdb.NewMemoryDatabase()
	genesis, err := gspec.Commit(db)
	if err != nil {
		t.Fatal(err)
	}
	blocks, _ := validation.GenerateChain(gspec.Config, genesis, engine, db, testHead+1, func(i int, b *validation.BlockGen) {
		b.SetCoinbase(util.Address{1})

		var txdata types.TxData
		if londonBlock != nil && b.Number().Cmp(londonBlock) >= 0 {
			txdata = &types.DynamicFeeTx{
				ChainID:   gspec.Config.ChainID,
				Nonce:     b.TxNonce(addr),
				To:        &util.Address{},
				Gas:       30000,
				GasFeeCap: big.NewInt(100 * chainparams.GWei),
				GasTipCap: big.NewInt(int64(i+1) * chainparams.GWei),
				Data:      []byte{},
			}
		} else {
			txdata = &types.LegacyTx{
				Nonce:    b.TxNonce(addr),
				To:       &util.Address{},
				Gas:      21000,
				GasPrice: big.NewInt(int64(i+1) * chainparams.GWei),
				Value:    big.NewInt(100),
				Data:     []byte{},
			}
		}
		b.AddTx(types.MustSignNewTx(key, signer, txdata))
	})
	diskdb := rawdb.NewMemoryDatabase()
	gspec.Commit(diskdb)
	chain, err := validation.NewBlockChain(diskdb, &validation.CacheConfig{TrieCleanNoPrefetch: true}, gspec.Config, engine, script.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create local chain, %v", err)
	}
	chain.InsertChain(blocks)
	return &testBackend{chain: chain, pending: pending}
}

func (b *testBackend) CurrentHeader() *types.Header {
	return b.chain.CurrentHeader()
}

func (b *testBackend) GetBlockByNumber(number uint64) *types.Block {
	return b.chain.GetBlockByNumber(number)
}

// smartFeeConfig returns a Config with the Bitcoin Core algorithm enabled.
func smartFeeConfig() Config {
	return Config{
		Default:                 big.NewInt(chainparams.GWei),
		EnableSmartFeeEstimator: true,
	}
}

// TestSuggestTipCapLegacy tests the legacy percentile-based oracle.
// With Blocks=3, Percentile=60, the oracle's retry logic samples up to
// 2*Blocks=6 blocks (each test block has 1 tx). Tips collected are
// [27,28,29,30,31,32]; the 60th percentile is index 3 → 30G.
func TestSuggestTipCapLegacy(t *testing.T) {
	config := Config{
		Blocks:     3,
		Percentile: 60,
		Default:    big.NewInt(chainparams.GWei),
	}
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, config)
	defer oracle.Close()

	got, err := oracle.SuggestTipCap(context.Background())
	if err != nil {
		t.Fatalf("SuggestTipCap error: %v", err)
	}
	expected := big.NewInt(30 * chainparams.GWei)
	if got.Cmp(expected) != 0 {
		t.Fatalf("Legacy SuggestTipCap mismatch, want %d, got %d", expected, got)
	}
}

// TestSuggestTipCapSmartFeeColdStart tests smart fee cold start behavior.
// With no confirmation data, the smart fee estimator falls back to the legacy
// percentile oracle. The result should be a market-aware value (from the test
// backend's block history), not the configured minimum.
func TestSuggestTipCapSmartFeeColdStart(t *testing.T) {
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, smartFeeConfig())
	defer oracle.Close()

	got, err := oracle.SuggestTipCap(context.Background())
	if err != nil {
		t.Fatalf("SuggestTipCap error: %v", err)
	}
	defaultPrice := big.NewInt(chainparams.GWei)
	if got.Cmp(defaultPrice) <= 0 {
		t.Fatalf("Smart fee cold start should fall back to legacy (got %v, want > %v)", got, defaultPrice)
	}
}

// TestEstimateSmartFeeColdStart verifies cold start falls back to legacy oracle
// and reports LegacyFallback in the metadata.
func TestEstimateSmartFeeColdStart(t *testing.T) {
	defaultPrice := big.NewInt(chainparams.GWei)
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, smartFeeConfig())
	defer oracle.Close()

	for _, target := range []int{2, 6, 12, 48, 100} {
		got, meta, err := oracle.EstimateSmartFee(context.Background(), target)
		if err != nil {
			t.Fatalf("EstimateSmartFee(%d) error: %v", target, err)
		}
		if got.Cmp(defaultPrice) <= 0 {
			t.Errorf("EstimateSmartFee(%d) = %v, want > %v (should fall back to legacy)", target, got, defaultPrice)
		}
		if !meta.LegacyFallback {
			t.Errorf("EstimateSmartFee(%d) meta.LegacyFallback = false, want true (cold start)", target)
		}
	}
}

// TestEstimateSmartFeeClamp verifies results are clamped to [default, maxPrice].
func TestEstimateSmartFeeClamp(t *testing.T) {
	defaultPrice := big.NewInt(5 * chainparams.GWei)
	maxPrice := big.NewInt(100 * chainparams.GWei)
	config := Config{
		Default:                 defaultPrice,
		MaxPrice:                maxPrice,
		EnableSmartFeeEstimator: true,
	}
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, config)
	defer oracle.Close()

	got, _, err := oracle.EstimateSmartFee(context.Background(), 2)
	if err != nil {
		t.Fatalf("EstimateSmartFee error: %v", err)
	}
	if got.Cmp(defaultPrice) < 0 {
		t.Errorf("Result %v is below default %v", got, defaultPrice)
	}
	if got.Cmp(maxPrice) > 0 {
		t.Errorf("Result %v exceeds max %v", got, maxPrice)
	}
}

// TestEstimateSmartFeeFlagToggle verifies the flag selects the correct algorithm.
// With smart fee disabled: legacy percentile of test backend (30 GWei).
// With smart fee enabled but no data: falls back to legacy, same result.
func TestEstimateSmartFeeFlagToggle(t *testing.T) {
	backend := newTestBackend(t, nil, false)

	legacy := NewOracle(backend, nil, Config{
		Blocks:     3,
		Percentile: 60,
		Default:    big.NewInt(chainparams.GWei),
	})
	defer legacy.Close()

	smart := NewOracle(backend, nil, Config{
		Blocks:                  3,
		Percentile:              60,
		Default:                 big.NewInt(chainparams.GWei),
		EnableSmartFeeEstimator: true,
	})
	defer smart.Close()

	legacyResult, _ := legacy.SuggestTipCap(context.Background())
	smartResult, _ := smart.SuggestTipCap(context.Background())

	if legacyResult.Cmp(big.NewInt(30*chainparams.GWei)) != 0 {
		t.Errorf("Legacy mode returned %v, want 30 GWei", legacyResult)
	}
	// With no smart fee data, the fallback should produce the same result
	// as the legacy oracle since both use the same backend and config.
	if smartResult.Cmp(legacyResult) != 0 {
		t.Errorf("Smart fee cold start returned %v, want %v (same as legacy fallback)", smartResult, legacyResult)
	}
}

// TestTxConfirmStatsBasic tests the core TxConfirmStats functionality.
func TestTxConfirmStatsBasic(t *testing.T) {
	// Create buckets: [1, 1.05, 1.1025, ..., +Inf]
	var buckets []float64
	for b := 1.0; b <= 100.0; b *= feeSpacing {
		buckets = append(buckets, b)
	}
	buckets = append(buckets, math.Inf(1))

	stats := newTxConfirmStats(buckets, shortBlockPeriods, shortDecay, shortScale)

	// Verify max confirms.
	if got := stats.getMaxConfirms(); got != shortBlockPeriods*shortScale {
		t.Errorf("getMaxConfirms() = %d, want %d", got, shortBlockPeriods*shortScale)
	}

	// Bucket index: feerate 1.0 should go to bucket 0.
	if got := stats.bucketIndex(1.0); got != 0 {
		t.Errorf("bucketIndex(1.0) = %d, want 0", got)
	}

	// Feerate above all real buckets goes to INF bucket.
	lastBucket := len(buckets) - 1
	if got := stats.bucketIndex(1000.0); got != lastBucket {
		t.Errorf("bucketIndex(1000.0) = %d, want %d", got, lastBucket)
	}
}

// TestTxConfirmStatsRecordAndEstimate tests recording confirmations
// and getting estimates.
func TestTxConfirmStatsRecordAndEstimate(t *testing.T) {
	var buckets []float64
	for b := 1.0; b <= 1000.0; b *= feeSpacing {
		buckets = append(buckets, b)
	}
	buckets = append(buckets, math.Inf(1))

	stats := newTxConfirmStats(buckets, shortBlockPeriods, shortDecay, shortScale)

	// Simulate: record many txs at feerate=10.0 confirming in 1 block.
	for i := 0; i < 100; i++ {
		stats.record(1, 10.0)
	}

	// Also record some txs at feerate=5.0 confirming in 1 block.
	for i := 0; i < 100; i++ {
		stats.record(1, 5.0)
	}

	// EstimateMedianVal for target=1 should find an answer.
	est := stats.estimateMedianVal(1, sufficientTxShort, successPct, 100)
	if est < 0 {
		t.Fatalf("Expected valid estimate, got %f", est)
	}
	// The estimate should be around 5.0 (the lower feerate that also passes).
	if est > 15.0 {
		t.Errorf("Estimate %f seems too high for txs at feerate 5-10", est)
	}
}

// TestTxConfirmStatsDecay verifies that decay reduces counters over time.
func TestTxConfirmStatsDecay(t *testing.T) {
	var buckets []float64
	for b := 1.0; b <= 100.0; b *= feeSpacing {
		buckets = append(buckets, b)
	}
	buckets = append(buckets, math.Inf(1))

	stats := newTxConfirmStats(buckets, shortBlockPeriods, shortDecay, shortScale)

	// Record some data.
	for i := 0; i < 50; i++ {
		stats.record(1, 10.0)
	}

	initialTxCt := stats.txCtAvg[stats.bucketIndex(10.0)]
	if initialTxCt == 0 {
		t.Fatal("Expected non-zero txCtAvg after recording")
	}

	// Apply decay many times.
	for i := 0; i < 100; i++ {
		stats.updateMovingAverages()
	}

	afterTxCt := stats.txCtAvg[stats.bucketIndex(10.0)]
	// After 100 blocks of decay at 0.962: 50 * 0.962^100 ≈ 1.03
	if afterTxCt >= initialTxCt/2 {
		t.Errorf("Decay didn't reduce sufficiently: initial=%f, after=%f", initialTxCt, afterTxCt)
	}
}

// TestTxConfirmStatsScale verifies that scale factors work correctly.
func TestTxConfirmStatsScale(t *testing.T) {
	var buckets []float64
	for b := 1.0; b <= 100.0; b *= feeSpacing {
		buckets = append(buckets, b)
	}
	buckets = append(buckets, math.Inf(1))

	// Medium stats with scale=2.
	stats := newTxConfirmStats(buckets, medBlockPeriods, medDecay, medScale)

	if got := stats.getMaxConfirms(); got != medBlockPeriods*medScale {
		t.Errorf("getMaxConfirms() = %d, want %d", got, medBlockPeriods*medScale)
	}

	// A tx confirmed in 3 blocks should map to period 2 (ceil(3/2) = 2).
	// This means confAvg[1] (0-indexed) and above get incremented.
	stats.record(3, 10.0)

	bucketIdx := stats.bucketIndex(10.0)
	// confAvg[0] (period 1) should NOT be incremented (periodsToConfirm=2 > 1).
	if stats.confAvg[0][bucketIdx] != 0 {
		t.Errorf("confAvg[0] should be 0, got %f", stats.confAvg[0][bucketIdx])
	}
	// confAvg[1] (period 2) should be incremented.
	if stats.confAvg[1][bucketIdx] != 1 {
		t.Errorf("confAvg[1] should be 1, got %f", stats.confAvg[1][bucketIdx])
	}
}

// TestTxConfirmStatsFailure verifies that removeTx correctly counts failures.
func TestTxConfirmStatsFailure(t *testing.T) {
	var buckets []float64
	for b := 1.0; b <= 100.0; b *= feeSpacing {
		buckets = append(buckets, b)
	}
	buckets = append(buckets, math.Inf(1))

	stats := newTxConfirmStats(buckets, shortBlockPeriods, shortDecay, shortScale)

	// Add a tx at block 10.
	bucketIdx := stats.newTx(10, 10.0)

	// Remove it at block 15 (not in block = failure, 5 blocks ago >= scale=1).
	stats.removeTx(10, 15, bucketIdx, false)

	// failAvg should be incremented for periods 0..4 (periodsAgo=5, 0-indexed: i < 5).
	for i := 0; i < 5 && i < len(stats.failAvg); i++ {
		if stats.failAvg[i][bucketIdx] != 1 {
			t.Errorf("failAvg[%d] should be 1, got %f", i, stats.failAvg[i][bucketIdx])
		}
	}

	// Periods beyond 5 should not be incremented.
	if len(stats.failAvg) > 5 && stats.failAvg[5][bucketIdx] != 0 {
		t.Errorf("failAvg[5] should be 0, got %f", stats.failAvg[5][bucketIdx])
	}
}

// TestProcessBlockAndEstimate tests the full flow: add txs to mempool,
// process blocks that confirm them, then estimate fees.
func TestProcessBlockAndEstimate(t *testing.T) {
	defaultPrice := big.NewInt(chainparams.GWei)
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, smartFeeConfig())
	defer oracle.Close()

	// Simulate: add txs to mempool at various fee levels, then confirm them.
	// Block 1: add 20 txs at 5 GWei, then confirm all in block 2.
	oracle.stateLock.Lock()
	oracle.nBestSeenHeight = 1
	for i := 0; i < 20; i++ {
		feerate := float64(5 * chainparams.GWei)
		bucketIdx := oracle.shortStats.newTx(1, feerate)
		oracle.medStats.newTx(1, feerate)
		oracle.longStats.newTx(1, feerate)
		hash := util.BigToHash(big.NewInt(int64(i + 1)))
		oracle.pendingTxs[hash] = txStatsInfo{blockHeight: 1, bucketIndex: bucketIdx}
	}
	oracle.stateLock.Unlock()

	// Simulate processing blocks 2 through 30.
	// Blocks 2..30: confirm 20 txs at 5 GWei per block.
	for blockNum := uint64(2); blockNum <= 30; blockNum++ {
		oracle.stateLock.Lock()

		oracle.nBestSeenHeight = blockNum
		oracle.shortStats.clearCurrent(blockNum)
		oracle.medStats.clearCurrent(blockNum)
		oracle.longStats.clearCurrent(blockNum)
		oracle.shortStats.updateMovingAverages()
		oracle.medStats.updateMovingAverages()
		oracle.longStats.updateMovingAverages()

		// Record 20 txs confirmed in 1 block at 5 GWei.
		feerate := float64(5 * chainparams.GWei)
		for i := 0; i < 20; i++ {
			oracle.shortStats.record(1, feerate)
			oracle.medStats.record(1, feerate)
			oracle.longStats.record(1, feerate)
		}

		if oracle.firstRecordedHeight == 0 {
			oracle.firstRecordedHeight = blockNum
		}

		oracle.cacheLock.Lock()
		oracle.cachedEstimates = make(map[int]cachedSmartEstimate)
		oracle.cacheLock.Unlock()

		oracle.stateLock.Unlock()
	}

	// Now estimate. With enough data, we should get an estimate.
	got, _, err := oracle.EstimateSmartFee(context.Background(), 2)
	if err != nil {
		t.Fatalf("EstimateSmartFee error: %v", err)
	}

	// The estimate should be around 5 GWei.
	fiveGwei := big.NewInt(5 * chainparams.GWei)
	tenGwei := big.NewInt(10 * chainparams.GWei)

	if got.Cmp(defaultPrice) < 0 {
		t.Errorf("Estimate %v is below default %v", got, defaultPrice)
	}

	// With all txs at 5 GWei and 100% confirmation, estimate should be near 5 GWei.
	if got.Cmp(tenGwei) > 0 {
		t.Errorf("Estimate %v is unexpectedly high (all txs at 5 GWei)", got)
	}
	_ = fiveGwei // used for context
}

// TestMaxUsableEstimate verifies that maxUsableEstimate limits based on block span.
func TestMaxUsableEstimate(t *testing.T) {
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, smartFeeConfig())
	defer oracle.Close()

	// With no data, maxUsableEstimate should be 1.
	oracle.stateLock.RLock()
	got := oracle.maxUsableEstimate()
	oracle.stateLock.RUnlock()
	if got != 1 {
		t.Errorf("maxUsableEstimate() = %d with no data, want 1", got)
	}

	// Simulate 100 blocks of data.
	oracle.stateLock.Lock()
	oracle.firstRecordedHeight = 1
	oracle.nBestSeenHeight = 101
	oracle.stateLock.Unlock()

	oracle.stateLock.RLock()
	got = oracle.maxUsableEstimate()
	oracle.stateLock.RUnlock()
	// blockSpan = 100, maxUsable = 100/2 = 50.
	if got != 50 {
		t.Errorf("maxUsableEstimate() = %d with 100 blocks, want 50", got)
	}
}

// TestConfTargetClamping verifies target clamping behavior.
func TestConfTargetClamping(t *testing.T) {
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, smartFeeConfig())
	defer oracle.Close()

	// Target 0 and 1 should both produce the same result (clamped to 2).
	got1, _, _ := oracle.EstimateSmartFee(context.Background(), 0)
	got2, _, _ := oracle.EstimateSmartFee(context.Background(), 1)
	if got1.Cmp(got2) != 0 {
		t.Errorf("Target 0 and 1 should produce same result, got %v and %v", got1, got2)
	}
}

// TestThreeSubEstimates verifies the three-threshold approach:
// halfEst (60% at target/2), actualEst (85% at target), doubleEst (95% at 2*target).
func TestThreeSubEstimates(t *testing.T) {
	var buckets []float64
	for b := float64(chainparams.GWei) / 10; b <= float64(500*chainparams.GWei); b *= feeSpacing {
		buckets = append(buckets, b)
	}
	buckets = append(buckets, math.Inf(1))

	stats := newTxConfirmStats(buckets, shortBlockPeriods, shortDecay, shortScale)

	// Record lots of txs at 2 GWei all confirming in 1 block.
	feerate := float64(2 * chainparams.GWei)
	for i := 0; i < 200; i++ {
		stats.record(1, feerate)
	}

	// Test at different thresholds.
	est60 := stats.estimateMedianVal(2, sufficientTxShort, halfSuccessPct, 100)
	est85 := stats.estimateMedianVal(2, sufficientTxShort, successPct, 100)
	est95 := stats.estimateMedianVal(2, sufficientTxShort, doubleSuccessPct, 100)

	// All should return valid estimates since we have 100% confirmation rate.
	if est60 < 0 || est85 < 0 || est95 < 0 {
		t.Errorf("Expected valid estimates: est60=%f, est85=%f, est95=%f", est60, est85, est95)
	}

	// With 100% confirmation rate at all fee levels, all thresholds should pass.
	// The estimates should be similar (around 2 GWei).
	target := float64(2 * chainparams.GWei)
	tolerance := target * 0.5
	if math.Abs(est85-target) > tolerance {
		t.Errorf("est85 = %f, expected near %f", est85, target)
	}
}

// TestBucketGeneration verifies bucket generation with FEE_SPACING = 1.05.
func TestBucketGeneration(t *testing.T) {
	config := Config{
		Default:                 big.NewInt(chainparams.GWei),
		MinBucketFee:            big.NewInt(chainparams.GWei / 10), // 0.1 GWei
		MaxBucketFee:            big.NewInt(500 * chainparams.GWei),
		EnableSmartFeeEstimator: true,
	}
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, config)
	defer oracle.Close()

	// Verify bucket count is reasonable for the range with 1.05 spacing.
	// ln(500G / 0.1G) / ln(1.05) = ln(5000) / ln(1.05) ≈ 175
	numBuckets := len(oracle.bucketBounds)
	if numBuckets < 150 || numBuckets > 200 {
		t.Errorf("Expected ~175 buckets, got %d", numBuckets)
	}

	// Verify last bucket is +Inf.
	if !math.IsInf(oracle.bucketBounds[numBuckets-1], 1) {
		t.Errorf("Last bucket should be +Inf, got %f", oracle.bucketBounds[numBuckets-1])
	}

	// Verify spacing is approximately 1.05.
	if numBuckets > 2 {
		ratio := oracle.bucketBounds[1] / oracle.bucketBounds[0]
		if ratio < 1.04 || ratio > 1.06 {
			t.Errorf("Bucket spacing ratio = %f, want ~1.05", ratio)
		}
	}
}

// TestCircularBuffer verifies the circular buffer mechanism for unconfirmed txs.
func TestCircularBuffer(t *testing.T) {
	var buckets []float64
	for b := 1.0; b <= 100.0; b *= feeSpacing {
		buckets = append(buckets, b)
	}
	buckets = append(buckets, math.Inf(1))

	stats := newTxConfirmStats(buckets, shortBlockPeriods, shortDecay, shortScale)

	// Add a tx at block 5.
	bucketIdx := stats.newTx(5, 10.0)
	slot := 5 % stats.getMaxConfirms()
	if stats.unconfTxs[slot][bucketIdx] != 1 {
		t.Fatalf("Expected unconfTxs[%d][%d] = 1, got %d", slot, bucketIdx, stats.unconfTxs[slot][bucketIdx])
	}

	// ClearCurrent at block 5 should move it to oldUnconfTxs.
	stats.clearCurrent(5)
	if stats.unconfTxs[slot][bucketIdx] != 0 {
		t.Errorf("unconfTxs should be 0 after clear, got %d", stats.unconfTxs[slot][bucketIdx])
	}
	if stats.oldUnconfTxs[bucketIdx] != 1 {
		t.Errorf("oldUnconfTxs should be 1, got %d", stats.oldUnconfTxs[bucketIdx])
	}

	// removeTx should decrement oldUnconfTxs.
	stats.removeTx(5, 20, bucketIdx, true)
	if stats.oldUnconfTxs[bucketIdx] != 0 {
		t.Errorf("oldUnconfTxs should be 0 after removeTx, got %d", stats.oldUnconfTxs[bucketIdx])
	}
}

// floorConfig is the legacy oracle with FloorWhenUncongested, whose estimate
// on the test chain (30 gwei) differs from the floor (1 gwei).
func floorConfig() Config {
	return Config{
		Blocks:               3,
		Percentile:           60,
		Default:              big.NewInt(chainparams.GWei),
		FloorWhenUncongested: true,
	}
}

// TestSuggestTipCapFloorWhenUncongested checks that nearly empty blocks get
// the minimum price instead of an estimate learned from what few
// transactions paid.
func TestSuggestTipCapFloorWhenUncongested(t *testing.T) {
	backend := newTestBackend(t, nil, false)
	oracle := NewOracle(backend, nil, floorConfig())
	defer oracle.Close()

	got, err := oracle.SuggestTipCap(context.Background())
	if err != nil {
		t.Fatalf("SuggestTipCap error: %v", err)
	}
	if want := big.NewInt(chainparams.GWei); got.Cmp(want) != 0 {
		t.Fatalf("uncongested blocks: want the floor %v, got %v", want, got)
	}
}

// TestSuggestTipCapEstimatesWhenCongested checks that blocks over half full
// get the estimator's answer.
func TestSuggestTipCapEstimatesWhenCongested(t *testing.T) {
	// One 21000 gas transfer in a 30000 limit: 70% full
	backend := newTestBackendWithGasLimit(t, nil, false, 30000)
	oracle := NewOracle(backend, nil, floorConfig())
	defer oracle.Close()

	got, err := oracle.SuggestTipCap(context.Background())
	if err != nil {
		t.Fatalf("SuggestTipCap error: %v", err)
	}
	if want := big.NewInt(30 * chainparams.GWei); got.Cmp(want) != 0 {
		t.Fatalf("congested blocks: want the estimate %v, got %v", want, got)
	}
}

// fullPendingBackend reports quiet history but a full pending block, as when
// a burst of transactions is waiting.
type fullPendingBackend struct {
	*testBackend
	pending *types.Block
}

func (b *fullPendingBackend) PendingBlockAndReceipts() (*types.Block, types.Receipts) {
	return b.pending, nil
}

// TestSuggestTipCapEstimatesWhenPendingIsFull checks that a full pending
// block overrides quiet history, so a burst gets estimates at once.
func TestSuggestTipCapEstimatesWhenPendingIsFull(t *testing.T) {
	congested := newTestBackendWithGasLimit(t, nil, false, 30000)
	backend := &fullPendingBackend{
		testBackend: newTestBackend(t, nil, false),
		pending:     congested.chain.GetBlockByNumber(testHead),
	}
	oracle := NewOracle(backend, nil, floorConfig())
	defer oracle.Close()

	got, err := oracle.SuggestTipCap(context.Background())
	if err != nil {
		t.Fatalf("SuggestTipCap error: %v", err)
	}
	if floor := big.NewInt(chainparams.GWei); got.Cmp(floor) == 0 {
		t.Fatalf("full pending block: want an estimate above the floor, got %v", got)
	}
}
