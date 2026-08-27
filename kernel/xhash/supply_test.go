package xhash

import (
	"math"
	"math/big"
	"testing"
	"testing/quick"

	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

// This file is a drift guard for the money supply math. The RPC endpoints
// GetTotalSupply and GetCirculatingSupply (api.go) compute the halving
// schedule in closed form, independently of how the consensus subsidy
// function calcBlockReward (consensus.go) is applied block by block. The
// guards below pin the consensus constants and cross-check the API behaviour
// against a ground truth derived from calcBlockReward. If either side is ever
// changed without the other, these tests fail loudly.
//
// Both endpoints report cumulative issuance through the chain tip, immature
// coinbases included: per the Bitcoin convention, maturity restricts
// spendability, not issuance, so circulating supply equals total supply.

// supplyStubChain is a minimal kernel.ChainHeaderReader; the supply RPC
// endpoints only ever call CurrentHeader, and Finalize only calls Config.
type supplyStubChain struct {
	head *types.Header
}

func (c *supplyStubChain) Config() *chainparams.ChainConfig          { return chainparams.MainnetChainConfig }
func (c *supplyStubChain) CurrentHeader() *types.Header              { return c.head }
func (c *supplyStubChain) GetHeader(util.Hash, uint64) *types.Header { return nil }
func (c *supplyStubChain) GetHeaderByNumber(uint64) *types.Header    { return nil }
func (c *supplyStubChain) GetHeaderByHash(util.Hash) *types.Header   { return nil }
func (c *supplyStubChain) GetTd(util.Hash, uint64) *big.Int          { return nil }

// newSupplyAPI returns an API whose chain head is at the given height. The
// supply endpoints never touch the engine, so it is left nil.
func newSupplyAPI(height uint64) *API {
	head := &types.Header{Number: new(big.Int).SetUint64(height)}
	return &API{chain: &supplyStubChain{head: head}}
}

// cumulativeSupplyTo returns the exact cumulative emission through block
// `height` inclusive, i.e. the sum of calcBlockReward(b) for b in [0, height].
// It is computed per era (era_block_count * era_reward), never by looping
// block by block, so it stays O(#eras) even for multi-million block heights.
func cumulativeSupplyTo(height uint64) *big.Int {
	total := new(big.Int)
	tmp := new(big.Int)
	for era := uint64(0); ; era++ {
		eraStart := era * HalvingIntervalBlocks
		if eraStart > height {
			break
		}
		// Genesis (block 0) carries no subsidy; era 0 therefore starts
		// paying at block 1.
		first := eraStart
		if first == 0 {
			first = 1
		}
		last := eraStart + HalvingIntervalBlocks - 1
		if last > height {
			last = height
		}
		if last < first {
			continue
		}
		reward := calcBlockReward(first)
		if reward.Sign() == 0 {
			// Reward exhausted (>63 halvings); every later era is zero too.
			break
		}
		tmp.SetUint64(last - first + 1)
		tmp.Mul(tmp, reward)
		total.Add(total, tmp)
	}
	return total
}

// mustBig parses the decimal string returned by the supply RPC endpoints.
func mustBig(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("API returned non-decimal supply string %q", s)
	}
	return v
}

// TestSupplyMathMatchesBlockRewards cross-checks the closed-form supply math
// in api.go against the exact cumulative sum of calcBlockReward: at every
// height, GetTotalSupply must equal the sum of calcBlockReward over blocks
// 1..height, and GetCirculatingSupply must report the identical figure
// (immature coinbases count as issued, Bitcoin-style).
func TestSupplyMathMatchesBlockRewards(t *testing.T) {
	heights := []uint64{
		0,
		1,
		209999,
		210000,
		210001,
		2 * 210000,
		3*210000 + 7,
		63 * 210000,
		64 * 210000,
		70 * 210000,
	}

	for _, h := range heights {
		api := newSupplyAPI(h)

		wantTotal := cumulativeSupplyTo(h)
		if gotTotal := mustBig(t, api.GetTotalSupply()); gotTotal.Cmp(wantTotal) != 0 {
			t.Errorf("height %d: GetTotalSupply = %s, want cumulative reward sum %s", h, gotTotal, wantTotal)
		}

		if gotCirc := mustBig(t, api.GetCirculatingSupply()); gotCirc.Cmp(wantTotal) != 0 {
			t.Errorf("height %d: GetCirculatingSupply = %s, want total supply %s (circulating must equal total)", h, gotCirc, wantTotal)
		}
	}
}

// TestHalvingConstantsConsistent pins the consensus halving constants and
// behaviourally verifies that api.go's function-local halving interval agrees
// with consensus.go's HalvingIntervalBlocks: the per-block increment of the
// circulating supply must halve exactly at the consensus era boundary.
func TestHalvingConstantsConsistent(t *testing.T) {
	// Pin the consensus schedule; the behavioural check below additionally
	// catches any drift between the API supply math and the consensus reward.
	if HalvingIntervalBlocks != 210000 {
		t.Fatalf("HalvingIntervalBlocks = %d, want 210000", HalvingIntervalBlocks)
	}
	wantInitial := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	if InitialBlockRewardWei.Cmp(wantInitial) != 0 {
		t.Fatalf("InitialBlockRewardWei = %s, want %s", InitialBlockRewardWei, wantInitial)
	}

	// Consensus side: the reward halves exactly at the boundary.
	pre := calcBlockReward(HalvingIntervalBlocks - 1)
	post := calcBlockReward(HalvingIntervalBlocks)
	if new(big.Int).Mul(post, big.NewInt(2)).Cmp(pre) != 0 {
		t.Fatalf("calcBlockReward does not halve at HalvingIntervalBlocks: pre %s, post %s", pre, post)
	}

	// API side (behavioural): GetCirculatingSupply's per-block increment must
	// switch from the era-0 reward to the era-1 reward at the same boundary.
	circAt := func(height uint64) *big.Int {
		return mustBig(t, newSupplyAPI(height).GetCirculatingSupply())
	}

	deltaPre := new(big.Int).Sub(circAt(HalvingIntervalBlocks-1), circAt(HalvingIntervalBlocks-2))
	if deltaPre.Cmp(pre) != 0 {
		t.Errorf("circulating supply increment just below the boundary = %s, want era-0 reward %s "+
			"(api.go halving interval drifted from consensus?)", deltaPre, pre)
	}
	deltaPost := new(big.Int).Sub(circAt(HalvingIntervalBlocks+2), circAt(HalvingIntervalBlocks+1))
	if deltaPost.Cmp(post) != 0 {
		t.Errorf("circulating supply increment just above the boundary = %s, want era-1 reward %s "+
			"(api.go halving interval drifted from consensus?)", deltaPost, post)
	}
}

// TestCoinbaseMaturityConstantConsistent pins the chainparams coinbase
// maturity used by the payout scheduling in Finalize, and verifies that
// maturity does NOT leak into the supply endpoints: per the Bitcoin
// convention, immature rewards are issued (counted) even though Finalize
// defers their spendability.
func TestCoinbaseMaturityConstantConsistent(t *testing.T) {
	maturity := chainparams.MainnetChainConfig.XHash.CoinbaseMaturityBlocks
	if maturity != 100 {
		t.Fatalf("mainnet CoinbaseMaturityBlocks = %d, want 100", maturity)
	}
	if tn := chainparams.TestnetChainConfig.XHash.CoinbaseMaturityBlocks; tn != maturity {
		t.Errorf("testnet CoinbaseMaturityBlocks = %d, mainnet = %d; expected identical", tn, maturity)
	}

	// API side (behavioural): the very first reward circulates at height 1,
	// well inside the maturity window. This fails if a maturity deduction is
	// ever reintroduced into GetCirculatingSupply.
	if got := mustBig(t, newSupplyAPI(1).GetCirculatingSupply()); got.Cmp(InitialBlockRewardWei) != 0 {
		t.Errorf("GetCirculatingSupply at height 1 = %s, want one initial reward %s (immature coinbase must count)",
			got, InitialBlockRewardWei)
	}

	// Consensus side: Finalize must schedule the coinbase payout to unlock
	// exactly CoinbaseMaturityBlocks after the rewarded height.
	engine := NewFaker()
	sdb := newTestStateDB(t)
	// Genesis allocates 1 wei to the lockbox so that EIP-158 empty-account
	// pruning in IntermediateRoot never deletes the maturity schedule; mirror
	// that here (see validation/genesis.go).
	sdb.AddBalance(lockboxAddress, big.NewInt(1))
	height := uint64(12345)
	coinbase := util.HexToAddress("0x00000000000000000000000000000000000000CC")
	header := &types.Header{
		Number:   new(big.Int).SetUint64(height),
		Coinbase: coinbase,
	}
	engine.Finalize(&supplyStubChain{head: header}, header, sdb, nil, nil)

	if _, _, ok := popDuePayout(sdb, height+maturity-1); ok {
		t.Fatalf("payout due before maturity horizon (height %d)", height+maturity-1)
	}
	gotAddr, gotAmt, ok := popDuePayout(sdb, height+maturity)
	if !ok {
		t.Fatalf("no payout scheduled at height %d (= rewarded height + mainnet maturity %d)",
			height+maturity, maturity)
	}
	if gotAddr != coinbase {
		t.Fatalf("scheduled payout address = %v, want %v", gotAddr, coinbase)
	}
	if want := calcBlockReward(height); gotAmt.Cmp(want) != 0 {
		t.Fatalf("scheduled payout amount = %s, want %s", gotAmt, want)
	}
}

// TestHalvingShiftOverflowClamp verifies that heights implying more than 63
// halvings yield a zero reward without panicking, and that the supply figures
// plateau once the subsidy is exhausted.
func TestHalvingShiftOverflowClamp(t *testing.T) {
	for _, h := range []uint64{
		64 * HalvingIntervalBlocks,
		100 * HalvingIntervalBlocks,
		1000 * HalvingIntervalBlocks,
		math.MaxUint64,
	} {
		if got := calcBlockReward(h); got.Sign() != 0 {
			t.Errorf("calcBlockReward(%d) = %s, want 0 (shift overflow clamp)", h, got)
		}
	}

	// The exact cumulative supply is flat once every era reward is zero.
	atExhaustion := cumulativeSupplyTo(64 * HalvingIntervalBlocks)
	muchLater := cumulativeSupplyTo(70 * HalvingIntervalBlocks)
	if atExhaustion.Cmp(muchLater) != 0 {
		t.Errorf("cumulative supply not flat after exhaustion: %s at 64 eras vs %s at 70 eras",
			atExhaustion, muchLater)
	}

	// Both API endpoints must plateau as well (whatever their absolute values).
	if a, b := newSupplyAPI(64*HalvingIntervalBlocks).GetTotalSupply(),
		newSupplyAPI(70*HalvingIntervalBlocks).GetTotalSupply(); a != b {
		t.Errorf("GetTotalSupply not flat after exhaustion: %s at 64 eras vs %s at 70 eras", a, b)
	}
	if a, b := newSupplyAPI(64*HalvingIntervalBlocks).GetCirculatingSupply(),
		newSupplyAPI(70*HalvingIntervalBlocks).GetCirculatingSupply(); a != b {
		t.Errorf("GetCirculatingSupply not flat after exhaustion: %s vs %s", a, b)
	}
}

// TestRewardMonotoneNonIncreasing property-checks that the block subsidy never
// increases from one era to the next.
func TestRewardMonotoneNonIncreasing(t *testing.T) {
	f := func(h uint64) bool {
		// Keep heights in a meaningful range (and avoid wrapping h + interval).
		h %= 100 * HalvingIntervalBlocks
		if h == 0 {
			// Genesis is special-cased to zero reward, which would trivially
			// violate monotonicity against era 1; start at block 1 instead.
			h = 1
		}
		next := calcBlockReward(h + HalvingIntervalBlocks)
		return next.Cmp(calcBlockReward(h)) <= 0
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("reward increased across an era boundary: %v", err)
	}
}
