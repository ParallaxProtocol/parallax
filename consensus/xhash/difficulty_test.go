package xhash

import (
	"math/big"
	"testing"

	"github.com/ParallaxProtocol/parallax/core/types"
	"github.com/ParallaxProtocol/parallax/params"
)

func bi(x int64) *big.Int { return big.NewInt(x) }

func header(num uint64, diff int64, time uint64, epochStart uint64) *types.Header {
	return &types.Header{
		Number:         new(big.Int).SetUint64(num),
		Difficulty:     bi(diff),
		Time:           time,
		EpochStartTime: epochStart,
	}
}

func cfg(retarget uint64) *params.ChainConfig {
	return &params.ChainConfig{
		XHash: &params.XHashConfig{
			RetargetIntervalBlocks: retarget,
		},
	}
}

func TestCalcNakamotoDifficulty_NonBoundaryKeepsDifficulty(t *testing.T) {
	r := uint64(100)
	parent := header(r-2, 123456, 1_000_000, 1_000_000-600*50) // nextHeight = r-1 => not boundary
	out := CalcNakamotoDifficulty(cfg(r), parent)
	if out.Cmp(parent.Difficulty) != 0 {
		t.Fatalf("expected unchanged difficulty on non-boundary, got %v want %v", out, parent.Difficulty)
	}
}

func TestCalcNakamotoDifficulty_BoundaryExactTimespan_NoChange(t *testing.T) {
	r := uint64(100)
	target := BlockTargetSpacingSeconds * r
	parent := header(r-1, 1_000_000, 5_000_000, 5_000_000-target) // nextHeight=r -> boundary; actual=target
	out := CalcNakamotoDifficulty(cfg(r), parent)
	if out.Cmp(parent.Difficulty) != 0 {
		t.Fatalf("expected same difficulty when actual==target, got %v want %v", out, parent.Difficulty)
	}
}

func TestCalcNakamotoDifficulty_BoundaryClampMin_Quadruples(t *testing.T) {
	r := uint64(120)
	target := BlockTargetSpacingSeconds * r // T
	minT := target / 4                      // T/4

	// Make actualTimespan < minT so it clamps up to minT
	parent := header(r-1, 2_000, 5_000_000, 5_000_000-(minT/2))

	out := CalcNakamotoDifficulty(cfg(r), parent)

	// new = old * T / minT = old * 4
	want := new(big.Int).Mul(bi(2_000), bi(4))
	if out.Cmp(want) != 0 {
		t.Fatalf("expected quadruple due to min clamp, got %v want %v", out, want)
	}
}

func TestCalcNakamotoDifficulty_BoundaryClampMax_Quarters(t *testing.T) {
	r := uint64(150)
	target := BlockTargetSpacingSeconds * r
	maxT := target * 4
	parent := header(r-1, 2_000, 9_999_999, 9_999_999-(maxT*10)) // actual >> maxT => clamp to maxT
	out := CalcNakamotoDifficulty(cfg(r), parent)

	// new = old * T / maxT = old / 4
	want := new(big.Int).Div(bi(2_000), bi(4))
	if out.Cmp(want) != 0 {
		t.Fatalf("expected quarter due to max clamp, got %v want %v", out, want)
	}
}

func TestCalcNakamotoDifficulty_NoXHashConfig_Uses2016Rule(t *testing.T) {
	// XHash == nil -> r=2016
	r := uint64(2016)
	target := BlockTargetSpacingSeconds * r
	parent := header(r-1, 777_777, 1_234_567, 1_234_567-target) // boundary with exact target
	conf := &params.ChainConfig{XHash: nil}
	out := CalcNakamotoDifficulty(conf, parent)
	if out.Cmp(parent.Difficulty) != 0 {
		t.Fatalf("expected same difficulty with XHash==nil on exact target, got %v want %v", out, parent.Difficulty)
	}
}

func TestCalcNakamotoDifficulty_RetargetIntervalZero_ReturnsSame(t *testing.T) {
	// r=0 => always return parent difficulty
	parent := header(123, 999_999, 100, 0)
	out := CalcNakamotoDifficulty(cfg(0), parent)
	if out.Cmp(parent.Difficulty) != 0 {
		t.Fatalf("expected same difficulty when r==0, got %v want %v", out, parent.Difficulty)
	}
}

func TestCalcNakamotoDifficulty_EnsureAtLeastOne(t *testing.T) {
	// Choose values that would round down to 0 before the guard.
	r := uint64(10)
	target := BlockTargetSpacingSeconds * r
	maxT := target * 4
	parent := header(r-1, 1, 9_999_999, 9_999_999-maxT) // old=1, actual=maxT => 1*target/maxT = 1/4 -> 0 -> clamp to 1
	out := CalcNakamotoDifficulty(cfg(r), parent)
	if out.Cmp(bi(1)) != 0 {
		t.Fatalf("expected difficulty to be clamped to 1, got %v", out)
	}
}
