package xhash

import (
	"math/big"
)

// ASERT params
const (
	asertIdealBlockTime = int64(600)     // seconds
	asertHalflife       = int64(172800)  // 2 days in seconds
	asertRadix          = int64(1 << 16) // fixed-point radix (2^16)
)

// Polynomial coefficients for 2^x cubic approximation (from BCH spec)
const (
	asertPolyA = uint64(195766423245049)
	asertPolyB = uint64(971821376)
	asertPolyC = uint64(5127)
)

// ASERTNextTarget computes the next target using the aserti3-2d algorithm.
// All math here is integer-only and matches the BCH specification.
//
// anchorHeight      = height of anchor block
// anchorParentTime  = timestamp (Unix seconds) of parent of anchor block
// anchorTarget      = integer target value of anchor block
// evalHeight        = height of evaluation block
// evalTime          = timestamp of evaluation block
// maxTarget         = maximum allowed target (easiest difficulty)
//
// Returns the target for the next block after the evaluation block.
func ASERTNextTarget(
	anchorHeight int64,
	anchorParentTime int64,
	anchorTarget *big.Int,
	evalHeight int64,
	evalTime int64,
	maxTarget *big.Int,
) *big.Int {
	if anchorHeight <= 0 {
		panic("ASERTNextTarget: anchorHeight must be > 0")
	}
	if anchorTarget.Sign() <= 0 {
		panic("ASERTNextTarget: anchorTarget must be > 0")
	}
	if maxTarget.Sign() <= 0 {
		panic("ASERTNextTarget: maxTarget must be > 0")
	}

	timeDelta := evalTime - anchorParentTime
	heightDelta := evalHeight - anchorHeight

	// Use truncating integer division (Go's / on ints already truncates toward zero)
	numBlocks := heightDelta + 1
	exponent := ((timeDelta - asertIdealBlockTime*numBlocks) * asertRadix) / asertHalflife

	numShifts := exponent >> 16

	// Keep 16-bit fractional part
	exponent -= numShifts * asertRadix

	// Now compute the cubic approximation factor in 16.16 fixed point.
	// We interpret exponent as a signed 64-bit, but pass it to the poly as uint64
	// so we get the same 2's-complement behavior as the BCH reference.
	ux := uint64(exponent)

	// factor = ((A*x + B*x^2 + C*x^3 + 2^47) >> 48) + 2^16
	// This yields a multiplier in 16.16 fixed point.
	x2 := ux * ux
	x3 := x2 * ux

	poly := asertPolyA*ux + asertPolyB*x2 + asertPolyC*x3 + (uint64(1) << 47)
	factor := (poly >> 48) + uint64(asertRadix) // + 2^16

	next := new(big.Int).Mul(anchorTarget, new(big.Int).SetUint64(factor))

	// Apply the 2^numShifts factor:
	if numShifts < 0 {
		// Right-shift by -numShifts
		next.Rsh(next, uint(-numShifts))
	} else if numShifts > 0 {
		// Left-shift by numShifts
		next.Lsh(next, uint(numShifts))
	}

	// Divide by 2^16 to remove fixed-point scaling
	next.Rsh(next, 16)

	// Clamp to valid range
	if next.Sign() <= 0 {
		next.SetInt64(1)
		return next
	}
	if next.Cmp(maxTarget) > 0 {
		next = new(big.Int).Set(maxTarget)
	}
	return next
}

// difficultyToTarget: target = floor((2^256-1) / difficulty)
func difficultyToTarget(d *big.Int) *big.Int {
	if d.Sign() <= 0 {
		// avoid div by zero; treat as max difficulty → min target
		return new(big.Int).SetInt64(1)
	}
	t := new(big.Int).Div(new(big.Int).Set(two256m1), d)
	if t.Sign() <= 0 {
		t.SetInt64(1)
	}
	return t
}

// targetToDifficulty: difficulty = floor((2^256-1) / target)
func targetToDifficulty(t *big.Int) *big.Int {
	if t.Sign() <= 0 {
		// avoid div by zero; treat as easiest target → difficulty = 1
		return big.NewInt(1)
	}
	d := new(big.Int).Div(new(big.Int).Set(two256m1), t)
	if d.Sign() <= 0 {
		d.SetInt64(1)
	}
	return d
}
