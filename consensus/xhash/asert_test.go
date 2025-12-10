package xhash

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// BCH uses this as POW limit (MAX_BITS = 0x1d00ffff).
const (
	asertMaxBits = 0x1d00ffff
	maxInt64     = int64(^uint64(0) >> 1)
)

// bitsToTargetBCH and targetToBitsBCH are direct ports of the
// Python reference in validate_nbits_aserti3_2d.py and the
// C++ SetCompact/GetCompact logic used in BCHN.

// bitsToTargetBCH converts compact nBits (0xEEFFFFFF) to *big.Int target.
func bitsToTargetBCH(bits uint32) *big.Int {
	size := bits >> 24
	mant := bits & 0x007fffff

	// Zero/invalid mantissa should not occur in valid BCH vectors,
	// but we keep code simple and assume vectors are well-formed.
	target := big.NewInt(int64(mant))

	if size <= 3 {
		shift := uint(8 * (3 - size))
		target.Rsh(target, shift)
	} else {
		shift := uint(8 * (size - 3))
		target.Lsh(target, shift)
	}
	return target
}

// targetToBitsBCH converts a big.Int target back to compact nBits.
func targetToBitsBCH(target *big.Int) uint32 {
	if target.Sign() <= 0 {
		// This shouldn't happen with ASERT if clamped correctly,
		// panic if it does.
		panic("invalid target sign")
	}

	// Work on a copy so we don't mutate the caller's *big.Int.
	t := new(big.Int).Set(target)

	// Clamp to BCH max target.
	maxTarget := bitsToTargetBCH(asertMaxBits)
	if t.Cmp(maxTarget) > 0 {
		t.Set(maxTarget)
	}

	// Determine size in bytes.
	size := uint32((t.BitLen() + 7) / 8)

	var compact uint32
	if size <= 3 {
		// Shift left so significant bytes sit in mantissa.
		shift := uint(8 * (3 - size))
		tmp := new(big.Int).Lsh(t, shift)
		compact = uint32(tmp.Uint64())
	} else {
		// Shift right to get top 3 bytes into mantissa.
		shift := uint(8 * (size - 3))
		tmp := new(big.Int).Rsh(t, shift)
		compact = uint32(tmp.Uint64())
	}

	// If mantissa's top bit is set, shift down and bump size.
	if compact&0x00800000 != 0 {
		compact >>= 8
		size++
	}

	compact &= 0x007fffff // keep 23 bits
	return compact | (size << 24)
}

type asertRunHeader struct {
	Description      string
	AnchorHeight     int64
	AnchorParentTime int64
	AnchorBits       uint32
	StartHeight      int64
	StartTime        int64
	Iterations       int64
}

type asertVectorLine struct {
	Iteration   int64
	Height      int64
	HeightDelta int64
	Time        int64
	Bits        uint32
}

func parseHexBits(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	v, err := strconv.ParseUint(s, 16, 32)
	return uint32(v), err
}

func loadASERTRun(path string) (*asertRunHeader, []asertVectorLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	hdr := &asertRunHeader{}
	var lines []asertVectorLine

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "##") {
			lower := strings.ToLower(line)

			getAfterColon := func() string {
				idx := strings.Index(line, ":")
				if idx < 0 {
					return ""
				}
				return strings.TrimSpace(line[idx+1:])
			}

			switch {
			case strings.Contains(lower, "description:"):
				hdr.Description = getAfterColon()

			case strings.Contains(lower, "anchor height:"):
				v := getAfterColon()
				hdr.AnchorHeight, err = strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("parse anchor height in %s: %w", path, err)
				}

			case strings.Contains(lower, "anchor") &&
				strings.Contains(lower, "time") &&
				!strings.Contains(lower, "start"):
				// anchor ancestor time / anchor parent time / anchor time
				v := getAfterColon()
				hdr.AnchorParentTime, err = strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("parse anchor parent/ancestor time in %s: %w", path, err)
				}

			case strings.Contains(lower, "anchor nbits:"):
				v := getAfterColon()
				hdr.AnchorBits, err = parseHexBits(v)
				if err != nil {
					return nil, nil, fmt.Errorf("parse anchor nBits in %s: %w", path, err)
				}

			case strings.Contains(lower, "start height:"):
				v := getAfterColon()
				hdr.StartHeight, err = strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("parse start height in %s: %w", path, err)
				}

			case strings.Contains(lower, "start time:"):
				v := getAfterColon()
				hdr.StartTime, err = strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("parse start time in %s: %w", path, err)
				}

			case strings.Contains(lower, "iterations:"):
				v := getAfterColon()
				hdr.Iterations, err = strconv.ParseInt(v, 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("parse iterations in %s: %w", path, err)
				}
			}

			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 4 {
			return nil, nil, fmt.Errorf("unexpected data line in %s: %q", path, line)
		}

		iter, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("parse iteration in %s: %w", path, err)
		}

		// --- height & heightDelta handling ---
		var height int64
		var heightDelta int64

		// First try signed parse.
		hSigned, err := strconv.ParseInt(parts[1], 10, 64)
		if err == nil {
			height = hSigned
			heightDelta = hSigned - hdr.AnchorHeight
		} else if strings.Contains(err.Error(), "value out of range") {
			hu, err2 := strconv.ParseUint(parts[1], 10, 64)
			if err2 != nil {
				return nil, nil, fmt.Errorf("parse uint height in %s: %w", path, err2)
			}
			anchorU := uint64(hdr.AnchorHeight)
			if hu < anchorU {
				return nil, nil, fmt.Errorf("height < anchor in %s: %q", path, line)
			}
			deltaU := hu - anchorU
			if deltaU > uint64(maxInt64) {
				return nil, nil, fmt.Errorf("height delta too large in %s: %q", path, line)
			}
			height = 0 // absolute height not needed in tests
			heightDelta = int64(deltaU)
		} else {
			return nil, nil, fmt.Errorf("parse height in %s: %w", path, err)
		}

		tm, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("parse time in %s: %w", path, err)
		}

		bits, err := parseHexBits(parts[3])
		if err != nil {
			return nil, nil, fmt.Errorf("parse bits in %s: %w", path, err)
		}

		lines = append(lines, asertVectorLine{
			Iteration:   iter,
			Height:      height,
			HeightDelta: heightDelta,
			Time:        tm,
			Bits:        bits,
		})
	}

	if err := sc.Err(); err != nil {
		return nil, nil, err
	}

	return hdr, lines, nil
}

// TestASERTNextTarget_BCHNVectors validates ASERTNextTarget against all BCHN
// aserti3-2d test vectors (run01..run12). It assumes the run files are present
// under testdata/aserti3-2d/.
func TestASERTNextTarget_BCHNVectors(t *testing.T) {
	maxTarget := bitsToTargetBCH(asertMaxBits)

	pattern := filepath.Join("testdata", "aserti3-2d", "run*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	if len(files) == 0 {
		t.Fatalf("no ASERT test vector files found under %s", pattern)
	}

	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			hdr, vecs, err := loadASERTRun(path)
			if err != nil {
				t.Fatalf("loadASERTRun(%s): %v", path, err)
			}

			if hdr.AnchorHeight <= 0 {
				t.Fatalf("%s: invalid or missing anchor height (got %d)", path, hdr.AnchorHeight)
			}
			if hdr.AnchorBits == 0 {
				t.Fatalf("%s: invalid or missing anchor nBits (got 0)", path)
			}
			if hdr.Iterations != int64(len(vecs)) {
				t.Fatalf("%s: header iterations=%d but got %d lines",
					path, hdr.Iterations, len(vecs))
			}

			anchorTarget := bitsToTargetBCH(hdr.AnchorBits)

			// For ASERT math we only care about heightDelta.
			// Use a synthetic small anchor height to avoid int64 overflow issues.
			const anchorHeightTest int64 = 1

			for _, v := range vecs {
				evalHeightTest := anchorHeightTest + v.HeightDelta

				gotTarget := ASERTNextTarget(
					anchorHeightTest,
					hdr.AnchorParentTime,
					anchorTarget,
					evalHeightTest,
					v.Time,
					maxTarget,
				)

				gotBits := targetToBitsBCH(gotTarget)
				if gotBits != v.Bits {
					t.Fatalf("%s: mismatch at iter=%d heightDelta=%d time=%d\n  got bits=0x%08x, want=0x%08x",
						path, v.Iteration, v.HeightDelta, v.Time, gotBits, v.Bits,
					)
				}
			}
		})
	}
}

func TestASERTMaxTargetConsistency(t *testing.T) {
	d1 := big.NewInt(1)
	targetFromDiff := difficultyToTarget(d1)

	if targetFromDiff.Cmp(two256m1) != 0 {
		t.Fatalf("expected target for difficulty=1 to be two256m1, got %v", targetFromDiff)
	}

	roundTrip := targetToDifficulty(targetFromDiff)
	if roundTrip.Cmp(d1) != 0 {
		t.Fatalf("roundtrip diff→target→diff failed: want 1, got %v", roundTrip)
	}
}
