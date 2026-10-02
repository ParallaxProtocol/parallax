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

package kernel

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

// copyConfig returns a shallow copy of the given chain config so tests can
// tweak individual fork blocks without mutating the shared TestChainConfig.
func copyConfig(original *chainparams.ChainConfig) *chainparams.ChainConfig {
	cpy := *original
	return &cpy
}

// TestCalcBaseFee verifies the EIP-1559 base fee calculation against
// hand-computed vectors. With parentGasLimit = 20M the gas target is 10M
// (ElasticityMultiplier = 2) and the change denominator is 8, so a full
// 10M gas delta moves the base fee by baseFee/8 = 125000000.
func TestCalcBaseFee(t *testing.T) {
	tests := []struct {
		name            string
		parentBaseFee   int64
		parentGasLimit  uint64
		parentGasUsed   uint64
		expectedBaseFee int64
	}{
		// parent.GasUsed == target: base fee unchanged.
		{"at target", 1000000000, 20000000, 10000000, 1000000000},
		// 1M above target: 1000000000 * 1000000 / 10000000 / 8 = 12500000 increase.
		{"above target", 1000000000, 20000000, 11000000, 1012500000},
		// 1M below target: same magnitude, decrease.
		{"below target", 1000000000, 20000000, 9000000, 987500000},
		// Empty block: full 10M delta below target, max decrease of baseFee/8.
		{"empty block max decrease", 1000000000, 20000000, 0, 875000000},
		// Completely full block: full 10M delta above target, max increase of baseFee/8.
		{"full block max increase", 1000000000, 20000000, 20000000, 1125000000},
		// Marginally above target with tiny base fee: 7 * 1 / 10000000 / 8 = 0,
		// clamped to the minimum increase of 1.
		{"minimum +1 delta clamp", 7, 20000000, 10000001, 8},
		// Marginally below target with tiny base fee: delta truncates to 0,
		// base fee unchanged (no clamp on the decrease side).
		{"tiny decrease truncates to zero", 7, 20000000, 9999999, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := &types.Header{
				Number:   big.NewInt(32),
				GasLimit: tt.parentGasLimit,
				GasUsed:  tt.parentGasUsed,
				BaseFee:  big.NewInt(tt.parentBaseFee),
			}
			if have, want := CalcBaseFee(chainparams.TestChainConfig, parent), big.NewInt(tt.expectedBaseFee); have.Cmp(want) != 0 {
				t.Errorf("base fee mismatch: have %v, want %v", have, want)
			}
		})
	}
}

// TestCalcBaseFeePreLondon verifies that a parent block before the London
// fork yields the initial base fee regardless of the parent's gas usage.
func TestCalcBaseFeePreLondon(t *testing.T) {
	config := copyConfig(chainparams.TestChainConfig)
	config.LondonBlock = big.NewInt(5)

	tests := []struct {
		name         string
		parentNumber int64
		parentBase   *big.Int
		want         *big.Int
	}{
		{"parent before fork", 4, nil, new(big.Int).SetUint64(chainparams.InitialBaseFee)},
		{"parent at fork", 5, big.NewInt(1000000000), big.NewInt(1000000000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := &types.Header{
				Number:   big.NewInt(tt.parentNumber),
				GasLimit: 20000000,
				GasUsed:  10000000,
				BaseFee:  tt.parentBase,
			}
			if have := CalcBaseFee(config, parent); have.Cmp(tt.want) != 0 {
				t.Errorf("base fee mismatch: have %v, want %v", have, tt.want)
			}
		})
	}
}

// TestVerifyEip1559Header exercises the combined gas limit and base fee
// header checks against a London parent.
func TestVerifyEip1559Header(t *testing.T) {
	parent := &types.Header{
		Number:   big.NewInt(32),
		GasLimit: 20000000,
		GasUsed:  11000000,
		BaseFee:  big.NewInt(1000000000),
	}
	tests := []struct {
		name    string
		header  *types.Header
		wantErr string
	}{
		{
			name: "valid header",
			header: &types.Header{
				Number:   big.NewInt(33),
				GasLimit: 20000000,
				BaseFee:  big.NewInt(1012500000),
			},
		},
		{
			name: "missing base fee",
			header: &types.Header{
				Number:   big.NewInt(33),
				GasLimit: 20000000,
			},
			wantErr: "missing baseFee",
		},
		{
			name: "wrong base fee",
			header: &types.Header{
				Number:   big.NewInt(33),
				GasLimit: 20000000,
				BaseFee:  big.NewInt(1000000000),
			},
			wantErr: "invalid baseFee",
		},
		{
			name: "gas limit out of bounds",
			header: &types.Header{
				Number:   big.NewInt(33),
				GasLimit: 20000000 + 20000000/chainparams.GasLimitBoundDivisor,
				BaseFee:  big.NewInt(1012500000),
			},
			wantErr: "invalid gas limit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyEip1559Header(chainparams.TestChainConfig, parent, tt.header)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestVerifyEip1559HeaderPreLondonParent verifies that a non-London parent's
// gas limit is doubled by the elasticity multiplier before the bounds check,
// and that the first London header must carry the initial base fee.
func TestVerifyEip1559HeaderPreLondonParent(t *testing.T) {
	config := copyConfig(chainparams.TestChainConfig)
	config.LondonBlock = big.NewInt(5)

	parent := &types.Header{
		Number:   big.NewInt(4),
		GasLimit: 10000000,
		GasUsed:  10000000,
	}
	// The header may double the parent gas limit at the fork boundary
	// (elasticity multiplier 2) and must use the initial base fee.
	header := &types.Header{
		Number:   big.NewInt(5),
		GasLimit: 20000000,
		BaseFee:  new(big.Int).SetUint64(chainparams.InitialBaseFee),
	}
	if err := VerifyEip1559Header(config, parent, header); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// A base fee other than the initial one must be rejected.
	header.BaseFee = big.NewInt(1)
	if err := VerifyEip1559Header(config, parent, header); err == nil {
		t.Error("expected invalid baseFee error, got nil")
	}
}

// TestVerifyEip1559HeaderMissingParentBaseFee verifies that a malformed London
// parent without a base fee is rejected instead of crashing the verifier.
func TestVerifyEip1559HeaderMissingParentBaseFee(t *testing.T) {
	parent := &types.Header{
		Number:   big.NewInt(1),
		GasLimit: 10000000,
		GasUsed:  5000000,
	}
	header := &types.Header{
		Number:   big.NewInt(2),
		GasLimit: 10000000,
		BaseFee:  big.NewInt(chainparams.InitialBaseFee),
	}
	if err := VerifyEip1559Header(chainparams.TestChainConfig, parent, header); err == nil {
		t.Fatal("expected error for parent missing baseFee, got nil")
	}
}

// TestVerifyGaslimit checks the parent-relative gas limit bounds. With a
// parent gas limit of 20M the bound is 20000000/1024 = 19531, and a diff of
// 19531 or more is rejected.
func TestVerifyGaslimit(t *testing.T) {
	tests := []struct {
		name           string
		parentGasLimit uint64
		headerGasLimit uint64
		wantErr        string
	}{
		{"unchanged", 20000000, 20000000, ""},
		{"increase within bound", 20000000, 20000000 + 19530, ""},
		{"decrease within bound", 20000000, 20000000 - 19530, ""},
		{"increase at bound rejected", 20000000, 20000000 + 19531, "invalid gas limit"},
		{"decrease at bound rejected", 20000000, 20000000 - 19531, "invalid gas limit"},
		{"increase past bound rejected", 20000000, 20000000 + 20000, "invalid gas limit"},
		{"below minimum rejected", 5001, 4999, "invalid gas limit below 5000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyGaslimit(tt.parentGasLimit, tt.headerGasLimit)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestVerifyForkHashes checks the optional EIP150 checkpoint hash validation.
func TestVerifyForkHashes(t *testing.T) {
	header := &types.Header{
		Number:     big.NewInt(10),
		Difficulty: big.NewInt(1),
	}
	wrongHash := util.Hash{0xde, 0xad, 0xbe, 0xef}

	tests := []struct {
		name    string
		config  *chainparams.ChainConfig
		uncle   bool
		wantErr string
	}{
		{
			name: "nil fork block passes",
			config: func() *chainparams.ChainConfig {
				c := copyConfig(chainparams.TestChainConfig)
				c.EIP150Block = nil
				c.EIP150Hash = wrongHash
				return c
			}(),
		},
		{
			name: "fork block elsewhere passes",
			config: func() *chainparams.ChainConfig {
				c := copyConfig(chainparams.TestChainConfig)
				c.EIP150Block = big.NewInt(11)
				c.EIP150Hash = wrongHash
				return c
			}(),
		},
		{
			name: "empty checkpoint hash at fork block passes",
			config: func() *chainparams.ChainConfig {
				c := copyConfig(chainparams.TestChainConfig)
				c.EIP150Block = big.NewInt(10)
				c.EIP150Hash = util.Hash{}
				return c
			}(),
		},
		{
			name: "matching checkpoint hash passes",
			config: func() *chainparams.ChainConfig {
				c := copyConfig(chainparams.TestChainConfig)
				c.EIP150Block = big.NewInt(10)
				c.EIP150Hash = header.Hash()
				return c
			}(),
		},
		{
			name: "mismatched checkpoint hash fails",
			config: func() *chainparams.ChainConfig {
				c := copyConfig(chainparams.TestChainConfig)
				c.EIP150Block = big.NewInt(10)
				c.EIP150Hash = wrongHash
				return c
			}(),
			wantErr: "homestead gas reprice fork",
		},
		{
			name: "uncle skips validation",
			config: func() *chainparams.ChainConfig {
				c := copyConfig(chainparams.TestChainConfig)
				c.EIP150Block = big.NewInt(10)
				c.EIP150Hash = wrongHash
				return c
			}(),
			uncle: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyForkHashes(tt.config, header, tt.uncle)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}
