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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/rpc"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
	"github.com/ParallaxProtocol/parallax/v2/util/math"
)

// errEstimateInvoked is returned by the mock backend when setDefaults reaches
// the gas estimation path, which needs live chain state to complete.
var errEstimateInvoked = errors.New("gas estimation invoked")

// backendMock implements the small subset of the Backend interface that
// TransactionArgs.setDefaults consults. All other methods panic via the
// embedded nil interface if they are called unexpectedly.
type backendMock struct {
	Backend

	config  *chainparams.ChainConfig
	current *types.Header
	tip     *big.Int
	nonce   uint64
}

// newLondonBackendMock returns a mock backend whose chain has EIP-1559
// activated from genesis.
func newLondonBackendMock() *backendMock {
	config := *chainparams.TestChainConfig
	return &backendMock{
		config: &config,
		current: &types.Header{
			Number:  big.NewInt(1100),
			BaseFee: big.NewInt(100),
		},
		tip:   big.NewInt(42),
		nonce: 7,
	}
}

// newLegacyBackendMock returns a mock backend whose chain never activates
// EIP-1559.
func newLegacyBackendMock() *backendMock {
	config := *chainparams.TestChainConfig
	config.LondonBlock = nil
	return &backendMock{
		config: &config,
		current: &types.Header{
			Number: big.NewInt(1100),
		},
		tip:   big.NewInt(42),
		nonce: 7,
	}
}

func (b *backendMock) CurrentHeader() *types.Header { return b.current }

func (b *backendMock) ChainConfig() *chainparams.ChainConfig { return b.config }

func (b *backendMock) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	// Return a copy: setDefaults mutates the suggestion on the legacy path.
	return new(big.Int).Set(b.tip), nil
}

func (b *backendMock) GetPoolNonce(ctx context.Context, addr util.Address) (uint64, error) {
	return b.nonce, nil
}

func (b *backendMock) RPCGasCap() uint64 { return 50_000_000 }

func (b *backendMock) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	return nil, errEstimateInvoked
}

func newHexBig(v int64) *hexutil.Big { return (*hexutil.Big)(big.NewInt(v)) }

func newHexUint64(v uint64) *hexutil.Uint64 { return (*hexutil.Uint64)(&v) }

func newHexBytes(b []byte) *hexutil.Bytes { return (*hexutil.Bytes)(&b) }

// TestSetDefaultsFees checks the fee field defaulting and validation logic of
// setDefaults against pre- and post-london mock backends. The mock suggests a
// tip of 42 and reports a base fee of 100.
func TestSetDefaultsFees(t *testing.T) {
	to := util.HexToAddress("0x0000000000000000000000000000000000001111")
	tests := []struct {
		name    string
		london  bool
		in      TransactionArgs
		gasPr   *hexutil.Big // expected GasPrice
		feeCap  *hexutil.Big // expected MaxFeePerGas
		tipCap  *hexutil.Big // expected MaxPriorityFeePerGas
		wantErr bool
	}{
		{
			name:    "gasPrice and maxFeePerGas conflict",
			london:  true,
			in:      TransactionArgs{GasPrice: newHexBig(10), MaxFeePerGas: newHexBig(10)},
			wantErr: true,
		},
		{
			name:    "gasPrice and maxPriorityFeePerGas conflict",
			london:  true,
			in:      TransactionArgs{GasPrice: newHexBig(10), MaxPriorityFeePerGas: newHexBig(10)},
			wantErr: true,
		},
		{
			name:   "legacy defaults pre-london",
			london: false,
			in:     TransactionArgs{},
			gasPr:  newHexBig(42), // suggested tip, no base fee added
		},
		{
			name:   "explicit gasPrice post-london kept",
			london: true,
			in:     TransactionArgs{GasPrice: newHexBig(1000)},
			gasPr:  newHexBig(1000),
		},
		{
			name:   "dynamic defaults post-london",
			london: true,
			in:     TransactionArgs{},
			feeCap: newHexBig(242), // tip + 2*baseFee = 42 + 200
			tipCap: newHexBig(42),
		},
		{
			name:   "tip given, fee cap derived",
			london: true,
			in:     TransactionArgs{MaxPriorityFeePerGas: newHexBig(10)},
			feeCap: newHexBig(210), // 10 + 2*baseFee
			tipCap: newHexBig(10),
		},
		{
			name:   "fee cap given, tip suggested",
			london: true,
			in:     TransactionArgs{MaxFeePerGas: newHexBig(1000)},
			feeCap: newHexBig(1000),
			tipCap: newHexBig(42),
		},
		{
			name:    "fee cap below suggested tip",
			london:  true,
			in:      TransactionArgs{MaxFeePerGas: newHexBig(10)},
			wantErr: true,
		},
		{
			name:   "both dynamic fields given and valid",
			london: true,
			in:     TransactionArgs{MaxFeePerGas: newHexBig(50), MaxPriorityFeePerGas: newHexBig(42)},
			feeCap: newHexBig(50),
			tipCap: newHexBig(42),
		},
		{
			name:    "fee cap below explicit tip",
			london:  true,
			in:      TransactionArgs{MaxFeePerGas: newHexBig(10), MaxPriorityFeePerGas: newHexBig(20)},
			wantErr: true,
		},
		{
			name:    "maxFeePerGas pre-london",
			london:  false,
			in:      TransactionArgs{MaxFeePerGas: newHexBig(10)},
			wantErr: true,
		},
		{
			name:    "maxPriorityFeePerGas pre-london",
			london:  false,
			in:      TransactionArgs{MaxPriorityFeePerGas: newHexBig(10)},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := newLondonBackendMock()
			if !test.london {
				b = newLegacyBackendMock()
			}
			args := test.in
			args.To = &to
			args.Gas = newHexUint64(21000) // skip the estimation path

			err := args.setDefaults(context.Background(), b)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cmp := func(field string, have, want *hexutil.Big) {
				switch {
				case want == nil:
					if have != nil {
						t.Errorf("%s: have %v, want nil", field, have)
					}
				case have == nil:
					t.Errorf("%s: have nil, want %v", field, want)
				case have.ToInt().Cmp(want.ToInt()) != 0:
					t.Errorf("%s: have %v, want %v", field, have, want)
				}
			}
			cmp("gasPrice", args.GasPrice, test.gasPr)
			cmp("maxFeePerGas", args.MaxFeePerGas, test.feeCap)
			cmp("maxPriorityFeePerGas", args.MaxPriorityFeePerGas, test.tipCap)
		})
	}
}

// TestSetDefaultsFields checks the non-fee defaulting behaviour: nonce, value,
// chain id, data/input consistency and contract creation validation.
func TestSetDefaultsFields(t *testing.T) {
	to := util.HexToAddress("0x0000000000000000000000000000000000001111")
	gas := newHexUint64(21000)

	t.Run("nonce fetched from pool", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{To: &to, Gas: gas}
		if err := args.setDefaults(context.Background(), b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args.Nonce == nil || uint64(*args.Nonce) != b.nonce {
			t.Errorf("nonce: have %v, want %d", args.Nonce, b.nonce)
		}
	})
	t.Run("explicit nonce kept", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{To: &to, Gas: gas, Nonce: newHexUint64(99)}
		if err := args.setDefaults(context.Background(), b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if uint64(*args.Nonce) != 99 {
			t.Errorf("nonce: have %d, want 99", uint64(*args.Nonce))
		}
	})
	t.Run("value defaults to zero", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{To: &to, Gas: gas}
		if err := args.setDefaults(context.Background(), b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args.Value == nil || args.Value.ToInt().Sign() != 0 {
			t.Errorf("value: have %v, want 0", args.Value)
		}
	})
	t.Run("chain id defaults to config", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{To: &to, Gas: gas}
		if err := args.setDefaults(context.Background(), b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args.ChainID == nil || args.ChainID.ToInt().Cmp(b.config.ChainID) != 0 {
			t.Errorf("chainId: have %v, want %v", args.ChainID, b.config.ChainID)
		}
	})
	t.Run("matching explicit chain id kept", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{To: &to, Gas: gas, ChainID: (*hexutil.Big)(new(big.Int).Set(b.config.ChainID))}
		if err := args.setDefaults(context.Background(), b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args.ChainID.ToInt().Cmp(b.config.ChainID) != 0 {
			t.Errorf("chainId: have %v, want %v", args.ChainID, b.config.ChainID)
		}
	})
	t.Run("mismatched explicit chain id rejected", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{To: &to, Gas: gas, ChainID: newHexBig(1234)}
		if err := args.setDefaults(context.Background(), b); err == nil {
			t.Fatal("expected error for chain id mismatch")
		}
	})
	t.Run("data and input differing rejected", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{
			To:    &to,
			Gas:   gas,
			Data:  newHexBytes([]byte{0x01}),
			Input: newHexBytes([]byte{0x02}),
		}
		if err := args.setDefaults(context.Background(), b); err == nil {
			t.Fatalf("expected error, got none")
		}
	})
	t.Run("data and input equal accepted", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{
			To:    &to,
			Gas:   gas,
			Data:  newHexBytes([]byte{0x01, 0x02}),
			Input: newHexBytes([]byte{0x01, 0x02}),
		}
		if err := args.setDefaults(context.Background(), b); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("contract creation without data rejected", func(t *testing.T) {
		b := newLondonBackendMock()
		args := TransactionArgs{Gas: gas}
		if err := args.setDefaults(context.Background(), b); err == nil {
			t.Fatalf("expected error, got none")
		}
	})
	t.Run("nil gas triggers estimation", func(t *testing.T) {
		// A real estimation needs live chain state; the mock fails the
		// lookup with a sentinel error to prove the path is entered.
		b := newLondonBackendMock()
		args := TransactionArgs{To: &to}
		err := args.setDefaults(context.Background(), b)
		if !errors.Is(err, errEstimateInvoked) {
			t.Fatalf("have error %v, want %v", err, errEstimateInvoked)
		}
	})
}

// TestToMessageGas checks the gas cap clamping behaviour of ToMessage.
func TestToMessageGas(t *testing.T) {
	tests := []struct {
		name    string
		gas     *hexutil.Uint64
		gasCap  uint64
		wantGas uint64
	}{
		{"no gas, no cap", nil, 0, uint64(math.MaxUint64 / 2)},
		{"no gas, cap applies", nil, 30_000_000, 30_000_000},
		{"gas below cap", newHexUint64(21000), 30_000_000, 21000},
		{"gas above cap clamped", newHexUint64(40_000_000), 30_000_000, 30_000_000},
		{"gas without cap", newHexUint64(40_000_000), 0, 40_000_000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := TransactionArgs{Gas: test.gas}
			msg, err := args.ToMessage(test.gasCap, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if msg.Gas() != test.wantGas {
				t.Errorf("gas: have %d, want %d", msg.Gas(), test.wantGas)
			}
		})
	}
}

// TestToMessageFees checks the fee normalization logic of ToMessage for both
// legacy and 1559 execution contexts.
func TestToMessageFees(t *testing.T) {
	tests := []struct {
		name    string
		args    TransactionArgs
		baseFee *big.Int
		gasPr   int64
		feeCap  int64
		tipCap  int64
		wantErr bool
	}{
		{
			name:    "gasPrice and maxFeePerGas conflict",
			args:    TransactionArgs{GasPrice: newHexBig(10), MaxFeePerGas: newHexBig(10)},
			wantErr: true,
		},
		{
			name:    "gasPrice and maxPriorityFeePerGas conflict",
			args:    TransactionArgs{GasPrice: newHexBig(10), MaxPriorityFeePerGas: newHexBig(10)},
			wantErr: true,
		},
		{
			name: "no basefee, no fees",
			args: TransactionArgs{},
		},
		{
			name:  "no basefee, legacy gasPrice",
			args:  TransactionArgs{GasPrice: newHexBig(100)},
			gasPr: 100, feeCap: 100, tipCap: 100,
		},
		{
			name:    "basefee, legacy gasPrice",
			args:    TransactionArgs{GasPrice: newHexBig(100)},
			baseFee: big.NewInt(50),
			gasPr:   100, feeCap: 100, tipCap: 100,
		},
		{
			name:    "basefee, no fees",
			args:    TransactionArgs{},
			baseFee: big.NewInt(50),
		},
		{
			name:    "basefee, effective price from tip",
			args:    TransactionArgs{MaxFeePerGas: newHexBig(200), MaxPriorityFeePerGas: newHexBig(10)},
			baseFee: big.NewInt(50),
			gasPr:   60, feeCap: 200, tipCap: 10, // min(tip+baseFee, feeCap) = 60
		},
		{
			name:    "basefee, effective price capped by fee cap",
			args:    TransactionArgs{MaxFeePerGas: newHexBig(55), MaxPriorityFeePerGas: newHexBig(10)},
			baseFee: big.NewInt(50),
			gasPr:   55, feeCap: 55, tipCap: 10, // min(60, 55) = 55
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg, err := test.args.ToMessage(0, test.baseFee)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if have := msg.GasPrice().Int64(); have != test.gasPr {
				t.Errorf("gasPrice: have %d, want %d", have, test.gasPr)
			}
			if have := msg.GasFeeCap().Int64(); have != test.feeCap {
				t.Errorf("gasFeeCap: have %d, want %d", have, test.feeCap)
			}
			if have := msg.GasTipCap().Int64(); have != test.tipCap {
				t.Errorf("gasTipCap: have %d, want %d", have, test.tipCap)
			}
		})
	}
}

// TestToMessageDefaults checks sender, value, calldata and access list
// handling in ToMessage.
func TestToMessageDefaults(t *testing.T) {
	t.Run("zero defaults", func(t *testing.T) {
		args := TransactionArgs{}
		msg, err := args.ToMessage(0, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.From() != (util.Address{}) {
			t.Errorf("from: have %v, want zero address", msg.From())
		}
		if msg.To() != nil {
			t.Errorf("to: have %v, want nil", msg.To())
		}
		if msg.Value().Sign() != 0 {
			t.Errorf("value: have %v, want 0", msg.Value())
		}
		if len(msg.Data()) != 0 {
			t.Errorf("data: have %x, want empty", msg.Data())
		}
		if len(msg.AccessList()) != 0 {
			t.Errorf("accessList: have %v, want empty", msg.AccessList())
		}
	})
	t.Run("explicit fields", func(t *testing.T) {
		var (
			from = util.HexToAddress("0x0000000000000000000000000000000000002222")
			to   = util.HexToAddress("0x0000000000000000000000000000000000001111")
			al   = types.AccessList{{Address: to, StorageKeys: []util.Hash{{1}}}}
		)
		args := TransactionArgs{
			From:       &from,
			To:         &to,
			Value:      newHexBig(1000),
			Input:      newHexBytes([]byte{0xca, 0xfe}),
			AccessList: &al,
		}
		msg, err := args.ToMessage(0, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.From() != from {
			t.Errorf("from: have %v, want %v", msg.From(), from)
		}
		if msg.To() == nil || *msg.To() != to {
			t.Errorf("to: have %v, want %v", msg.To(), to)
		}
		if msg.Value().Int64() != 1000 {
			t.Errorf("value: have %v, want 1000", msg.Value())
		}
		if !bytes.Equal(msg.Data(), []byte{0xca, 0xfe}) {
			t.Errorf("data: have %x, want cafe", msg.Data())
		}
		if len(msg.AccessList()) != 1 || msg.AccessList()[0].Address != to {
			t.Errorf("accessList: have %v, want %v", msg.AccessList(), al)
		}
	})
}

// TestTransactionArgsData checks the input-over-data preference of the
// calldata accessor.
func TestTransactionArgsData(t *testing.T) {
	tests := []struct {
		name string
		args TransactionArgs
		want []byte
	}{
		{"neither", TransactionArgs{}, nil},
		{"data only", TransactionArgs{Data: newHexBytes([]byte{0x01})}, []byte{0x01}},
		{"input only", TransactionArgs{Input: newHexBytes([]byte{0x02})}, []byte{0x02}},
		{"input preferred", TransactionArgs{Data: newHexBytes([]byte{0x01}), Input: newHexBytes([]byte{0x02})}, []byte{0x02}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if have := test.args.data(); !bytes.Equal(have, test.want) {
				t.Errorf("data: have %x, want %x", have, test.want)
			}
		})
	}
}

// TestTransactionArgsJSON checks that malformed hex input is rejected when
// unmarshalling TransactionArgs and that valid input decodes correctly.
func TestTransactionArgsJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		mustFail bool
	}{
		{"empty object", `{}`, false},
		{"valid full args", `{
			"from": "0x0000000000000000000000000000000000002222",
			"to": "0x0000000000000000000000000000000000001111",
			"gas": "0x5208",
			"maxFeePerGas": "0xf2",
			"maxPriorityFeePerGas": "0x2a",
			"value": "0x3e8",
			"nonce": "0x7",
			"input": "0xcafe",
			"chainId": "0x83e"
		}`, false},
		{"invalid gas hex", `{"gas": "0xgg"}`, true},
		{"gas missing prefix", `{"gas": "5208"}`, true},
		{"invalid gasPrice", `{"gasPrice": "0x"}`, true},
		{"invalid maxFeePerGas", `{"maxFeePerGas": "12"}`, true},
		{"invalid from address", `{"from": "0x123"}`, true},
		{"odd length data", `{"data": "0x1"}`, true},
		{"invalid input hex", `{"input": "0xzz"}`, true},
		{"invalid nonce", `{"nonce": "seven"}`, true},
		{"invalid value type", `{"value": 1000}`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var args TransactionArgs
			err := json.Unmarshal([]byte(test.input), &args)
			if test.mustFail && err == nil {
				t.Fatalf("expected error, got none")
			}
			if !test.mustFail && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	t.Run("decoded values", func(t *testing.T) {
		var args TransactionArgs
		input := `{"to": "0x0000000000000000000000000000000000001111", "gas": "0x5208", "value": "0x3e8", "input": "0xcafe"}`
		if err := json.Unmarshal([]byte(input), &args); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if args.To == nil || *args.To != util.HexToAddress("0x0000000000000000000000000000000000001111") {
			t.Errorf("to: have %v", args.To)
		}
		if args.Gas == nil || uint64(*args.Gas) != 21000 {
			t.Errorf("gas: have %v, want 21000", args.Gas)
		}
		if args.Value == nil || args.Value.ToInt().Int64() != 1000 {
			t.Errorf("value: have %v, want 1000", args.Value)
		}
		if !bytes.Equal(args.data(), []byte{0xca, 0xfe}) {
			t.Errorf("data: have %x, want cafe", args.data())
		}
	})
}
