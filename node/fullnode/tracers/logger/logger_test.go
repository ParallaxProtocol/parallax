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

package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation/state"
)

type dummyContractRef struct {
	calledForEach bool
}

func (dummyContractRef) Address() util.Address     { return util.Address{} }
func (dummyContractRef) Value() *big.Int           { return new(big.Int) }
func (dummyContractRef) SetCode(util.Hash, []byte) {}
func (d *dummyContractRef) ForEachStorage(callback func(key, value util.Hash) bool) {
	d.calledForEach = true
}
func (d *dummyContractRef) SubBalance(amount *big.Int) {}
func (d *dummyContractRef) AddBalance(amount *big.Int) {}
func (d *dummyContractRef) SetBalance(*big.Int)        {}
func (d *dummyContractRef) SetNonce(uint64)            {}
func (d *dummyContractRef) Balance() *big.Int          { return new(big.Int) }

type dummyStatedb struct {
	state.StateDB
}

func (*dummyStatedb) GetRefund() uint64                                 { return 1337 }
func (*dummyStatedb) GetState(_ util.Address, _ util.Hash) util.Hash    { return util.Hash{} }
func (*dummyStatedb) SetState(_ util.Address, _ util.Hash, _ util.Hash) {}

func TestStoreCapture(t *testing.T) {
	var (
		logger   = NewStructLogger(nil)
		env      = script.NewPVM(script.BlockContext{}, script.TxContext{}, &dummyStatedb{}, chainparams.TestChainConfig, script.Config{Debug: true, Tracer: logger})
		contract = script.NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 100000)
	)
	contract.Code = []byte{byte(script.PUSH1), 0x1, byte(script.PUSH1), 0x0, byte(script.SSTORE)}
	var index util.Hash
	logger.CaptureStart(env, util.Address{}, contract.Address(), false, nil, 0, nil)
	_, err := env.Interpreter().Run(contract, []byte{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(logger.storage[contract.Address()]) == 0 {
		t.Fatalf("expected exactly 1 changed value on address %x, got %d", contract.Address(),
			len(logger.storage[contract.Address()]))
	}
	exp := util.BigToHash(big.NewInt(1))
	if logger.storage[contract.Address()][index] != exp {
		t.Errorf("expected %x, got %x", exp, logger.storage[contract.Address()][index])
	}
}

// Tests that the JSON logger stops emitting step logs once the configured
// limit is reached.
func TestJSONLoggerLimit(t *testing.T) {
	for _, tc := range []struct {
		limit int
		want  int // step lines + end line
	}{
		{0, 4},
		{1, 2},
		{2, 3},
		{10, 4},
	} {
		var (
			buf      bytes.Buffer
			logger   = NewJSONLogger(&Config{Limit: tc.limit}, &buf)
			env      = script.NewPVM(script.BlockContext{}, script.TxContext{}, &dummyStatedb{}, chainparams.TestChainConfig, script.Config{Debug: true, Tracer: logger})
			contract = script.NewContract(&dummyContractRef{}, &dummyContractRef{}, new(big.Int), 100000)
		)
		contract.Code = []byte{byte(script.PUSH1), 0x1, byte(script.PUSH1), 0x0, byte(script.STOP)}
		logger.CaptureStart(env, util.Address{}, contract.Address(), false, nil, 0, nil)
		if _, err := env.Interpreter().Run(contract, []byte{}, false); err != nil {
			t.Fatal(err)
		}
		logger.CaptureEnd(nil, 0, 0, nil)
		if have := strings.Count(buf.String(), "\n"); have != tc.want {
			t.Errorf("limit %d: have %d lines, want %d\n%s", tc.limit, have, tc.want, buf.String())
		}
	}
}

// Tests that blank fields don't appear in logs when JSON marshalled, to reduce
// logs bloat and confusion. See https://github.com/ParallaxProtocol/parallax/issues/24487
func TestStructLogMarshalingOmitEmpty(t *testing.T) {
	tests := []struct {
		name string
		log  *StructLog
		want string
	}{
		{"empty err and no fields", &StructLog{},
			`{"pc":0,"op":0,"gas":"0x0","gasCost":"0x0","memSize":0,"stack":null,"depth":0,"refund":0,"opName":"STOP"}`},
		{"with err", &StructLog{Err: fmt.Errorf("this failed")},
			`{"pc":0,"op":0,"gas":"0x0","gasCost":"0x0","memSize":0,"stack":null,"depth":0,"refund":0,"opName":"STOP","error":"this failed"}`},
		{"with mem", &StructLog{Memory: make([]byte, 2), MemorySize: 2},
			`{"pc":0,"op":0,"gas":"0x0","gasCost":"0x0","memory":"0x0000","memSize":2,"stack":null,"depth":0,"refund":0,"opName":"STOP"}`},
		{"with 0-size mem", &StructLog{Memory: make([]byte, 0)},
			`{"pc":0,"op":0,"gas":"0x0","gasCost":"0x0","memSize":0,"stack":null,"depth":0,"refund":0,"opName":"STOP"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob, err := json.Marshal(tt.log)
			if err != nil {
				t.Fatal(err)
			}
			if have, want := string(blob), tt.want; have != want {
				t.Fatalf("mismatched results\n\thave: %v\n\twant: %v", have, want)
			}
		})
	}
}
