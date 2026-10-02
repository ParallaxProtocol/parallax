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

package native

import (
	"encoding/json"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
)

func init() {
	register("prestateTracer", newPrestateTracer)
}

type (
	prestate = map[util.Address]*account
	account  struct {
		Balance string                  `json:"balance"`
		Nonce   uint64                  `json:"nonce"`
		Code    string                  `json:"code"`
		Storage map[util.Hash]util.Hash `json:"storage"`
	}
)

type prestateTracer struct {
	env       *script.PVM
	prestate  prestate
	create    bool
	to        util.Address
	gasLimit  uint64 // Amount of gas bought for the whole tx
	interrupt uint32 // Atomic flag to signal execution interruption
	reason    error  // Textual reason for the interruption
}

func newPrestateTracer(ctx *tracers.Context) tracers.Tracer {
	// First callframe contains tx context info
	// and is populated on start and end.
	return &prestateTracer{prestate: prestate{}}
}

// CaptureStart implements the PVMLogger interface to initialize the tracing operation.
func (t *prestateTracer) CaptureStart(env *script.PVM, from util.Address, to util.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env
	t.create = create
	t.to = to

	t.lookupAccount(from)
	t.lookupAccount(to)

	// The recipient balance includes the value transferred.
	toBal := hexutil.MustDecodeBig(t.prestate[to].Balance)
	toBal = new(big.Int).Sub(toBal, value)
	t.prestate[to].Balance = hexutil.EncodeBig(toBal)

	// The sender balance is after reducing: value and gasLimit.
	// We need to re-add them to get the pre-tx balance.
	fromBal := hexutil.MustDecodeBig(t.prestate[from].Balance)
	gasPrice := env.TxContext.GasPrice
	consumedGas := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(t.gasLimit))
	fromBal.Add(fromBal, new(big.Int).Add(value, consumedGas))
	t.prestate[from].Balance = hexutil.EncodeBig(fromBal)
	t.prestate[from].Nonce--
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *prestateTracer) CaptureEnd(output []byte, gasUsed uint64, _ time.Duration, err error) {
	if t.create {
		// Exclude created contract.
		delete(t.prestate, t.to)
	}
}

// CaptureState implements the PVMLogger interface to trace a single step of VM execution.
func (t *prestateTracer) CaptureState(pc uint64, op script.OpCode, gas, cost uint64, scope *script.ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		return
	}
	stack := scope.Stack
	stackData := stack.Data()
	stackLen := len(stackData)
	switch {
	case stackLen >= 1 && (op == script.SLOAD || op == script.SSTORE):
		slot := util.Hash(stackData[stackLen-1].Bytes32())
		t.lookupStorage(scope.Contract.Address(), slot)
	case stackLen >= 1 && (op == script.EXTCODECOPY || op == script.EXTCODEHASH || op == script.EXTCODESIZE || op == script.BALANCE || op == script.SELFDESTRUCT):
		addr := util.Address(stackData[stackLen-1].Bytes20())
		t.lookupAccount(addr)
	case stackLen >= 5 && (op == script.DELEGATECALL || op == script.CALL || op == script.STATICCALL || op == script.CALLCODE):
		addr := util.Address(stackData[stackLen-2].Bytes20())
		t.lookupAccount(addr)
	case op == script.CREATE:
		addr := scope.Contract.Address()
		nonce := t.env.StateDB.GetNonce(addr)
		t.lookupAccount(crypto.CreateAddress(addr, nonce))
	case stackLen >= 4 && op == script.CREATE2:
		offset := stackData[stackLen-2]
		size := stackData[stackLen-3]
		init, err := tracers.GetMemoryCopyPadded(scope.Memory, int64(offset.Uint64()), int64(size.Uint64()))
		if err != nil {
			logging.Warn("failed to copy CREATE2 input", "err", err, "tracer", "prestateTracer", "offset", offset, "size", size)
			return
		}
		inithash := crypto.Keccak256(init)
		salt := stackData[stackLen-4]
		t.lookupAccount(crypto.CreateAddress2(scope.Contract.Address(), salt.Bytes32(), inithash))
	}
}

// CaptureFault implements the PVMLogger interface to trace an execution fault.
func (t *prestateTracer) CaptureFault(pc uint64, op script.OpCode, gas, cost uint64, _ *script.ScopeContext, depth int, err error) {
}

// CaptureEnter is called when PVM enters a new scope (via call, create or selfdestruct).
func (t *prestateTracer) CaptureEnter(typ script.OpCode, from util.Address, to util.Address, input []byte, gas uint64, value *big.Int) {
}

// CaptureExit is called when PVM exits a scope, even if the scope didn't
// execute any code.
func (t *prestateTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
}

func (t *prestateTracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

func (t *prestateTracer) CaptureTxEnd(restGas uint64) {}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *prestateTracer) GetResult() (json.RawMessage, error) {
	res, err := json.Marshal(t.prestate)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(res), t.reason
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *prestateTracer) Stop(err error) {
	t.reason = err
	atomic.StoreUint32(&t.interrupt, 1)
}

// lookupAccount fetches details of an account and adds it to the prestate
// if it doesn't exist there.
func (t *prestateTracer) lookupAccount(addr util.Address) {
	if _, ok := t.prestate[addr]; ok {
		return
	}
	t.prestate[addr] = &account{
		Balance: bigToHex(t.env.StateDB.GetBalance(addr)),
		Nonce:   t.env.StateDB.GetNonce(addr),
		Code:    bytesToHex(t.env.StateDB.GetCode(addr)),
		Storage: make(map[util.Hash]util.Hash),
	}
}

// lookupStorage fetches the requested storage slot and adds
// it to the prestate of the given contract. It assumes `lookupAccount`
// has been performed on the contract before.
func (t *prestateTracer) lookupStorage(addr util.Address, key util.Hash) {
	if _, ok := t.prestate[addr].Storage[key]; ok {
		return
	}
	t.prestate[addr].Storage[key] = t.env.StateDB.GetState(addr, key)
}
