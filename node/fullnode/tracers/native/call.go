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
	"errors"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

func init() {
	register("callTracer", newCallTracer)
}

type callFrame struct {
	Type    string      `json:"type"`
	From    string      `json:"from"`
	To      string      `json:"to,omitempty"`
	Value   string      `json:"value,omitempty"`
	Gas     string      `json:"gas"`
	GasUsed string      `json:"gasUsed"`
	Input   string      `json:"input"`
	Output  string      `json:"output,omitempty"`
	Error   string      `json:"error,omitempty"`
	Calls   []callFrame `json:"calls,omitempty"`
}

type callTracer struct {
	env       *script.PVM
	callstack []callFrame
	interrupt uint32                // Atomic flag to signal execution interruption
	reason    atomic.Pointer[error] // Reason for the interruption, populated by Stop
}

// newCallTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.PVMLogger.
func newCallTracer(ctx *tracers.Context) tracers.Tracer {
	// First callframe contains tx context info
	// and is populated on start and end.
	return &callTracer{callstack: make([]callFrame, 1)}
}

// CaptureStart implements the PVMLogger interface to initialize the tracing operation.
func (t *callTracer) CaptureStart(env *script.PVM, from util.Address, to util.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env
	t.callstack[0] = callFrame{
		Type:  "CALL",
		From:  addrToHex(from),
		To:    addrToHex(to),
		Input: bytesToHex(input),
		Gas:   uintToHex(gas),
		Value: bigToHex(value),
	}
	if create {
		t.callstack[0].Type = "CREATE"
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *callTracer) CaptureEnd(output []byte, gasUsed uint64, _ time.Duration, err error) {
	t.callstack[0].GasUsed = uintToHex(gasUsed)
	if err != nil {
		t.callstack[0].Error = err.Error()
		if err.Error() == "execution reverted" && len(output) > 0 {
			t.callstack[0].Output = bytesToHex(output)
		}
	} else {
		t.callstack[0].Output = bytesToHex(output)
	}
}

// CaptureState implements the PVMLogger interface to trace a single step of VM execution.
func (t *callTracer) CaptureState(pc uint64, op script.OpCode, gas, cost uint64, scope *script.ScopeContext, rData []byte, depth int, err error) {
}

// CaptureFault implements the PVMLogger interface to trace an execution fault.
func (t *callTracer) CaptureFault(pc uint64, op script.OpCode, gas, cost uint64, _ *script.ScopeContext, depth int, err error) {
}

// CaptureEnter is called when PVM enters a new scope (via call, create or selfdestruct).
func (t *callTracer) CaptureEnter(typ script.OpCode, from util.Address, to util.Address, input []byte, gas uint64, value *big.Int) {
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		t.env.Cancel()
		return
	}

	call := callFrame{
		Type:  typ.String(),
		From:  addrToHex(from),
		To:    addrToHex(to),
		Input: bytesToHex(input),
		Gas:   uintToHex(gas),
		Value: bigToHex(value),
	}
	t.callstack = append(t.callstack, call)
}

// CaptureExit is called when PVM exits a scope, even if the scope didn't
// execute any code.
func (t *callTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	size := len(t.callstack)
	if size <= 1 {
		return
	}
	// pop call
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size -= 1

	call.GasUsed = uintToHex(gasUsed)
	if err == nil {
		call.Output = bytesToHex(output)
	} else {
		call.Error = err.Error()
		if call.Type == "CREATE" || call.Type == "CREATE2" {
			call.To = ""
		}
	}
	t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
}

func (*callTracer) CaptureTxStart(gasLimit uint64) {}

func (*callTracer) CaptureTxEnd(restGas uint64) {}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *callTracer) GetResult() (json.RawMessage, error) {
	if len(t.callstack) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}
	res, err := json.Marshal(t.callstack[0])
	if err != nil {
		return nil, err
	}
	if p := t.reason.Load(); p != nil {
		return json.RawMessage(res), *p
	}
	return json.RawMessage(res), nil
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *callTracer) Stop(err error) {
	t.reason.Store(&err)
	atomic.StoreUint32(&t.interrupt, 1)
}

func bytesToHex(s []byte) string {
	return "0x" + util.Bytes2Hex(s)
}

func bigToHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return "0x" + n.Text(16)
}

func uintToHex(n uint64) string {
	return "0x" + strconv.FormatUint(n, 16)
}

func addrToHex(a util.Address) string {
	return strings.ToLower(a.Hex())
}
