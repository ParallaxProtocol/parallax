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

package script

import (
	"math/big"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/math"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"
	"github.com/ParallaxProtocol/parallax/v2/validation/state"
)

var loopInterruptTests = []string{
	// infinite loop using JUMP: push(2) jumpdest dup1 jump
	"60025b8056",
	// infinite loop using JUMPI: push(1) push(4) jumpdest dup2 dup2 jumpi
	"600160045b818157",
}

func TestLoopInterrupt(t *testing.T) {
	address := util.BytesToAddress([]byte("contract"))
	vmctx := BlockContext{
		Transfer: func(StateDB, util.Address, util.Address, *big.Int) {},
	}

	for i, tt := range loopInterruptTests {
		statedb, _ := state.New(util.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		statedb.CreateAccount(address)
		statedb.SetCode(address, util.Hex2Bytes(tt))
		statedb.Finalise(true)

		pvm := NewPVM(vmctx, TxContext{}, statedb, chainparams.AllXHashProtocolChanges, Config{})

		errChannel := make(chan error)
		timeout := make(chan bool)

		go func(pvm *PVM) {
			_, _, err := pvm.Call(AccountRef(util.Address{}), address, nil, math.MaxUint64, new(big.Int))
			errChannel <- err
		}(pvm)

		go func() {
			<-time.After(time.Second)
			timeout <- true
		}()

		pvm.Cancel()

		select {
		case <-timeout:
			t.Errorf("test %d timed out", i)
		case err := <-errChannel:
			if err != nil {
				t.Errorf("test %d failure: %v", i, err)
			}
		}
	}
}

// TestExtraEipsActivation checks that only successfully activated extra EIPs
// are reported back in the interpreter config.
func TestExtraEipsActivation(t *testing.T) {
	statedb, _ := state.New(util.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	pvm := NewPVM(BlockContext{}, TxContext{}, statedb, chainparams.AllXHashProtocolChanges, Config{ExtraEips: []int{1, 2, 3855}})

	if have := pvm.interpreter.cfg.ExtraEips; len(have) != 1 || have[0] != 3855 {
		t.Fatalf("activated extra eips mismatch: have %v, want [3855]", have)
	}
}
