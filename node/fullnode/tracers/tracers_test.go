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

package tracers

import (
	"math/big"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers/logger"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/tests"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"
)

func BenchmarkTransactionTrace(b *testing.B) {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	from := crypto.PubkeyToAddress(key.PublicKey)
	gas := uint64(1000000) // 1M gas
	to := util.HexToAddress("0x00000000000000000000000000000000deadbeef")
	signer := types.LatestSignerForChainID(big.NewInt(1337))
	tx, err := types.SignNewTx(key, signer,
		&types.LegacyTx{
			Nonce:    1,
			GasPrice: big.NewInt(500),
			Gas:      gas,
			To:       &to,
		})
	if err != nil {
		b.Fatal(err)
	}
	txContext := script.TxContext{
		Origin:   from,
		GasPrice: tx.GasPrice(),
	}
	context := script.BlockContext{
		CanTransfer: validation.CanTransfer,
		Transfer:    validation.Transfer,
		Coinbase:    util.Address{},
		BlockNumber: new(big.Int).SetUint64(uint64(5)),
		Time:        new(big.Int).SetUint64(uint64(5)),
		Difficulty:  big.NewInt(0xffffffff),
		GasLimit:    gas,
		BaseFee:     big.NewInt(8),
	}
	alloc := validation.GenesisAlloc{}
	// The code pushes 'deadbeef' into memory, then the other params, and calls CREATE2, then returns
	// the address
	loop := []byte{
		byte(script.JUMPDEST),
		byte(script.PUSH1), 0, // jumpdestination
		byte(script.JUMP),
	}
	alloc[util.HexToAddress("0x00000000000000000000000000000000deadbeef")] = validation.GenesisAccount{
		Nonce:   1,
		Code:    loop,
		Balance: big.NewInt(1),
	}
	alloc[from] = validation.GenesisAccount{
		Nonce:   1,
		Code:    []byte{},
		Balance: big.NewInt(500000000000000),
	}
	_, statedb := tests.MakePreState(rawdb.NewMemoryDatabase(), alloc, false)
	// Create the tracer, the PVM environment and run it
	tracer := logger.NewStructLogger(&logger.Config{
		Debug: false,
		// DisableStorage: true,
		// EnableMemory: false,
		// EnableReturnData: false,
	})
	pvm := script.NewPVM(context, txContext, statedb, chainparams.AllXHashProtocolChanges, script.Config{Debug: true, Tracer: tracer})
	msg, err := tx.AsMessage(signer, nil)
	if err != nil {
		b.Fatalf("failed to prepare transaction for tracing: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		snap := statedb.Snapshot()
		st := validation.NewStateTransition(pvm, msg, new(validation.GasPool).AddGas(tx.Gas()))
		_, err = st.TransitionDb()
		if err != nil {
			b.Fatal(err)
		}
		statedb.RevertToSnapshot(snap)
		if have, want := len(tracer.StructLogs()), 244752; have != want {
			b.Fatalf("trace wrong, want %d steps, have %d", want, have)
		}
		tracer.Reset()
	}
}

func TestMemCopying(t *testing.T) {
	for i, tc := range []struct {
		memsize  int64
		offset   int64
		size     int64
		wantErr  string
		wantSize int
	}{
		{0, 0, 100, "", 100},    // Should pad up to 100
		{0, 100, 0, "", 0},      // No need to pad (0 size)
		{100, 50, 100, "", 100}, // Should pad 100-150
		{100, 50, 5, "", 5},     // Wanted range fully within memory
		{100, -50, 0, "offset or size must not be negative", 0},                        // Error
		{0, 1, 1024*1024 + 1, "reached limit for padding memory slice: 1048578", 0},    // Error
		{10, 0, 1024*1024 + 100, "reached limit for padding memory slice: 1048666", 0}, // Error
	} {
		mem := script.NewMemory()
		mem.Resize(uint64(tc.memsize))
		cpy, err := GetMemoryCopyPadded(mem, tc.offset, tc.size)
		if want := tc.wantErr; want != "" {
			if err == nil {
				t.Fatalf("test %d: want '%v' have no error", i, want)
			}
			if have := err.Error(); want != have {
				t.Fatalf("test %d: want '%v' have '%v'", i, want, have)
			}
			continue
		}
		if err != nil {
			t.Fatalf("test %d: unexpected error: %v", i, err)
		}
		if want, have := tc.wantSize, len(cpy); have != want {
			t.Fatalf("test %d: want %v have %v", i, want, have)
		}
	}
}
