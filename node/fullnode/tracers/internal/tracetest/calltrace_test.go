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

package tracetest

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/tests"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
	"github.com/ParallaxProtocol/parallax/v2/util/math"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"

	// Force-load native and js pacakges, to trigger registration
	_ "github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers/js"
	_ "github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers/native"
)

// To generate a new callTracer test, copy paste the makeTest method below into
// a Prlx console and call it with a transaction hash you which to export.

/*
// makeTest generates a callTracer test by running a prestate reassembled and a
// call trace run, assembling all the gathered information into a test case.
var makeTest = function(tx, rewind) {
  // Generate the genesis block from the block, transaction and prestate data
  var block   = eth.getBlock(eth.getTransaction(tx).blockHash);
  var genesis = eth.getBlock(block.parentHash);

  delete genesis.gasUsed;
  delete genesis.logsBloom;
  delete genesis.parentHash;
  delete genesis.receiptsRoot;
  delete genesis.sha3Uncles;
  delete genesis.size;
  delete genesis.transactions;
  delete genesis.transactionsRoot;
  delete genesis.uncles;

  genesis.gasLimit  = genesis.gasLimit.toString();
  genesis.number    = genesis.number.toString();
  genesis.timestamp = genesis.timestamp.toString();

  genesis.alloc = debug.traceTransaction(tx, {tracer: "prestateTracer", rewind: rewind});
  for (var key in genesis.alloc) {
    genesis.alloc[key].nonce = genesis.alloc[key].nonce.toString();
  }
  genesis.config = admin.nodeInfo.protocols.eth.config;

  // Generate the call trace and produce the test input
  var result = debug.traceTransaction(tx, {tracer: "callTracer", rewind: rewind});
  delete result.time;

  console.log(JSON.stringify({
    genesis: genesis,
    context: {
      number:     block.number.toString(),
      difficulty: block.difficulty,
      timestamp:  block.timestamp.toString(),
      gasLimit:   block.gasLimit.toString(),
      miner:      block.miner,
    },
    input:  eth.getRawTransaction(tx),
    result: result,
  }, null, 2));
}
*/

type callContext struct {
	Number     math.HexOrDecimal64   `json:"number"`
	Difficulty *math.HexOrDecimal256 `json:"difficulty"`
	Time       math.HexOrDecimal64   `json:"timestamp"`
	GasLimit   math.HexOrDecimal64   `json:"gasLimit"`
	Miner      util.Address          `json:"miner"`
}

// callTrace is the result of a callTracer run.
type callTrace struct {
	Type    string          `json:"type"`
	From    util.Address    `json:"from"`
	To      util.Address    `json:"to"`
	Input   hexutil.Bytes   `json:"input"`
	Output  hexutil.Bytes   `json:"output"`
	Gas     *hexutil.Uint64 `json:"gas,omitempty"`
	GasUsed *hexutil.Uint64 `json:"gasUsed,omitempty"`
	Value   *hexutil.Big    `json:"value,omitempty"`
	Error   string          `json:"error,omitempty"`
	Calls   []callTrace     `json:"calls,omitempty"`
}

// callTracerTest defines a single test to check the call tracer against.
type callTracerTest struct {
	Genesis *validation.Genesis `json:"genesis"`
	Context *callContext        `json:"context"`
	Input   string              `json:"input"`
	Result  *callTrace          `json:"result"`
}

// Iterates over all the input-output datasets in the tracer test harness and
// runs the JavaScript tracers against them.
func TestCallTracerLegacy(t *testing.T) {
	testCallTracer("callTracerLegacy", "call_tracer_legacy", t)
}

func TestCallTracerNative(t *testing.T) {
	testCallTracer("callTracer", "call_tracer", t)
}

func testCallTracer(tracerName string, dirPath string, t *testing.T) {
	files, err := os.ReadDir(filepath.Join("testdata", dirPath))
	if err != nil {
		t.Fatalf("failed to retrieve tracer test suite: %v", err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(camel(strings.TrimSuffix(file.Name(), ".json")), func(t *testing.T) {
			t.Parallel()

			var (
				test = new(callTracerTest)
				tx   = new(types.Transaction)
			)
			// Call tracer test found, read if from disk
			if blob, err := os.ReadFile(filepath.Join("testdata", dirPath, file.Name())); err != nil {
				t.Fatalf("failed to read testcase: %v", err)
			} else if err := json.Unmarshal(blob, test); err != nil {
				t.Fatalf("failed to parse testcase: %v", err)
			}
			if err := rlp.DecodeBytes(util.FromHex(test.Input), tx); err != nil {
				t.Fatalf("failed to parse testcase input: %v", err)
			}
			// Configure a blockchain with the given prestate
			var (
				signer    = types.MakeSigner(test.Genesis.Config, new(big.Int).SetUint64(uint64(test.Context.Number)))
				origin, _ = signer.Sender(tx)
				txContext = script.TxContext{
					Origin:   origin,
					GasPrice: tx.GasPrice(),
				}
				context = script.BlockContext{
					CanTransfer: validation.CanTransfer,
					Transfer:    validation.Transfer,
					Coinbase:    test.Context.Miner,
					BlockNumber: new(big.Int).SetUint64(uint64(test.Context.Number)),
					Time:        new(big.Int).SetUint64(uint64(test.Context.Time)),
					Difficulty:  (*big.Int)(test.Context.Difficulty),
					GasLimit:    uint64(test.Context.GasLimit),
				}
				_, statedb = tests.MakePreState(rawdb.NewMemoryDatabase(), test.Genesis.Alloc, false)
			)
			tracer, err := tracers.New(tracerName, new(tracers.Context))
			if err != nil {
				t.Fatalf("failed to create call tracer: %v", err)
			}
			pvm := script.NewPVM(context, txContext, statedb, test.Genesis.Config, script.Config{Debug: true, Tracer: tracer})
			msg, err := tx.AsMessage(signer, nil)
			if err != nil {
				t.Fatalf("failed to prepare transaction for tracing: %v", err)
			}
			st := validation.NewStateTransition(pvm, msg, new(validation.GasPool).AddGas(tx.Gas()))
			if _, err = st.TransitionDb(); err != nil {
				t.Fatalf("failed to execute transaction: %v", err)
			}
			// Retrieve the trace result and compare against the etalon
			res, err := tracer.GetResult()
			if err != nil {
				t.Fatalf("failed to retrieve trace result: %v", err)
			}
			ret := new(callTrace)
			if err := json.Unmarshal(res, ret); err != nil {
				t.Fatalf("failed to unmarshal trace result: %v", err)
			}

			if !jsonEqual(ret, test.Result) {
				// uncomment this for easier debugging
				// have, _ := json.MarshalIndent(ret, "", " ")
				// want, _ := json.MarshalIndent(test.Result, "", " ")
				// t.Fatalf("trace mismatch: \nhave %+v\nwant %+v", string(have), string(want))
				t.Fatalf("trace mismatch: \nhave %+v\nwant %+v", ret, test.Result)
			}
		})
	}
}

// jsonEqual is similar to reflect.DeepEqual, but does a 'bounce' via json prior to
// comparison
func jsonEqual(x, y any) bool {
	xTrace := new(callTrace)
	yTrace := new(callTrace)
	if xj, err := json.Marshal(x); err == nil {
		json.Unmarshal(xj, xTrace)
	} else {
		return false
	}
	if yj, err := json.Marshal(y); err == nil {
		json.Unmarshal(yj, yTrace)
	} else {
		return false
	}
	return reflect.DeepEqual(xTrace, yTrace)
}

// camel converts a snake cased input string into a camel cased output.
func camel(str string) string {
	pieces := strings.Split(str, "_")
	for i := 1; i < len(pieces); i++ {
		pieces[i] = string(unicode.ToUpper(rune(pieces[i][0]))) + pieces[i][1:]
	}
	return strings.Join(pieces, "")
}

func BenchmarkTracers(b *testing.B) {
	files, err := os.ReadDir(filepath.Join("testdata", "call_tracer"))
	if err != nil {
		b.Fatalf("failed to retrieve tracer test suite: %v", err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		b.Run(camel(strings.TrimSuffix(file.Name(), ".json")), func(b *testing.B) {
			blob, err := os.ReadFile(filepath.Join("testdata", "call_tracer", file.Name()))
			if err != nil {
				b.Fatalf("failed to read testcase: %v", err)
			}
			test := new(callTracerTest)
			if err := json.Unmarshal(blob, test); err != nil {
				b.Fatalf("failed to parse testcase: %v", err)
			}
			benchTracer("callTracer", test, b)
		})
	}
}

func benchTracer(tracerName string, test *callTracerTest, b *testing.B) {
	// Configure a blockchain with the given prestate
	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(util.FromHex(test.Input), tx); err != nil {
		b.Fatalf("failed to parse testcase input: %v", err)
	}
	signer := types.MakeSigner(test.Genesis.Config, new(big.Int).SetUint64(uint64(test.Context.Number)))
	msg, err := tx.AsMessage(signer, nil)
	if err != nil {
		b.Fatalf("failed to prepare transaction for tracing: %v", err)
	}
	origin, _ := signer.Sender(tx)
	txContext := script.TxContext{
		Origin:   origin,
		GasPrice: tx.GasPrice(),
	}
	context := script.BlockContext{
		CanTransfer: validation.CanTransfer,
		Transfer:    validation.Transfer,
		Coinbase:    test.Context.Miner,
		BlockNumber: new(big.Int).SetUint64(uint64(test.Context.Number)),
		Time:        new(big.Int).SetUint64(uint64(test.Context.Time)),
		Difficulty:  (*big.Int)(test.Context.Difficulty),
		GasLimit:    uint64(test.Context.GasLimit),
	}
	_, statedb := tests.MakePreState(rawdb.NewMemoryDatabase(), test.Genesis.Alloc, false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracer, err := tracers.New(tracerName, new(tracers.Context))
		if err != nil {
			b.Fatalf("failed to create call tracer: %v", err)
		}
		pvm := script.NewPVM(context, txContext, statedb, test.Genesis.Config, script.Config{Debug: true, Tracer: tracer})
		snap := statedb.Snapshot()
		st := validation.NewStateTransition(pvm, msg, new(validation.GasPool).AddGas(tx.Gas()))
		if _, err = st.TransitionDb(); err != nil {
			b.Fatalf("failed to execute transaction: %v", err)
		}
		if _, err = tracer.GetResult(); err != nil {
			b.Fatal(err)
		}
		statedb.RevertToSnapshot(snap)
	}
}

// TestZeroValueToNotExitCall tests the calltracer(s) on the following:
// Tx to A, A calls B with zero value. B does not already exist.
// Expected: that enter/exit is invoked and the inner call is shown in the result
func TestZeroValueToNotExitCall(t *testing.T) {
	to := util.HexToAddress("0x00000000000000000000000000000000deadbeef")
	privkey, err := crypto.HexToECDSA("0000000000000000deadbeef00000000000000000000000000000000deadbeef")
	if err != nil {
		t.Fatalf("err %v", err)
	}
	signer := types.NewEIP155Signer(big.NewInt(1))
	tx, err := types.SignNewTx(privkey, signer, &types.LegacyTx{
		GasPrice: big.NewInt(0),
		Gas:      50000,
		To:       &to,
	})
	if err != nil {
		t.Fatalf("err %v", err)
	}
	origin, _ := signer.Sender(tx)
	txContext := script.TxContext{
		Origin:   origin,
		GasPrice: big.NewInt(1),
	}
	context := script.BlockContext{
		CanTransfer: validation.CanTransfer,
		Transfer:    validation.Transfer,
		Coinbase:    util.Address{},
		BlockNumber: new(big.Int).SetUint64(8000000),
		Time:        new(big.Int).SetUint64(5),
		Difficulty:  big.NewInt(0x30000),
		GasLimit:    uint64(6000000),
	}
	code := []byte{
		byte(script.PUSH1), 0x0, byte(script.DUP1), byte(script.DUP1), byte(script.DUP1),
		byte(script.DUP1), byte(script.PUSH1), 0xff, byte(script.GAS),
		byte(script.CALL),
	}
	alloc := validation.GenesisAlloc{
		to: validation.GenesisAccount{
			Nonce: 1,
			Code:  code,
		},
		origin: validation.GenesisAccount{
			Nonce:   0,
			Balance: big.NewInt(500000000000000),
		},
	}
	_, statedb := tests.MakePreState(rawdb.NewMemoryDatabase(), alloc, false)
	// Create the tracer, the PVM environment and run it
	tracer, err := tracers.New("callTracer", nil)
	if err != nil {
		t.Fatalf("failed to create call tracer: %v", err)
	}
	pvm := script.NewPVM(context, txContext, statedb, chainparams.MainnetChainConfig, script.Config{Debug: true, Tracer: tracer})
	msg, err := tx.AsMessage(signer, nil)
	if err != nil {
		t.Fatalf("failed to prepare transaction for tracing: %v", err)
	}
	st := validation.NewStateTransition(pvm, msg, new(validation.GasPool).AddGas(tx.Gas()))
	if _, err = st.TransitionDb(); err != nil {
		t.Fatalf("failed to execute transaction: %v", err)
	}
	// Retrieve the trace result and compare against the etalon
	res, err := tracer.GetResult()
	if err != nil {
		t.Fatalf("failed to retrieve trace result: %v", err)
	}
	have := new(callTrace)
	if err := json.Unmarshal(res, have); err != nil {
		t.Fatalf("failed to unmarshal trace result: %v", err)
	}
	wantStr := `{"type":"CALL","from":"0x682a80a6f560eec50d54e63cbeda1c324c5f8d1b","to":"0x00000000000000000000000000000000deadbeef","value":"0x0","gas":"0x7148","gasUsed":"0xa3c","input":"0x","output":"0x","calls":[{"type":"CALL","from":"0x00000000000000000000000000000000deadbeef","to":"0x00000000000000000000000000000000000000ff","value":"0x0","gas":"0x6570","gasUsed":"0x0","input":"0x","output":"0x"}]}`
	want := new(callTrace)
	json.Unmarshal([]byte(wantStr), want)
	if !jsonEqual(have, want) {
		t.Error("have != want")
	}
}

// TestPrestateTracerInternals runs the prestate tracer over hand-crafted
// bytecode exercising edge cases that previously crashed the tracer.
func TestPrestateTracerInternals(t *testing.T) {
	var (
		to        = util.HexToAddress("0x00000000000000000000000000000000deadbeef")
		origin    = util.HexToAddress("0x00000000000000000000000000000000feed")
		txContext = script.TxContext{
			Origin:   origin,
			GasPrice: big.NewInt(1),
		}
		context = script.BlockContext{
			CanTransfer: validation.CanTransfer,
			Transfer:    validation.Transfer,
			Coinbase:    util.Address{},
			BlockNumber: new(big.Int).SetUint64(8000000),
			Time:        new(big.Int).SetUint64(5),
			Difficulty:  big.NewInt(0x30000),
			GasLimit:    uint64(6000000),
		}
	)
	for _, tc := range []struct {
		name string
		code []byte
		want string
	}{
		{
			// Leads to OOM on the prestate tracer
			name: "CREATE2 OOM",
			code: []byte{
				byte(script.PUSH1), 0x1,
				byte(script.PUSH1), 0x0,
				byte(script.MSTORE),
				byte(script.PUSH1), 0x1,
				byte(script.PUSH5), 0xff, 0xff, 0xff, 0xff, 0xff,
				byte(script.PUSH1), 0x1,
				byte(script.PUSH1), 0x0,
				byte(script.CREATE2),
				byte(script.PUSH1), 0xff,
				byte(script.PUSH1), 0x0,
				byte(script.LOG0),
			},
			want: `{"0x000000000000000000000000000000000000feed":{"balance":"0x1c6bf52647880","nonce":0,"code":"0x","storage":{}},"0x00000000000000000000000000000000deadbeef":{"balance":"0x0","nonce":0,"code":"0x6001600052600164ffffffffff60016000f560ff6000a0","storage":{}}}`,
		},
		{
			// CREATE2 which requires padding memory by prestate tracer
			name: "CREATE2 Memory padding",
			code: []byte{
				byte(script.PUSH1), 0x1,
				byte(script.PUSH1), 0x0,
				byte(script.MSTORE),
				byte(script.PUSH1), 0x1,
				byte(script.PUSH1), 0xff,
				byte(script.PUSH1), 0x1,
				byte(script.PUSH1), 0x0,
				byte(script.CREATE2),
				byte(script.PUSH1), 0xff,
				byte(script.PUSH1), 0x0,
				byte(script.LOG0),
			},
			want: `{"0x000000000000000000000000000000000000feed":{"balance":"0x1c6bf52647880","nonce":0,"code":"0x","storage":{}},"0x00000000000000000000000000000000deadbeef":{"balance":"0x0","nonce":0,"code":"0x6001600052600160ff60016000f560ff6000a0","storage":{}},"0x91ff9a805d36f54e3e272e230f3e3f5c1b330804":{"balance":"0x0","nonce":0,"code":"0x","storage":{}}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, statedb := tests.MakePreState(rawdb.NewMemoryDatabase(),
				validation.GenesisAlloc{
					to: validation.GenesisAccount{
						Code: tc.code,
					},
					origin: validation.GenesisAccount{
						Balance: big.NewInt(500000000000000),
					},
				}, false)
			tracer, err := tracers.New("prestateTracer", nil)
			if err != nil {
				t.Fatalf("failed to create prestate tracer: %v", err)
			}
			pvm := script.NewPVM(context, txContext, statedb, chainparams.MainnetChainConfig, script.Config{Debug: true, Tracer: tracer})
			msg := types.NewMessage(origin, &to, 0, big.NewInt(0), 80000, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, false)
			st := validation.NewStateTransition(pvm, msg, new(validation.GasPool).AddGas(msg.Gas()))
			if _, err := st.TransitionDb(); err != nil {
				t.Fatalf("failed to execute transaction: %v", err)
			}
			res, err := tracer.GetResult()
			if err != nil {
				t.Fatalf("failed to retrieve trace result: %v", err)
			}
			if string(res) != tc.want {
				t.Errorf("trace mismatch\n have: %s\n want: %s", res, tc.want)
			}
		})
	}
}
