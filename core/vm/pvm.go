// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/common"
	"github.com/ParallaxProtocol/parallax/crypto"
	"github.com/ParallaxProtocol/parallax/params"
	"github.com/holiman/uint256"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH PVM op code.
	GetHashFunc func(uint64) common.Hash
)

func (pvm *PVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	var precompiles map[common.Address]PrecompiledContract
	switch {
	case pvm.chainRules.IsBerlin:
		precompiles = PrecompiledContractsBerlin
	case pvm.chainRules.IsIstanbul:
		precompiles = PrecompiledContractsIstanbul
	case pvm.chainRules.IsByzantium:
		precompiles = PrecompiledContractsByzantium
	default:
		precompiles = PrecompiledContractsHomestead
	}
	p, ok := precompiles[addr]
	return p, ok
}

// BlockContext provides the PVM with auxiliary information. Once provided
// it shouldn't be modified.
type BlockContext struct {
	// CanTransfer returns whether the account contains
	// sufficient laxes to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers laxes from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
	BaseFee     *big.Int       // Provides information for BASEFEE
	Random      *common.Hash   // Provides information for RANDOM
}

// TxContext provides the PVM with information about a transaction.
// All fields can change between transactions.
type TxContext struct {
	// Message information
	Origin   common.Address // Provides information for ORIGIN
	GasPrice *big.Int       // Provides information for GASPRICE
}

// PVM is the Parallax Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The PVM should never be reused and is not thread safe.
type PVM struct {
	// Context provides auxiliary blockchain related information
	Context BlockContext
	TxContext
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// pvm.
	Config Config
	// global (to this context) parallax virtual machine
	// used throughout the execution of the tx.
	interpreter *PVMInterpreter
	// abort is used to abort the PVM calling operations
	// NOTE: must be set atomically
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64
}

// NewPVM returns a new PVM. The returned PVM is not thread safe and should
// only ever be used *once*.
func NewPVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *PVM {
	pvm := &PVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		Config:      config,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil),
	}
	pvm.interpreter = NewPVMInterpreter(pvm, config)
	return pvm
}

// Reset resets the PVM with a new transaction context.Reset
// This is not threadsafe and should only be done very cautiously.
func (pvm *PVM) Reset(txCtx TxContext, statedb StateDB) {
	pvm.TxContext = txCtx
	pvm.StateDB = statedb
}

// Cancel cancels any running PVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (pvm *PVM) Cancel() {
	atomic.StoreInt32(&pvm.abort, 1)
}

// Cancelled returns true if Cancel has been called
func (pvm *PVM) Cancelled() bool {
	return atomic.LoadInt32(&pvm.abort) == 1
}

// Interpreter returns the current interpreter
func (pvm *PVM) Interpreter() *PVMInterpreter {
	return pvm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (pvm *PVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if pvm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if value.Sign() != 0 && !pvm.Context.CanTransfer(pvm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := pvm.StateDB.Snapshot()
	p, isPrecompile := pvm.precompile(addr)

	if !pvm.StateDB.Exist(addr) {
		if !isPrecompile && pvm.chainRules.IsEIP158 && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer
			if pvm.Config.Debug {
				if pvm.depth == 0 {
					pvm.Config.Tracer.CaptureStart(pvm, caller.Address(), addr, false, input, gas, value)
					pvm.Config.Tracer.CaptureEnd(ret, 0, 0, nil)
				} else {
					pvm.Config.Tracer.CaptureEnter(CALL, caller.Address(), addr, input, gas, value)
					pvm.Config.Tracer.CaptureExit(ret, 0, nil)
				}
			}
			return nil, gas, nil
		}
		pvm.StateDB.CreateAccount(addr)
	}
	pvm.Context.Transfer(pvm.StateDB, caller.Address(), addr, value)

	// Capture the tracer start/end events in debug mode
	if pvm.Config.Debug {
		if pvm.depth == 0 {
			pvm.Config.Tracer.CaptureStart(pvm, caller.Address(), addr, false, input, gas, value)
			defer func(startGas uint64, startTime time.Time) { // Lazy evaluation of the parameters
				pvm.Config.Tracer.CaptureEnd(ret, startGas-gas, time.Since(startTime), err)
			}(gas, time.Now())
		} else {
			// Handle tracer events for entering and exiting a call frame
			pvm.Config.Tracer.CaptureEnter(CALL, caller.Address(), addr, input, gas, value)
			defer func(startGas uint64) {
				pvm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
			}(gas)
		}
	}

	if isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		// Initialise a new contract and set the code that is to be used by the pvm.
		// The contract is a scoped environment for this execution context only.
		code := pvm.StateDB.GetCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil // gas is unchanged
		} else {
			addrCopy := addr
			// If the account has no code, we can abort here
			// The depth-check is already done, and precompiles handled above
			contract := NewContract(caller, AccountRef(addrCopy), value, gas)
			contract.SetCallCode(&addrCopy, pvm.StateDB.GetCodeHash(addrCopy), code)
			ret, err = pvm.interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}
	// When an error was returned by the PVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		pvm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
		// TODO: consider clearing up unused snapshots:
		//} else {
		//	pvm.StateDB.DiscardSnapshot(snapshot)
	}
	return ret, gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (pvm *PVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if pvm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	// Note although it's noop to transfer X laxes to caller itself. But
	// if caller doesn't have enough balance, it would be an error to allow
	// over-charging itself. So the check here is necessary.
	if !pvm.Context.CanTransfer(pvm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := pvm.StateDB.Snapshot()

	// Invoke tracer hooks that signal entering/exiting a call frame
	if pvm.Config.Debug {
		pvm.Config.Tracer.CaptureEnter(CALLCODE, caller.Address(), addr, input, gas, value)
		defer func(startGas uint64) {
			pvm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := pvm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the pvm.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, AccountRef(caller.Address()), value, gas)
		contract.SetCallCode(&addrCopy, pvm.StateDB.GetCodeHash(addrCopy), pvm.StateDB.GetCode(addrCopy))
		ret, err = pvm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		pvm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (pvm *PVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if pvm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	snapshot := pvm.StateDB.Snapshot()

	// Invoke tracer hooks that signal entering/exiting a call frame
	if pvm.Config.Debug {
		pvm.Config.Tracer.CaptureEnter(DELEGATECALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			pvm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := pvm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		// Initialise a new contract and make initialise the delegate values
		contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
		contract.SetCallCode(&addrCopy, pvm.StateDB.GetCodeHash(addrCopy), pvm.StateDB.GetCode(addrCopy))
		ret, err = pvm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		pvm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (pvm *PVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if pvm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// We take a snapshot here. This is a bit counter-intuitive, and could probably be skipped.
	// However, even a staticcall is considered a 'touch'. On mainnet, static calls were introduced
	// after all empty accounts were deleted, so this is not required. However, if we omit this,
	// then certain tests start failing; stRevertTest/RevertPrecompiledTouchExactOOG.json.
	// We could change this, but for now it's left for legacy reasons
	snapshot := pvm.StateDB.Snapshot()

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	pvm.StateDB.AddBalance(addr, big0)

	// Invoke tracer hooks that signal entering/exiting a call frame
	if pvm.Config.Debug {
		pvm.Config.Tracer.CaptureEnter(STATICCALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			pvm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	if p, isPrecompile := pvm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		// At this point, we use a copy of address. If we don't, the go compiler will
		// leak the 'contract' to the outer scope, and make allocation for 'contract'
		// even if the actual execution ends on RunPrecompiled above.
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the PVM.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, AccountRef(addrCopy), new(big.Int), gas)
		contract.SetCallCode(&addrCopy, pvm.StateDB.GetCodeHash(addrCopy), pvm.StateDB.GetCode(addrCopy))
		// When an error was returned by the PVM or when setting the creation code
		// above we revert to the snapshot and consume any gas remaining. Additionally
		// when we're in Homestead this also counts for code storage gas errors.
		ret, err = pvm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		pvm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// create creates a new contract using code as deployment code.
func (pvm *PVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address, typ OpCode) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if pvm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !pvm.Context.CanTransfer(pvm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := pvm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	pvm.StateDB.SetNonce(caller.Address(), nonce+1)
	// We add this to the access list _before_ taking a snapshot. Even if the creation fails,
	// the access-list change should not be rolled back
	if pvm.chainRules.IsBerlin {
		pvm.StateDB.AddAddressToAccessList(address)
	}
	// Ensure there's no existing contract already at the designated address
	contractHash := pvm.StateDB.GetCodeHash(address)
	if pvm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := pvm.StateDB.Snapshot()
	pvm.StateDB.CreateAccount(address)
	if pvm.chainRules.IsEIP158 {
		pvm.StateDB.SetNonce(address, 1)
	}
	pvm.Context.Transfer(pvm.StateDB, caller.Address(), address, value)

	// Initialise a new contract and set the code that is to be used by the PVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if pvm.Config.Debug {
		if pvm.depth == 0 {
			pvm.Config.Tracer.CaptureStart(pvm, caller.Address(), address, true, codeAndHash.code, gas, value)
		} else {
			pvm.Config.Tracer.CaptureEnter(typ, caller.Address(), address, codeAndHash.code, gas, value)
		}
	}

	start := time.Now()

	ret, err := pvm.interpreter.Run(contract, nil, false)

	// Check whether the max code size has been exceeded, assign err if the case.
	if err == nil && pvm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		err = ErrMaxCodeSizeExceeded
	}

	// Reject code starting with 0xEF if EIP-3541 is enabled.
	if err == nil && len(ret) >= 1 && ret[0] == 0xEF && pvm.chainRules.IsLondon {
		err = ErrInvalidCode
	}

	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			pvm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the PVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil && (pvm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		pvm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	if pvm.Config.Debug {
		if pvm.depth == 0 {
			pvm.Config.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
		} else {
			pvm.Config.Tracer.CaptureExit(ret, gas-contract.Gas, err)
		}
	}
	return ret, address, contract.Gas, err
}

// Create creates a new contract using code as deployment code.
func (pvm *PVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), pvm.StateDB.GetNonce(caller.Address()))
	return pvm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr, CREATE)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (pvm *PVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
	return pvm.create(caller, codeAndHash, gas, endowment, contractAddr, CREATE2)
}

// ChainConfig returns the environment's chain configuration
func (pvm *PVM) ChainConfig() *params.ChainConfig { return pvm.chainConfig }
