// Copyright 2017 The go-ethereum Authors
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

package xhash

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"slices"
	"time"

	"github.com/microstack-tech/parallax/common"
	"github.com/microstack-tech/parallax/consensus"
	"github.com/microstack-tech/parallax/consensus/misc"
	"github.com/microstack-tech/parallax/core/state"
	"github.com/microstack-tech/parallax/core/types"
	"github.com/microstack-tech/parallax/params"
	"github.com/microstack-tech/parallax/rlp"
	"github.com/microstack-tech/parallax/trie"
	"golang.org/x/crypto/sha3"
)

// XHash proof-of-work protocol constants.
var (
	allowedFutureBlockTimeSeconds = int64(5 * 60)
	// Reward halving interval in number of blocks
	HalvingIntervalBlocks = uint64(210000)
	// Initial block reward in atomic units
	InitialBlockRewardWei = new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	// A reserved system address to store maturity schedules in the state trie.
	lockboxAddress = common.HexToAddress("0x0000000000000000000000000000000000000042")

	MaxTarget = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errOlderBlockTime    = errors.New("timestamp older than parent")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidMixDigest  = errors.New("invalid mix digest")
	errInvalidPoW        = errors.New("invalid proof-of-work")
)

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (xhash *XHash) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Parallax xhash engine.
func (xhash *XHash) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	// If we're running a full engine faking, accept any input as valid
	if xhash.config.PowMode == ModeFullFake {
		return nil
	}
	// Short circuit if the header is known, or its parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return xhash.verifyHeader(chain, header, parent, false, seal, time.Now().Unix())
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (xhash *XHash) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// If we're running a full engine faking, accept any input as valid
	if xhash.config.PowMode == ModeFullFake || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for range headers {
			results <- nil
		}
		return abort, results
	}

	// Wrap canonical chain with a batch-aware view
	batchChain := newHeaderBatchChain(chain, headers)

	// Spawn as many workers as allowed threads
	workers := min(len(headers), runtime.GOMAXPROCS(0))

	// Create a task channel and spawn the verifiers
	var (
		inputs  = make(chan int)
		done    = make(chan int, workers)
		errors  = make([]error, len(headers))
		abort   = make(chan struct{})
		unixNow = time.Now().Unix()
	)
	for range workers {
		go func() {
			for index := range inputs {
				errors[index] = xhash.verifyHeaderWorker(batchChain, headers, seals, index, unixNow)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (xhash *XHash) verifyHeaderWorker(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool, index int, unixNow int64) error {
	header := headers[index]

	var parent *types.Header
	if index > 0 && headers[index-1].Hash() == header.ParentHash {
		parent = headers[index-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	}

	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return xhash.verifyHeader(chain, header, parent, false, seals[index], unixNow)
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Parallax xhash engine.
func (xhash *XHash) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Parallax xhash engine.
func (xhash *XHash) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, _ bool, seal bool, unixNow int64) error {
	// Extra-data size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}

	if header.Time > uint64(unixNow)+uint64(allowedFutureBlockTimeSeconds) {
		return consensus.ErrFutureBlock
	}

	if header.Time <= medianTimePast(chain, parent) {
		return errOlderBlockTime
	}

	if xhash.config.PowMode != ModeFullFake && xhash.config.PowMode != ModeFake && xhash.config.PowMode != ModeTest {
		if header.Number.Uint64()%chain.Config().XHash.RetargetIntervalBlocks == 0 {
			if header.EpochStartTime != header.Time {
				return fmt.Errorf("epoch anchor mismatch: want %d, have %d", header.Time, header.EpochStartTime)
			}
		} else {
			if header.EpochStartTime != parent.EpochStartTime {
				return fmt.Errorf("epoch anchor propagation mismatch: parent %d, header %d", parent.EpochStartTime, header.EpochStartTime)
			}
		}
	}

	// Difficulty retarget check
	expected := xhash.CalcDifficulty(chain, header.Time, parent)
	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v, height %v", header.Difficulty, expected, header.Number.Uint64())
	}

	// Gas limits
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// EIP-1559 / basefee (leave per your chain config)
	if !chain.Config().IsLondon(header.Number) {
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, expected 'nil'", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		return err
	}

	// Height = parent + 1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}

	// PoW seal
	if seal {
		if err := xhash.verifySeal(chain, header, false); err != nil {
			return err
		}
	}

	if err := misc.VerifyForkHashes(chain.Config(), header, false /* no uncles in this chain */); err != nil {
		return err
	}

	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func (xhash *XHash) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	if parent == nil {
		panic("CalcDifficulty called with nil parent")
	}

	cfg := chain.Config()
	xcfg := cfg.XHash
	nextHeight := parent.Number.Uint64() + 1

	// Pre-ASERT → Nakamoto / BTC-style
	if xcfg == nil || xcfg.AsertActivationHeight == 0 || nextHeight < xcfg.AsertActivationHeight {
		return CalcNakamotoDifficulty(cfg, parent)
	}

	asertActivationHeight := xcfg.AsertActivationHeight
	asertAnchorHeight := asertActivationHeight - 1

	// Lazily populate anchor cache on first ASERT block
	if !xhash.asertAnchorInit {
		anchorHeader := chain.GetHeaderByNumber(asertAnchorHeight)
		if anchorHeader == nil && parent.Number.Uint64() > asertAnchorHeight {
			// Fallback: walk backwards from parent
			h := parent
			for h != nil && h.Number.Uint64() > asertAnchorHeight {
				h = chain.GetHeader(h.ParentHash, h.Number.Uint64()-1)
			}
			anchorHeader = h
		}

		if anchorHeader == nil || anchorHeader.Number.Uint64() != asertAnchorHeight {
			panic(fmt.Sprintf("ASERT: could not locate anchor at height %d (nextHeight=%d, parentHeight=%d)",
				asertAnchorHeight, nextHeight, parent.Number.Uint64()))
		}

		anchorParent := chain.GetHeader(anchorHeader.ParentHash, anchorHeader.Number.Uint64()-1)
		if anchorParent == nil {
			panic("ASERT: missing anchor parent header")
		}

		xhash.asertAnchorHeight = int64(anchorHeader.Number.Uint64())
		xhash.asertAnchorParentTime = int64(anchorParent.Time)
		xhash.asertAnchorTarget = difficultyToTarget(anchorHeader.Difficulty)
		xhash.asertAnchorInit = true
	}

	evalHeight := int64(parent.Number.Uint64())
	evalTime := int64(parent.Time)

	// Calculate ASERT
	nextTarget := ASERTNextTarget(
		xhash.asertAnchorHeight,
		xhash.asertAnchorParentTime,
		xhash.asertAnchorTarget,
		evalHeight,
		evalTime,
		MaxTarget,
	)

	return targetToDifficulty(nextTarget)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func CalcDifficulty(config *params.ChainConfig, time uint64, parent *types.Header) *big.Int {
	return CalcNakamotoDifficulty(config, parent)
}

// Some weird constants to avoid constant memory allocs for them.
var (
	big1 = big.NewInt(1)
)

// verifySeal checks whether a block satisfies the PoW difficulty requirements,
// either using the usual xhash cache for it, or alternatively using a full DAG
// to make remote mining fast.
func (xhash *XHash) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, fulldag bool) error {
	// If we're running a fake PoW, accept any seal as valid
	if xhash.config.PowMode == ModeFake || xhash.config.PowMode == ModeFullFake {
		time.Sleep(xhash.fakeDelay)
		if xhash.fakeFail == header.Number.Uint64() {
			return errInvalidPoW
		}
		return nil
	}
	// If we're running a shared PoW, delegate verification to it
	if xhash.shared != nil {
		return xhash.shared.verifySeal(chain, header, fulldag)
	}
	// Ensure that we have a valid difficulty for the block
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}
	// Recompute the digest and PoW values
	number := header.Number.Uint64()

	var (
		digest []byte
		result []byte
	)
	// If fast-but-heavy PoW verification was requested, use an xhash dataset
	if fulldag {
		dataset := xhash.dataset(number, true)
		if dataset.generated() {
			digest, result = hashimotoFull(dataset.dataset, xhash.SealHash(header).Bytes(), header.Nonce.Uint64())

			// Datasets are unmapped in a finalizer. Ensure that the dataset stays alive
			// until after the call to hashimotoFull so it's not unmapped while being used.
			runtime.KeepAlive(dataset)
		} else {
			// Dataset not yet generated, don't hang, use a cache instead
			fulldag = false
		}
	}
	// If slow-but-light PoW verification was requested (or DAG not yet ready), use an xhash cache
	if !fulldag {
		cache := xhash.cache(number)

		size := datasetSize(number)
		if xhash.config.PowMode == ModeTest {
			size = 32 * 1024
		}
		digest, result = hashimotoLight(size, cache.cache, xhash.SealHash(header).Bytes(), header.Nonce.Uint64())

		// Caches are unmapped in a finalizer. Ensure that the cache stays alive
		// until after the call to hashimotoLight so it's not unmapped while being used.
		runtime.KeepAlive(cache)
	}
	// Verify the calculated values against the ones provided in the header
	if !bytes.Equal(header.MixDigest[:], digest) {
		return errInvalidMixDigest
	}
	target := new(big.Int).Div(new(big.Int).Set(two256m1), header.Difficulty)
	if new(big.Int).SetBytes(result).Cmp(target) > 0 {
		return errInvalidPoW
	}
	return nil
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the xhash protocol. The changes are done inline.
func (xhash *XHash) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	var r uint64

	if chain.Config().XHash == nil {
		// If no xhash config is given, fall back to Parallax's original difficulty
		// adjustment scheme (which is basically Bitcoin's with a 10-minute target).
		r = 2016
	} else {
		r = chain.Config().XHash.RetargetIntervalBlocks
	}

	// If we're on a retarget boundary, set the epoch start time to the current
	// block's timestamp (to be used by the next retarget calculation).
	if header.Number.Uint64()%r == 0 {
		header.EpochStartTime = header.Time
	} else {
		// Otherwise copy from parent
		header.EpochStartTime = parent.EpochStartTime
	}

	header.Difficulty = xhash.CalcDifficulty(chain, header.Time, parent)
	return nil
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards,
// setting the final state on the header
func (xhash *XHash) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// 1) Schedule THIS block’s coinbase for future maturity
	height := header.Number.Uint64()
	reward := calcBlockReward(header.Number.Uint64())
	if reward.Sign() > 0 {
		unlock := height + chain.Config().XHash.CoinbaseMaturityBlocks
		putScheduledPayout(state, unlock, header.Coinbase, reward)
	}

	// 2) Pay any matured rewards for THIS height
	if addr, amt, ok := popDuePayout(state, height); ok && amt.Sign() > 0 {
		state.AddBalance(addr, amt)
	}

	// 3) Commit final state root as usual
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}

// FinalizeAndAssemble implements consensus.Engine, accumulating the block and
// uncle rewards, setting the final state and assembling the block.
func (xhash *XHash) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	xhash.Finalize(chain, header, state, txs, nil)
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (xhash *XHash) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	enc := []any{
		header.ParentHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
		header.EpochStartTime,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}

// calcBlockReward calculates the block reward for a given block number
func calcBlockReward(blockNumber uint64) *big.Int {
	// No spendable subsidy for genesis
	if blockNumber == 0 {
		return new(big.Int) // 0
	}
	reward := new(big.Int).Set(InitialBlockRewardWei)

	halvings := blockNumber / HalvingIntervalBlocks
	if halvings > 63 {
		// Prevent shift overflow; after enough halvings, reward is effectively 0
		return new(big.Int)
	}
	divisor := new(big.Int).Lsh(big1, uint(halvings)) // 2^halvings
	reward.Div(reward, divisor)
	return reward
}

// medianTimePast returns the median of the last 11 block timestamps ending at parent.
func medianTimePast(chain consensus.ChainHeaderReader, parent *types.Header) uint64 {
	const window = 11
	times := make([]uint64, 0, window)
	h := parent
	for i := 0; i < window && h != nil; i++ {
		times = append(times, h.Time)
		h = chain.GetHeader(h.ParentHash, h.Number.Uint64()-1)
	}
	slices.Sort(times)
	return times[len(times)/2]
}

func schedKeyAddr(height uint64) common.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], height)
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("maturity:addr:"))
	h.Write(b[:])
	var out common.Hash
	sum := h.Sum(nil)
	copy(out[:], sum)
	return out
}

func schedKeyAmt(height uint64) common.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], height)
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("maturity:amt:"))
	h.Write(b[:])
	var out common.Hash
	sum := h.Sum(nil)
	copy(out[:], sum)
	return out
}

func putScheduledPayout(state *state.StateDB, unlockHeight uint64, addr common.Address, amt *big.Int) {
	state.SetState(lockboxAddress, schedKeyAddr(unlockHeight), common.BytesToHash(addr.Bytes()))
	state.SetState(lockboxAddress, schedKeyAmt(unlockHeight), common.BigToHash(amt))
}

func popDuePayout(state *state.StateDB, height uint64) (addr common.Address, amt *big.Int, ok bool) {
	if height == 0 {
		return common.Address{}, nil, false
	}
	rawAddr := state.GetState(lockboxAddress, schedKeyAddr(height))
	rawAmt := state.GetState(lockboxAddress, schedKeyAmt(height))

	// Consider only amount as the presence bit
	if rawAmt == (common.Hash{}) {
		return common.Address{}, nil, false
	}

	// Clear after read
	state.SetState(lockboxAddress, schedKeyAddr(height), common.Hash{})
	state.SetState(lockboxAddress, schedKeyAmt(height), common.Hash{})

	addr = common.BytesToAddress(rawAddr.Bytes())
	amt = new(big.Int).SetBytes(rawAmt.Bytes())

	return addr, amt, true
}

type headerBatchChain struct {
	consensus.ChainHeaderReader // embeds the base reader
	byNumber                    map[uint64]*types.Header
	byHashAndNumber             map[common.Hash]uint64
}

func newHeaderBatchChain(base consensus.ChainHeaderReader, headers []*types.Header) *headerBatchChain {
	hb := &headerBatchChain{
		ChainHeaderReader: base,
		byNumber:          make(map[uint64]*types.Header, len(headers)),
		byHashAndNumber:   make(map[common.Hash]uint64, len(headers)),
	}
	for _, h := range headers {
		n := h.Number.Uint64()
		hb.byNumber[n] = h
		hb.byHashAndNumber[h.Hash()] = n
	}
	return hb
}

func (hb *headerBatchChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if n, ok := hb.byHashAndNumber[hash]; ok && n == number {
		if h := hb.byNumber[n]; h != nil {
			return h
		}
	}
	return hb.ChainHeaderReader.GetHeader(hash, number)
}

func (hb *headerBatchChain) GetHeaderByNumber(number uint64) *types.Header {
	if h, ok := hb.byNumber[number]; ok {
		return h
	}
	return hb.ChainHeaderReader.GetHeaderByNumber(number)
}
