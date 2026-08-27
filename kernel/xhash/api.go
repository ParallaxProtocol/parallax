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

package xhash

import (
	"errors"
	"math/big"

	"github.com/ParallaxProtocol/parallax/v2/kernel"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
)

var errXHashStopped = errors.New("xhash stopped")

// API exposes xhash related methods for the RPC interface.
type API struct {
	xhash *XHash
	chain kernel.ChainHeaderReader
}

// NewAPI creates a new API for the given chain and engine.
func NewAPI(chain kernel.ChainHeaderReader, xhash *XHash) *API {
	return &API{chain: chain, xhash: xhash}
}

// GetWork returns a work package for external miner.
//
// The work package consists of 3 strings:
//
//	result[0] - 32 bytes hex encoded current block header pow-hash
//	result[1] - 32 bytes hex encoded seed hash used for DAG
//	result[2] - 32 bytes hex encoded boundary condition ("target"), 2^256/difficulty
//	result[3] - hex encoded block number
func (api *API) GetWork() ([4]string, error) {
	if api.xhash.remote == nil {
		return [4]string{}, errors.New("not supported")
	}

	var (
		workCh = make(chan [4]string, 1)
		errc   = make(chan error, 1)
	)
	select {
	case api.xhash.remote.fetchWorkCh <- &sealWork{errc: errc, res: workCh}:
	case <-api.xhash.remote.exitCh:
		return [4]string{}, errXHashStopped
	}
	select {
	case work := <-workCh:
		return work, nil
	case err := <-errc:
		return [4]string{}, err
	}
}

// SubmitWork can be used by external miner to submit their POW solution.
// It returns an indication if the work was accepted.
// Note either an invalid solution, a stale work a non-existent work will return false.
func (api *API) SubmitWork(nonce types.BlockNonce, hash, digest util.Hash) bool {
	if api.xhash.remote == nil {
		return false
	}

	errc := make(chan error, 1)
	select {
	case api.xhash.remote.submitWorkCh <- &mineResult{
		nonce:     nonce,
		mixDigest: digest,
		hash:      hash,
		errc:      errc,
	}:
	case <-api.xhash.remote.exitCh:
		return false
	}
	err := <-errc
	return err == nil
}

// SubmitHashrate can be used for remote miners to submit their hash rate.
// This enables the node to report the combined hash rate of all miners
// which submit work through this node.
//
// It accepts the miner hash rate and an identifier which must be unique
// between nodes.
func (api *API) SubmitHashrate(rate hexutil.Uint64, id util.Hash) bool {
	if api.xhash.remote == nil {
		return false
	}

	done := make(chan struct{}, 1)
	select {
	case api.xhash.remote.submitRateCh <- &hashrate{done: done, rate: uint64(rate), id: id}:
	case <-api.xhash.remote.exitCh:
		return false
	}

	// Block until hash rate submitted successfully.
	<-done
	return true
}

// GetHashrate returns the current hashrate for local CPU miner and remote miner.
func (api *API) GetHashrate() uint64 {
	return uint64(api.xhash.Hashrate())
}

func (api *API) GetTotalSupply() string {
	header := api.chain.CurrentHeader()
	if header == nil {
		return "0"
	}
	return cumulativeEmissionThrough(header.Number.Uint64()).String()
}

// GetCirculatingSupply reports the same figure as GetTotalSupply, following
// the Bitcoin convention: coinbase maturity is a spendability restriction,
// not an issuance restriction, so rewards count as circulating from the
// block that mints them even while they sit in the maturity lockbox. With
// no premine, burns, or protocol locks, circulating and total supply are
// identical by construction.
func (api *API) GetCirculatingSupply() string {
	return api.GetTotalSupply()
}

// cumulativeEmissionThrough returns the exact sum of block rewards for blocks
// 1..height. Genesis carries no subsidy and every era boundary block belongs
// to the new (halved) era, matching calcBlockReward.
func cumulativeEmissionThrough(height uint64) *big.Int {
	emissions := new(big.Int)
	tmp := new(big.Int)

	lastEra := height / HalvingIntervalBlocks
	if lastEra > 63 {
		lastEra = 63 // calcBlockReward is zero beyond 63 halvings
	}
	for era := uint64(0); era <= lastEra; era++ {
		first := era * HalvingIntervalBlocks
		last := first + HalvingIntervalBlocks - 1
		if last > height {
			last = height
		}
		if first == 0 {
			first = 1 // genesis has no reward
		}
		if last < first {
			continue
		}
		tmp.SetUint64(last - first + 1)
		tmp.Mul(tmp, calcBlockReward(first))
		emissions.Add(emissions, tmp)
	}
	return emissions
}
