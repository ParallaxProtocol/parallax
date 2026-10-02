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

package rawdb

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/dbstore"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/netparams"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

const (
	// freezerRecheckInterval is the frequency to check the key-value database for
	// chain progression that might permit new blocks to be frozen into immutable
	// storage.
	freezerRecheckInterval = time.Minute

	// freezerBatchLimit is the maximum number of blocks to freeze in one batch
	// before doing an fsync and deleting it from the key-value store.
	freezerBatchLimit = 30000
)

// chainFreezer is a wrapper of freezer with additional chain freezing feature.
// The background thread will keep moving ancient chain segments from key-value
// database to flat files for saving space on live database.
type chainFreezer struct {
	// WARNING: The `threshold` field is accessed atomically. On 32 bit platforms, only
	// 64-bit aligned fields can be atomic. The struct is guaranteed to be so aligned,
	// so take advantage of that (https://golang.org/pkg/sync/atomic/#pkg-note-BUG).
	threshold uint64 // Number of recent blocks not to freeze (params.FullImmutabilityThreshold apart from tests)

	*Freezer
	quit    chan struct{}
	wg      sync.WaitGroup
	trigger chan chan struct{} // Manual blocking freeze trigger, test determinism
}

// newChainFreezer initializes the freezer for ancient chain data.
func newChainFreezer(datadir string, namespace string, readonly bool, maxTableSize uint32, tables map[string]bool) (*chainFreezer, error) {
	freezer, err := NewFreezer(datadir, namespace, readonly, maxTableSize, tables)
	if err != nil {
		return nil, err
	}
	return &chainFreezer{
		Freezer:   freezer,
		threshold: netparams.FullImmutabilityThreshold,
		quit:      make(chan struct{}),
		trigger:   make(chan chan struct{}),
	}, nil
}

// Close closes the chain freezer instance and terminates the background thread.
func (f *chainFreezer) Close() error {
	select {
	case <-f.quit:
	default:
		close(f.quit)
	}
	f.wg.Wait()
	return f.Freezer.Close()
}

// freeze is a background thread that periodically checks the blockchain for any
// import progress and moves ancient data from the fast database into the freezer.
//
// This functionality is deliberately broken off from block importing to avoid
// incurring additional data shuffling delays on block propagation.
func (f *chainFreezer) freeze(db dbstore.KeyValueStore) {
	nfdb := &nofreezedb{KeyValueStore: db}

	var (
		backoff   bool
		triggered chan struct{} // Used in tests
	)
	timer := time.NewTimer(freezerRecheckInterval)
	defer timer.Stop()
	for {
		select {
		case <-f.quit:
			logging.Info("Freezer shutting down")
			return
		default:
		}
		if backoff {
			// If we were doing a manual trigger, notify it
			if triggered != nil {
				triggered <- struct{}{}
				triggered = nil
			}
			select {
			case <-timer.C:
				backoff = false
				timer.Reset(freezerRecheckInterval)
			case triggered = <-f.trigger:
				backoff = false
			case <-f.quit:
				return
			}
		}
		// Retrieve the freezing threshold.
		hash := ReadHeadBlockHash(nfdb)
		if hash == (util.Hash{}) {
			logging.Debug("Current full block hash unavailable") // new chain, empty database
			backoff = true
			continue
		}
		number := ReadHeaderNumber(nfdb, hash)
		threshold := atomic.LoadUint64(&f.threshold)
		frozen := atomic.LoadUint64(&f.frozen)
		switch {
		case number == nil:
			logging.Error("Current full block number unavailable", "hash", hash)
			backoff = true
			continue

		case *number < threshold:
			logging.Debug("Current full block not old enough", "number", *number, "hash", hash, "delay", threshold)
			backoff = true
			continue

		case *number-threshold <= frozen:
			logging.Debug("Ancient blocks frozen already", "number", *number, "hash", hash, "frozen", frozen)
			backoff = true
			continue
		}
		head := ReadHeader(nfdb, hash, *number)
		if head == nil {
			logging.Error("Current full block unavailable", "number", *number, "hash", hash)
			backoff = true
			continue
		}

		// Seems we have data ready to be frozen, process in usable batches
		var (
			start    = time.Now()
			first, _ = f.Ancients()
			limit    = *number - threshold
		)
		if limit-first > freezerBatchLimit {
			limit = first + freezerBatchLimit
		}
		ancients, err := f.freezeRange(nfdb, first, limit)
		if err != nil {
			logging.Error("Error in block freeze operation", "err", err)
			backoff = true
			continue
		}

		// Batch of blocks have been frozen, flush them before wiping from leveldb
		if err := f.Sync(); err != nil {
			logging.Crit("Failed to flush frozen tables", "err", err)
		}

		// Wipe out all data from the active database
		batch := db.NewBatch()
		for i := 0; i < len(ancients); i++ {
			// Always keep the genesis block in active database
			if first+uint64(i) != 0 {
				DeleteBlockWithoutNumber(batch, ancients[i], first+uint64(i))
				DeleteCanonicalHash(batch, first+uint64(i))
			}
		}
		if err := batch.Write(); err != nil {
			logging.Crit("Failed to delete frozen canonical blocks", "err", err)
		}
		batch.Reset()

		// Wipe out side chains also and track dangling side chains
		var dangling []util.Hash
		frozen = atomic.LoadUint64(&f.frozen) // Needs reload after during freezeRange
		for number := first; number < frozen; number++ {
			// Always keep the genesis block in active database
			if number != 0 {
				dangling = ReadAllHashes(db, number)
				for _, hash := range dangling {
					logging.Trace("Deleting side chain", "number", number, "hash", hash)
					DeleteBlock(batch, hash, number)
				}
			}
		}
		if err := batch.Write(); err != nil {
			logging.Crit("Failed to delete frozen side blocks", "err", err)
		}
		batch.Reset()

		// Step into the future and delete and dangling side chains
		if frozen > 0 {
			tip := frozen
			for len(dangling) > 0 {
				drop := make(map[util.Hash]struct{})
				for _, hash := range dangling {
					logging.Debug("Dangling parent from Freezer", "number", tip-1, "hash", hash)
					drop[hash] = struct{}{}
				}
				children := ReadAllHashes(db, tip)
				for i := 0; i < len(children); i++ {
					// Dig up the child and ensure it's dangling
					child := ReadHeader(nfdb, children[i], tip)
					if child == nil {
						logging.Error("Missing dangling header", "number", tip, "hash", children[i])
						continue
					}
					if _, ok := drop[child.ParentHash]; !ok {
						children = append(children[:i], children[i+1:]...)
						i--
						continue
					}
					// Delete all block data associated with the child
					logging.Debug("Deleting dangling block", "number", tip, "hash", children[i], "parent", child.ParentHash)
					DeleteBlock(batch, children[i], tip)
				}
				dangling = children
				tip++
			}
			if err := batch.Write(); err != nil {
				logging.Crit("Failed to delete dangling side blocks", "err", err)
			}
		}

		// Log something friendly for the user
		context := []any{
			"blocks", frozen - first, "elapsed", util.PrettyDuration(time.Since(start)), "number", frozen - 1,
		}
		if n := len(ancients); n > 0 {
			context = append(context, []any{"hash", ancients[n-1]}...)
		}
		logging.Info("Deep froze chain segment", context...)

		// Avoid database thrashing with tiny writes
		if frozen-first < freezerBatchLimit {
			backoff = true
		}
	}
}

func (f *chainFreezer) freezeRange(nfdb *nofreezedb, number, limit uint64) (hashes []util.Hash, err error) {
	hashes = make([]util.Hash, 0, limit-number)

	_, err = f.ModifyAncients(func(op dbstore.AncientWriteOp) error {
		for ; number <= limit; number++ {
			// Retrieve all the components of the canonical block.
			hash := ReadCanonicalHash(nfdb, number)
			if hash == (util.Hash{}) {
				return fmt.Errorf("canonical hash missing, can't freeze block %d", number)
			}
			header := ReadHeaderRLP(nfdb, hash, number)
			if len(header) == 0 {
				return fmt.Errorf("block header missing, can't freeze block %d", number)
			}
			body := ReadBodyRLP(nfdb, hash, number)
			if len(body) == 0 {
				return fmt.Errorf("block body missing, can't freeze block %d", number)
			}
			receipts := ReadReceiptsRLP(nfdb, hash, number)
			if len(receipts) == 0 {
				return fmt.Errorf("block receipts missing, can't freeze block %d", number)
			}
			td := ReadTdRLP(nfdb, hash, number)
			if len(td) == 0 {
				return fmt.Errorf("total difficulty missing, can't freeze block %d", number)
			}

			// Write to the batch.
			if err := op.AppendRaw(freezerHashTable, number, hash[:]); err != nil {
				return fmt.Errorf("can't write hash to Freezer: %v", err)
			}
			if err := op.AppendRaw(freezerHeaderTable, number, header); err != nil {
				return fmt.Errorf("can't write header to Freezer: %v", err)
			}
			if err := op.AppendRaw(freezerBodiesTable, number, body); err != nil {
				return fmt.Errorf("can't write body to Freezer: %v", err)
			}
			if err := op.AppendRaw(freezerReceiptTable, number, receipts); err != nil {
				return fmt.Errorf("can't write receipts to Freezer: %v", err)
			}
			if err := op.AppendRaw(freezerDifficultyTable, number, td); err != nil {
				return fmt.Errorf("can't write td to Freezer: %v", err)
			}

			hashes = append(hashes, hash)
		}
		return nil
	})

	return hashes, err
}
