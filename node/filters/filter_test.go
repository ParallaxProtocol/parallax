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

package filters

import (
	"context"
	"math/big"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/kernel/xhash"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/rpc"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"
)

func makeReceipt(addr util.Address) *types.Receipt {
	receipt := types.NewReceipt(nil, false, 0)
	receipt.Logs = []*types.Log{
		{Address: addr},
	}
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	return receipt
}

func BenchmarkFilters(b *testing.B) {
	dir := b.TempDir()

	var (
		db, _   = rawdb.NewLevelDBDatabase(dir, 0, 0, "", false)
		backend = &testBackend{db: db}
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		addr2   = util.BytesToAddress([]byte("jeff"))
		addr3   = util.BytesToAddress([]byte("ethereum"))
		addr4   = util.BytesToAddress([]byte("random addresses please"))
	)
	defer db.Close()

	genesis := validation.GenesisBlockForTesting(db, addr1, big.NewInt(1000000))
	chain, receipts := validation.GenerateChain(chainparams.TestChainConfig, genesis, xhash.NewFaker(), db, 100010, func(i int, gen *validation.BlockGen) {
		switch i {
		case 2403:
			receipt := makeReceipt(addr1)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, util.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		case 1034:
			receipt := makeReceipt(addr2)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, util.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		case 34:
			receipt := makeReceipt(addr3)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, util.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		case 99999:
			receipt := makeReceipt(addr4)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, util.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		}
	})
	for i, block := range chain {
		rawdb.WriteBlock(db, block)
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
		rawdb.WriteHeadBlockHash(db, block.Hash())
		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts[i])
	}
	b.ResetTimer()

	filter := NewRangeFilter(backend, 0, -1, []util.Address{addr1, addr2, addr3, addr4}, nil)

	for i := 0; i < b.N; i++ {
		logs, _ := filter.Logs(context.Background())
		if len(logs) != 4 {
			b.Fatal("expected 4 logs, got", len(logs))
		}
	}
}

func TestFilters(t *testing.T) {
	dir := t.TempDir()

	var (
		db, _   = rawdb.NewLevelDBDatabase(dir, 0, 0, "", false)
		backend = &testBackend{db: db}
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr    = crypto.PubkeyToAddress(key1.PublicKey)

		hash1 = util.BytesToHash([]byte("topic1"))
		hash2 = util.BytesToHash([]byte("topic2"))
		hash3 = util.BytesToHash([]byte("topic3"))
		hash4 = util.BytesToHash([]byte("topic4"))
	)
	defer db.Close()

	genesis := validation.GenesisBlockForTesting(db, addr, big.NewInt(1000000))
	chain, receipts := validation.GenerateChain(chainparams.TestChainConfig, genesis, xhash.NewFaker(), db, 1000, func(i int, gen *validation.BlockGen) {
		switch i {
		case 1:
			receipt := types.NewReceipt(nil, false, 0)
			receipt.Logs = []*types.Log{
				{
					Address: addr,
					Topics:  []util.Hash{hash1},
				},
			}
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(1, util.HexToAddress("0x1"), big.NewInt(1), 1, gen.BaseFee(), nil))
		case 2:
			receipt := types.NewReceipt(nil, false, 0)
			receipt.Logs = []*types.Log{
				{
					Address: addr,
					Topics:  []util.Hash{hash2},
				},
			}
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(2, util.HexToAddress("0x2"), big.NewInt(2), 2, gen.BaseFee(), nil))

		case 998:
			receipt := types.NewReceipt(nil, false, 0)
			receipt.Logs = []*types.Log{
				{
					Address: addr,
					Topics:  []util.Hash{hash3},
				},
			}
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(998, util.HexToAddress("0x998"), big.NewInt(998), 998, gen.BaseFee(), nil))
		case 999:
			receipt := types.NewReceipt(nil, false, 0)
			receipt.Logs = []*types.Log{
				{
					Address: addr,
					Topics:  []util.Hash{hash4},
				},
			}
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, util.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		}
	})
	for i, block := range chain {
		rawdb.WriteBlock(db, block)
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
		rawdb.WriteHeadBlockHash(db, block.Hash())
		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts[i])
	}

	filter := NewRangeFilter(backend, 0, -1, []util.Address{addr}, [][]util.Hash{{hash1, hash2, hash3, hash4}})

	logs, _ := filter.Logs(context.Background())
	if len(logs) != 4 {
		t.Error("expected 4 log, got", len(logs))
	}

	filter = NewRangeFilter(backend, 900, 999, []util.Address{addr}, [][]util.Hash{{hash3}})
	logs, _ = filter.Logs(context.Background())
	if len(logs) != 1 {
		t.Error("expected 1 log, got", len(logs))
	}
	if len(logs) > 0 && logs[0].Topics[0] != hash3 {
		t.Errorf("expected log[0].Topics[0] to be %x, got %x", hash3, logs[0].Topics[0])
	}

	filter = NewRangeFilter(backend, 990, -1, []util.Address{addr}, [][]util.Hash{{hash3}})
	logs, _ = filter.Logs(context.Background())
	if len(logs) != 1 {
		t.Error("expected 1 log, got", len(logs))
	}
	if len(logs) > 0 && logs[0].Topics[0] != hash3 {
		t.Errorf("expected log[0].Topics[0] to be %x, got %x", hash3, logs[0].Topics[0])
	}

	filter = NewRangeFilter(backend, 1, 10, nil, [][]util.Hash{{hash1, hash2}})

	logs, _ = filter.Logs(context.Background())
	if len(logs) != 2 {
		t.Error("expected 2 log, got", len(logs))
	}

	failHash := util.BytesToHash([]byte("fail"))
	filter = NewRangeFilter(backend, 0, -1, nil, [][]util.Hash{{failHash}})

	logs, _ = filter.Logs(context.Background())
	if len(logs) != 0 {
		t.Error("expected 0 log, got", len(logs))
	}

	failAddr := util.BytesToAddress([]byte("failmenow"))
	filter = NewRangeFilter(backend, 0, -1, []util.Address{failAddr}, nil)

	logs, _ = filter.Logs(context.Background())
	if len(logs) != 0 {
		t.Error("expected 0 log, got", len(logs))
	}

	filter = NewRangeFilter(backend, 0, -1, nil, [][]util.Hash{{failHash}, {hash1}})

	logs, _ = filter.Logs(context.Background())
	if len(logs) != 0 {
		t.Error("expected 0 log, got", len(logs))
	}

	// "pending" is served from the latest block.
	filter = NewRangeFilter(backend, rpc.PendingBlockNumber.Int64(), rpc.PendingBlockNumber.Int64(), []util.Address{addr}, [][]util.Hash{{hash4}})
	logs, err := filter.Logs(context.Background())
	if err != nil {
		t.Fatal("unexpected error for pending range:", err)
	}
	if len(logs) != 1 {
		t.Error("expected 1 log, got", len(logs))
	}

	// Inverted ranges are rejected, also when they end at genesis or start
	// after the head block.
	for _, r := range [][2]int64{{10, 1}, {1, 0}, {2000, rpc.LatestBlockNumber.Int64()}} {
		filter = NewRangeFilter(backend, r[0], r[1], nil, nil)
		if _, err := filter.Logs(context.Background()); err != errInvalidBlockRange {
			t.Errorf("range %d..%d: expected %v, got %v", r[0], r[1], errInvalidBlockRange, err)
		}
	}

	// Ranges exceeding the configured limit are rejected.
	filter = NewRangeFilter(backend, 0, 10, nil, nil)
	filter.rangeLimit = 5
	if _, err := filter.Logs(context.Background()); err == nil {
		t.Error("expected error for range exceeding the limit")
	}
	filter = NewRangeFilter(backend, 5, 10, []util.Address{addr}, nil)
	filter.rangeLimit = 5
	if _, err := filter.Logs(context.Background()); err != nil {
		t.Error("unexpected error for range within the limit:", err)
	}

	// Special block numbers which cannot be resolved must not be treated as
	// raw block numbers.
	filter = NewRangeFilter(backend, rpc.FinalizedBlockNumber.Int64(), rpc.LatestBlockNumber.Int64(), nil, nil)
	if _, err := filter.Logs(context.Background()); err == nil {
		t.Error("expected error for unknown finalized block")
	}
}
