package watcher

import (
	"context"
	"math/big"
	"sync/atomic"
	"testing"

	parallax "github.com/ParallaxProtocol/parallax/v2"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/registry"
)

// truncatingLogBackend serves logs whose data payload is truncated for one
// event topic while active: the generated iterator's UnpackLog then fails
// MID-iteration — Next() returns false with the error parked in Error(),
// which only the caller can surface.
type truncatingLogBackend struct {
	TxBackend
	topic  util.Hash
	active atomic.Bool
}

func (b *truncatingLogBackend) FilterLogs(ctx context.Context, q parallax.FilterQuery) ([]types.Log, error) {
	logs, err := b.TxBackend.FilterLogs(ctx, q)
	if err != nil || !b.active.Load() {
		return logs, err
	}
	for i := range logs {
		if len(logs[i].Topics) > 0 && logs[i].Topics[0] == b.topic {
			logs[i].Data = logs[i].Data[:1]
		}
	}
	return logs, nil
}

// TestScanKeepsWatermarkOnIteratorError: a log lost to a mid-iteration
// decode failure must keep LastScannedBlock where it was. Advancing to
// cutoff anyway permanently skips the range: a CloseStarted there is never
// re-scanned, StatusClosing is never set, no challenge is submitted, and
// the counterparty's stale close settles — fund loss.
func TestScanKeepsWatermarkOnIteratorError(t *testing.T) {
	e := setupSim(t)
	ctx := context.Background()

	// Bob's true latest state is seq 5; alice force-closes at stale seq 2.
	latest := e.dualSigned(t, 5, lax(3), new(big.Int))
	if err := e.store.PutComplete(latest); err != nil {
		t.Fatal(err)
	}
	stale := e.dualSigned(t, 2, lax(1), new(big.Int))
	if _, err := e.contract.StartClose(e.aliceAuth, big.NewInt(1), stale.ContractProof(), stale.SigA, stale.SigB); err != nil {
		t.Fatal(err)
	}
	e.commit(3) // confirm CloseStarted

	abi, err := registry.ChannelRegistryMetaData.GetAbi()
	if err != nil {
		t.Fatal(err)
	}
	trunc := &truncatingLogBackend{TxBackend: e.backend, topic: abi.Events["CloseStarted"].ID}
	w, err := New(Config{ChainID: "1337", Registry: e.regAddr, Confirmations: 3}, e.store, trunc,
		NewTxManager(trunc, e.bobPriv, big.NewInt(1337)))
	if err != nil {
		t.Fatal(err)
	}

	// Tick 1: the CloseStarted log arrives truncated and cannot be decoded.
	before, _ := e.store.Deposits(e.key)
	trunc.active.Store(true)
	if _, err := w.Tick(ctx); err != nil {
		t.Logf("tick over truncated log: %v", err)
	}
	after, _ := e.store.Deposits(e.key)
	if after.LastScannedBlock != before.LastScannedBlock {
		t.Fatalf("watermark advanced over an unread log: %d -> %d", before.LastScannedBlock, after.LastScannedBlock)
	}

	// Tick 2: logs decode again; the close must be re-scanned, the status
	// flipped, and the stale close challenged with seq 5.
	trunc.active.Store(false)
	if _, err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	e.commit(1) // mine the challenge

	onchain, err := e.contract.GetChannel(nil, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if onchain.ClosingSeq != 5 {
		t.Fatalf("close skipped by the failed scan was never challenged: on-chain seq %d, want 5", onchain.ClosingSeq)
	}
}

// countingFilterBackend counts FilterLogs queries.
type countingFilterBackend struct {
	TxBackend
	filters atomic.Int64
}

func (b *countingFilterBackend) FilterLogs(ctx context.Context, q parallax.FilterQuery) ([]types.Log, error) {
	b.filters.Add(1)
	return b.TxBackend.FilterLogs(ctx, q)
}

// TestScanUsesOneFilterQueryPerChannel: scanChannel issued six separate
// eth_getLogs round trips per channel per tick (opened, deposit, withdraw,
// close-started, settled, coop-closed), all against the same block range
// and channel-id topic. One combined query serves all six.
func TestScanUsesOneFilterQueryPerChannel(t *testing.T) {
	e := setupSim(t)
	e.commit(3)

	counting := &countingFilterBackend{TxBackend: e.backend}
	w, err := New(Config{ChainID: "1337", Registry: e.regAddr, Confirmations: 3}, e.store, counting,
		NewTxManager(counting, e.bobPriv, big.NewInt(1337)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := counting.filters.Load(); got != 1 {
		t.Fatalf("%d filter queries for one channel's scan, want 1", got)
	}
	// The one query still credited the confirmed deposits.
	dep, err := e.store.Deposits(e.key)
	if err != nil {
		t.Fatal(err)
	}
	if dep.DepositA.BigInt().Cmp(lax(10)) != 0 || dep.DepositB.BigInt().Cmp(lax(5)) != 0 {
		t.Fatalf("deposits not credited by the combined scan: %+v", dep)
	}
}
