package xhash

import (
	"math/big"
	"testing"

	"github.com/ParallaxProtocol/parallax/common"
	"github.com/ParallaxProtocol/parallax/core/rawdb"
	"github.com/ParallaxProtocol/parallax/core/state"
)

// newTestStateDB creates a blank in-memory StateDB.
func newTestStateDB(t *testing.T) *state.StateDB {
	t.Helper()
	memdb := rawdb.NewMemoryDatabase()
	statedb := state.NewDatabase(memdb)

	db, err := state.New(common.Hash{}, statedb, nil)
	if err != nil {
		t.Fatalf("failed to create StateDB: %v", err)
	}
	return db
}

func TestPutAndPopScheduledPayout_NormalFlow(t *testing.T) {
	sdb := newTestStateDB(t)

	height := uint64(100)
	addr := common.HexToAddress("0x00000000000000000000000000000000000000AA")
	amt := new(big.Int).Mul(big.NewInt(123), big.NewInt(1e18))

	// Before scheduling: nothing due
	_, _, ok := popDuePayout(sdb, height)
	if ok {
		t.Fatalf("expected no payout before scheduling at height %d", height)
	}

	// Schedule payout and then pop it
	putScheduledPayout(sdb, height, addr, amt)

	gotAddr, gotAmt, ok := popDuePayout(sdb, height)
	if !ok {
		t.Fatalf("expected payout to be due at height %d", height)
	}
	if gotAddr != addr {
		t.Fatalf("address mismatch: got %v want %v", gotAddr, addr)
	}
	if gotAmt.Cmp(amt) != 0 {
		t.Fatalf("amount mismatch: got %v want %v", gotAmt, amt)
	}

	// Should be cleared after read
	_, _, ok = popDuePayout(sdb, height)
	if ok {
		t.Fatalf("expected payout to be cleared after pop at height %d", height)
	}
}

func TestPopDuePayout_HeightZeroIgnored(t *testing.T) {
	sdb := newTestStateDB(t)

	addr, amt, ok := popDuePayout(sdb, 0)
	if ok || (addr != (common.Address{})) || amt != nil {
		t.Fatalf("height 0 must not yield payouts; got ok=%v addr=%v amt=%v", ok, addr, amt)
	}
}

func TestPopDuePayout_NoSchedule(t *testing.T) {
	sdb := newTestStateDB(t)

	// Nothing has been scheduled at this height.
	addr, amt, ok := popDuePayout(sdb, 42)
	if ok || (addr != (common.Address{})) || amt != nil {
		t.Fatalf("expected no payout at unscheduled height; got ok=%v addr=%v amt=%v", ok, addr, amt)
	}
}

func TestPutScheduledPayout_ZeroAmountActsAsAbsent(t *testing.T) {
	// Presence bit is the amount hash; zero amount should behave like "no payout".
	sdb := newTestStateDB(t)

	height := uint64(7)
	addr := common.HexToAddress("0x00000000000000000000000000000000000000BB")
	zero := new(big.Int) // 0

	putScheduledPayout(sdb, height, addr, zero)

	// popDuePayout should treat zero-amt as "not present"
	gotAddr, gotAmt, ok := popDuePayout(sdb, height)
	if ok || (gotAddr != (common.Address{})) || gotAmt != nil {
		t.Fatalf("zero-amount schedule should not be considered present; got ok=%v addr=%v amt=%v", ok, gotAddr, gotAmt)
	}
}

func TestPutAndPopScheduledPayout_BurnAddress(t *testing.T) {
	sdb := newTestStateDB(t)

	height := uint64(55)
	burn := common.HexToAddress("0x0000000000000000000000000000000000000000")
	amt := big.NewInt(42)

	// Schedule payout to burn address
	putScheduledPayout(sdb, height, burn, amt)

	// Pop it
	gotAddr, gotAmt, ok := popDuePayout(sdb, height)
	if !ok {
		t.Fatalf("expected payout to be due at height %d", height)
	}

	if gotAddr != burn {
		t.Fatalf("expected burn address %v, got %v", burn, gotAddr)
	}
	if gotAmt.Cmp(amt) != 0 {
		t.Fatalf("amount mismatch: expected %v, got %v", amt, gotAmt)
	}
}
