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
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/rpc"
)

// Tests that eth_subscribe("newWork") sends the current work package, then each new one.
func TestNewWorkSubscription(t *testing.T) {
	xhash := NewTester(nil, false)
	defer xhash.Close()

	server := rpc.NewServer()
	defer server.Stop()
	if err := server.RegisterName("eth", NewAPI(nil, xhash)); err != nil {
		t.Fatalf("failed to register the API: %v", err)
	}
	client := rpc.DialInProc(server)
	defer client.Close()

	expect := func(works chan [4]string, block *types.Block) {
		t.Helper()
		select {
		case work := <-works:
			if want := xhash.SealHash(block.Header()).Hex(); work[0] != want {
				t.Errorf("work hash mismatch: have %s, want %s", work[0], want)
			}
			if want := "0x" + block.Number().Text(16); work[3] != want {
				t.Errorf("work number mismatch: have %s, want %s", work[3], want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no work for block %d", block.NumberU64())
		}
	}

	// Work from before the subscription comes first
	first := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(100)})
	xhash.Seal(nil, first, nil, nil)

	works := make(chan [4]string, 4)
	sub, err := client.ParallaxSubscribe(context.Background(), works, "newWork")
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	expect(works, first)

	second := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(2), Difficulty: big.NewInt(100)})
	xhash.Seal(nil, second, nil, nil)
	expect(works, second)

	// A second subscriber gets the same work, and the first keeps getting it after
	// the second one leaves
	others := make(chan [4]string, 4)
	other, err := client.ParallaxSubscribe(context.Background(), others, "newWork")
	if err != nil {
		t.Fatalf("failed to subscribe again: %v", err)
	}
	expect(others, second)
	other.Unsubscribe()

	third := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(3), Difficulty: big.NewInt(100)})
	xhash.Seal(nil, third, nil, nil)
	expect(works, third)
	sub.Unsubscribe()
}
