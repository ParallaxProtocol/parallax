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

package stats

import (
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	protocol "github.com/ParallaxProtocol/parallax/v2/node/fullnode"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
)

// The full node backend must keep satisfying fullNodeBackend: the reporter
// detects full nodes by type assertion and would silently report as a
// light node otherwise.
var _ fullNodeBackend = (*protocol.PrlAPIBackend)(nil)

func TestParseEthstatsURL(t *testing.T) {
	cases := []struct {
		url              string
		node, pass, host string
	}{
		{
			url:  `"debug meowsbits":mypass@ws://mordor.dash.fault.dev:3000`,
			node: "debug meowsbits", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `"debug @meowsbits":mypass@ws://mordor.dash.fault.dev:3000`,
			node: "debug @meowsbits", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `"debug: @meowsbits":mypass@ws://mordor.dash.fault.dev:3000`,
			node: "debug: @meowsbits", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `name:@ws://mordor.dash.fault.dev:3000`,
			node: "name", pass: "", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `name@ws://mordor.dash.fault.dev:3000`,
			node: "name", pass: "", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `:mypass@ws://mordor.dash.fault.dev:3000`,
			node: "", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `:@ws://mordor.dash.fault.dev:3000`,
			node: "", pass: "", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `status.parallaxprotocol.org`,
			node: "", pass: "", host: "status.parallaxprotocol.org",
		},
	}

	for i, c := range cases {
		parts, err := parsePrlstatsURL(c.url)
		if err != nil {
			t.Fatal(err)
		}
		node, pass, host := parts[0], parts[1], parts[2]

		// unquote because the value provided will be used as a CLI flag value, so unescaped quotes will be removed
		nodeUnquote, err := strconv.Unquote(node)
		if err == nil {
			node = nodeUnquote
		}

		if node != c.node {
			t.Errorf("case=%d mismatch node value, got: %v ,want: %v", i, node, c.node)
		}
		if pass != c.pass {
			t.Errorf("case=%d mismatch pass value, got: %v ,want: %v", i, pass, c.pass)
		}
		if host != c.host {
			t.Errorf("case=%d mismatch host value, got: %v ,want: %v", i, host, c.host)
		}
	}
}

func TestMedianMinPing(t *testing.T) {
	ms := time.Millisecond
	cases := []struct {
		pings []time.Duration
		want  time.Duration
	}{
		{nil, 0},
		{[]time.Duration{0, 0}, 0},
		{[]time.Duration{30 * ms}, 30 * ms},
		{[]time.Duration{50 * ms, 0, 10 * ms, 30 * ms}, 30 * ms},
		{[]time.Duration{40 * ms, 10 * ms, 0, 20 * ms, 30 * ms}, 25 * ms},
	}
	for i, c := range cases {
		if got := medianMinPing(c.pings); got != c.want {
			t.Errorf("case %d: medianMinPing(%v) = %v, want %v", i, c.pings, got, c.want)
		}
	}
}

// The full node API backend must satisfy fullNodeBackend, or reportStats
// silently falls back to the reduced stats path.
var _ fullNodeBackend = (*protocol.PrlAPIBackend)(nil)

func TestBlockFees(t *testing.T) {
	tx := func(gasPrice int64) *types.Transaction {
		return types.NewTx(&types.LegacyTx{Gas: 100000, GasPrice: big.NewInt(gasPrice)})
	}
	txs := types.Transactions{tx(1_000_000_000), tx(2_500_000_000), tx(0)}
	receipts := types.Receipts{{GasUsed: 21000}, {GasUsed: 50000}, {GasUsed: 30000}}

	want := big.NewInt(21000*1_000_000_000 + 50000*2_500_000_000)
	if got := blockFees(txs, receipts); got == nil || got.Cmp(want) != 0 {
		t.Errorf("fees: have %v, want %v", got, want)
	}
	if got := blockFees(types.Transactions{}, types.Receipts{}); got == nil || got.Sign() != 0 {
		t.Errorf("empty block fees: have %v, want 0", got)
	}
	// Receipts that do not match the transactions give no figure, not 0
	if got := blockFees(txs, receipts[:2]); got != nil {
		t.Errorf("mismatched receipts: have %v, want nil", got)
	}
}

func TestParsePrlstatsURLRejectsEmpty(t *testing.T) {
	for _, url := range []string{"", "name@"} {
		if _, err := parsePrlstatsURL(url); err == nil {
			t.Errorf("%q: parsed without error", url)
		}
	}
}

// TestDefaultNodeName — the generated name is kept in the instance
// directory, so a restarted node reports under the same name and keeps
// its dashboard history, while separate nodes get different names.
func TestDefaultNodeName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "parallaxd")
	first := defaultNodeName(dir)
	if again := defaultNodeName(dir); again != first {
		t.Fatalf("name changed across calls: %q then %q", first, again)
	}
	if b, err := os.ReadFile(filepath.Join(dir, statsNameFile)); err != nil || string(b) != first+"\n" {
		t.Fatalf("name file holds %q (err %v), want %q", b, err, first+"\n")
	}
	if other := defaultNodeName(filepath.Join(t.TempDir(), "parallaxd")); other == first {
		t.Fatalf("two data directories share the name %q", first)
	}
	if a, b := defaultNodeName(""), defaultNodeName(""); a == b {
		t.Fatalf("no datadir: names repeat (%q)", a)
	}
}
