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

package nat

import (
	"net"
	"strings"
	"testing"
)

func TestParseRouteGateways(t *testing.T) {
	// A router on .254 (which the x.x.x.1 guess misses), a second
	// default route via another uplink, and on-link Docker bridge
	// routes that have no gateway.
	table := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eno1	00000000	FE03A8C0	0003	0	0	100	00000000	0	0	0
wlan0	00000000	0100000A	0003	0	0	600	00000000	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
eno1	0003A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	got := parseRouteGateways(strings.NewReader(table))
	want := []net.IP{net.IPv4(192, 168, 3, 254), net.IPv4(10, 0, 0, 1)}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Fatalf("gateway %d: got %v, want %v", i, got[i], want[i])
		}
	}
}
