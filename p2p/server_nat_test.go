// Copyright 2026 The Parallax Protocol Authors
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

package p2p

import (
	"net"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
)

// TestSetNATEndpoint — the gateway's external IP and the mapped TCP
// port arrive separately; OnNATMapping fires only once both are known
// and on each change, and a lapsed mapping withdraws the endpoint.
func TestSetNATEndpoint(t *testing.T) {
	var got []addrman.NetAddr
	srv := &Server{Config: Config{OnNATMapping: func(a addrman.NetAddr) { got = append(got, a) }}}

	ep := func(ip net.IP, port uint16) addrman.NetAddr {
		a, err := addrman.NewNetAddr(addrman.NetIPv4, ip.To4(), port)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	ipA, ipB := net.IPv4(45, 236, 49, 58), net.IPv4(45, 236, 49, 99)

	srv.setNATEndpoint(ipA, 0)     // IP alone: incomplete
	srv.setNATEndpoint(nil, 40123) // port: endpoint known
	srv.setNATEndpoint(nil, 40123) // renewal, unchanged: no call
	srv.setNATEndpoint(ipB, 0)     // WAN address changed
	srv.setNATEndpoint(nil, 0)     // renewal failed: withdrawn

	want := []addrman.NetAddr{ep(ipA, 40123), ep(ipB, 40123), {}}
	if len(got) != len(want) {
		t.Fatalf("got %d OnNATMapping calls %v, want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d: got %v, want %v", i, got[i], want[i])
		}
	}
}
