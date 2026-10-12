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
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
)

// parseRouteGateways extracts default-route gateways from the Linux
// /proc/net/route format: a header line, then one route per line with
// whitespace-separated Iface, Destination, Gateway and Flags columns.
// Addresses are 32-bit hex in host (little-endian) byte order.
func parseRouteGateways(r io.Reader) []net.IP {
	const rtfGateway = 0x2 // RTF_GATEWAY: the route goes through a router

	var gws []net.IP
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := hex.DecodeString(fields[3])
		if err != nil || len(flags) == 0 || flags[len(flags)-1]&rtfGateway == 0 {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		gw := make(net.IP, 4)
		binary.BigEndian.PutUint32(gw, binary.LittleEndian.Uint32(raw))
		if gw.IsUnspecified() || containsIP(gws, gw) {
			continue
		}
		gws = append(gws, gw)
	}
	return gws
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, x := range list {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}
