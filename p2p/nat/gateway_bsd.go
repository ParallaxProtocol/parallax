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

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package nat

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// routeGateways returns the IPv4 gateways of the default routes in the
// kernel routing table, in table order, or nil if it can't be read.
func routeGateways() []net.IP {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	var gws []net.IP
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		if !isZeroInet4(rm.Addrs[syscall.RTAX_DST]) || !isZeroInet4(rm.Addrs[syscall.RTAX_NETMASK]) {
			continue // not a default route
		}
		gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok {
			continue
		}
		ip := net.IPv4(gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3]).To4()
		if ip.IsUnspecified() || containsIP(gws, ip) {
			continue
		}
		gws = append(gws, ip)
	}
	return gws
}

// isZeroInet4 reports whether a is 0.0.0.0 or absent, as the
// destination and netmask of a default route are.
func isZeroInet4(a route.Addr) bool {
	if a == nil {
		return true
	}
	v4, ok := a.(*route.Inet4Addr)
	return ok && v4.IP == [4]byte{}
}
