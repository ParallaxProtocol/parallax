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
	"unsafe"

	"golang.org/x/sys/windows"
)

// routeGateways returns the IPv4 default gateways of the adapters that
// are up, as reported by GetAdaptersAddresses, or nil if they can't be
// read.
func routeGateways() []net.IP {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER

	// The adapter list can grow between the sizing call and the read,
	// so retry a few times with the size the system asks for.
	size := uint32(15 * 1024)
	for try := 0; try < 3; try++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var gws []net.IP
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for g := a.FirstGatewayAddress; g != nil; g = g.Next {
				ip := g.Address.IP().To4()
				if ip == nil || ip.IsUnspecified() || containsIP(gws, ip) {
					continue
				}
				gws = append(gws, ip)
			}
		}
		return gws
	}
	return nil
}
