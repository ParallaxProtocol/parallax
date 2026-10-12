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
	"os"
)

// procNetRoute is the Linux IPv4 routing table. A variable so tests can
// point it at a fixture.
var procNetRoute = "/proc/net/route"

// routeGateways returns the IPv4 gateways of the default routes in the
// system routing table, in table order, or nil if it can't be read.
func routeGateways() []net.IP {
	f, err := os.Open(procNetRoute)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseRouteGateways(f)
}
