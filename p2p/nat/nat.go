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

// Package nat provides access to common network port mapping protocols.
package nat

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	natpmp "github.com/jackpal/go-nat-pmp"
)

// An implementation of nat.Interface can map local ports to ports
// accessible from the Internet.
type Interface interface {
	// These methods manage a mapping between a port on the local
	// machine to a port that can be connected to from the internet.
	//
	// protocol is "UDP" or "TCP". Some implementations allow setting
	// a display name for the mapping. The mapping may be removed by
	// the gateway when its lifetime ends.
	AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error)
	DeleteMapping(protocol string, extport, intport int) error

	// This method should return the external (Internet-facing)
	// address of the gateway device.
	ExternalIP() (net.IP, error)

	// Should return name of the method. This is used for logging.
	String() string
}

// Parse parses a NAT interface description.
// The following formats are currently accepted.
// Note that mechanism names are not case-sensitive.
//
//	"" or "none"         return nil
//	"extip:77.12.33.4"   will assume the local machine is reachable on the given IP
//	"any"                uses the first auto-detected mechanism
//	"upnp"               uses the Universal Plug and Play protocol
//	"pmp"                uses NAT-PMP with an auto-detected gateway address
//	"pmp:192.168.0.1"    uses NAT-PMP with the given gateway address
func Parse(spec string) (Interface, error) {
	var (
		parts = strings.SplitN(spec, ":", 2)
		mech  = strings.ToLower(parts[0])
		ip    net.IP
	)
	if len(parts) > 1 {
		ip = net.ParseIP(parts[1])
		if ip == nil {
			return nil, errors.New("invalid IP address")
		}
	}
	switch mech {
	case "", "none", "off":
		return nil, nil
	case "any", "auto", "on":
		return Any(), nil
	case "extip", "ip":
		if ip == nil {
			return nil, errors.New("missing IP address")
		}
		return ExtIP(ip), nil
	case "upnp":
		return UPnP(), nil
	case "pmp", "natpmp", "nat-pmp":
		return PMP(ip), nil
	default:
		return nil, fmt.Errorf("unknown mechanism %q", parts[0])
	}
}

// mapTimeout is the lease requested for each mapping.
const mapTimeout = 10 * time.Minute

// mapRefresh is how often the mapping is renewed. Half the lease, so a
// renewal that is slow or needs a retry still lands before the router
// expires the entry; renewing exactly at the lease end left a window
// every cycle in which the port was closed. A variable so tests can
// shorten it.
var mapRefresh = mapTimeout / 2

// Map adds a port mapping on m and keeps it alive until c is closed.
// This function is typically invoked in its own goroutine.
//
// onMapped, if non-nil, is invoked with the actual external port assigned by
// the router whenever it differs from the last reported value (including the
// initial mapping). This is required because IGDv2's AddAnyPortMapping and
// the random-port retry path may assign an external port different from the
// requested intport, and the caller needs to advertise the assigned port in
// its node record so that remote peers can reach it. When a renewal fails
// after a mapping was established, onMapped is invoked with 0: the router
// may already have dropped the entry, so the port must not be advertised
// until a later renewal succeeds and reports it again.
func Map(m Interface, c <-chan struct{}, protocol string, extport, intport int, name string, onMapped func(uint16)) {
	logger := logging.New("proto", protocol, "extport", extport, "intport", intport, "interface", m)
	refresh := time.NewTimer(mapRefresh)
	var (
		lastMapped uint16 // port currently reported to onMapped, 0 if none
		deletePort uint16 // last port the router assigned, for the final delete
	)
	notify := func(p uint16) {
		if p == lastMapped {
			return
		}
		lastMapped = p
		if p != 0 {
			deletePort = p
		}
		if onMapped != nil {
			onMapped(p)
		}
	}
	defer func() {
		refresh.Stop()
		// Use the last successfully-mapped external port for the delete; if no
		// mapping was ever established, fall back to the originally requested
		// external port (DeleteMapping is harmless on a non-existent entry).
		delPort := int(deletePort)
		if delPort == 0 {
			delPort = extport
		}
		logger.Info("Deleting port mapping", "extport", delPort)
		m.DeleteMapping(protocol, delPort, intport)
	}()
	if p, err := m.AddMapping(protocol, extport, intport, name, mapTimeout); err != nil {
		logger.Warn("Couldn't add port mapping", "err", err)
	} else {
		logger.Info("Mapped network port", "actual_extport", p)
		notify(p)
	}
	for {
		select {
		case _, ok := <-c:
			if !ok {
				return
			}
		case <-refresh.C:
			logger.Debug("Refreshing port mapping")
			if p, err := m.AddMapping(protocol, extport, intport, name, mapTimeout); err != nil {
				logger.Warn("Couldn't refresh port mapping", "err", err)
				notify(0)
			} else {
				notify(p)
			}
			refresh.Reset(mapRefresh)
		}
	}
}

// ExtIP assumes that the local machine is reachable on the given
// external IP address, and that any required ports were mapped manually.
// Mapping operations will not return an error but won't actually do anything.
type ExtIP net.IP

func (n ExtIP) ExternalIP() (net.IP, error) { return net.IP(n), nil }
func (n ExtIP) String() string              { return fmt.Sprintf("ExtIP(%v)", net.IP(n)) }

// These do nothing.

func (ExtIP) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	return uint16(extport), nil
}
func (ExtIP) DeleteMapping(string, int, int) error { return nil }

// Any returns a port mapper that tries to discover any supported
// mechanism on the local network.
func Any() Interface {
	// TODO: attempt to discover whether the local machine has an
	// Internet-class address. Return ExtIP in this case.
	return startautodisc("UPnP or NAT-PMP", func() Interface {
		found := make(chan Interface, 2)
		go func() { found <- discoverUPnP() }()
		go func() { found <- discoverPMP() }()
		for i := 0; i < cap(found); i++ {
			if c := <-found; c != nil {
				return c
			}
		}
		return nil
	})
}

// UPnP returns a port mapper that uses UPnP. It will attempt to
// discover the address of your router using UDP broadcasts.
func UPnP() Interface {
	return startautodisc("UPnP", discoverUPnP)
}

// PMP returns a port mapper that uses NAT-PMP. The provided gateway
// address should be the IP of your router. If the given gateway
// address is nil, PMP will attempt to auto-discover the router.
func PMP(gateway net.IP) Interface {
	if gateway != nil {
		return &pmp{gw: gateway, c: natpmp.NewClient(gateway)}
	}
	return startautodisc("NAT-PMP", discoverPMP)
}

// autodisc represents a port mapping mechanism that is still being
// auto-discovered. Calls to the Interface methods on this type will
// wait until the discovery is done and then call the method on the
// discovered mechanism.
//
// This type is useful because discovery can take a while but we
// want return an Interface value from UPnP, PMP and Auto immediately.
type autodisc struct {
	what string // type of interface being autodiscovered
	once sync.Once
	doit func() Interface

	mu    sync.Mutex
	found Interface
}

func startautodisc(what string, doit func() Interface) Interface {
	// TODO: monitor network configuration and rerun doit when it changes.
	return &autodisc{what: what, doit: doit}
}

func (n *autodisc) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	if err := n.wait(); err != nil {
		return 0, err
	}
	return n.found.AddMapping(protocol, extport, intport, name, lifetime)
}

func (n *autodisc) DeleteMapping(protocol string, extport, intport int) error {
	if err := n.wait(); err != nil {
		return err
	}
	return n.found.DeleteMapping(protocol, extport, intport)
}

func (n *autodisc) ExternalIP() (net.IP, error) {
	if err := n.wait(); err != nil {
		return nil, err
	}
	return n.found.ExternalIP()
}

func (n *autodisc) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.found == nil {
		return n.what
	}
	return n.found.String()
}

// wait blocks until auto-discovery has been performed.
func (n *autodisc) wait() error {
	n.once.Do(func() {
		logging.Info("Starting NAT device discovery", "mechanism", n.what)
		n.mu.Lock()
		n.found = n.doit()
		n.mu.Unlock()
		if n.found != nil {
			logging.Info("NAT device discovered", "mechanism", n.what, "device", n.found)
		}
	})
	if n.found == nil {
		return fmt.Errorf("no %s router discovered", n.what)
	}
	return nil
}
