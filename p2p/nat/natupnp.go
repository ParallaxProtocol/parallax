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
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

const (
	soapRequestTimeout = 3 * time.Second
	rateLimit          = 200 * time.Millisecond
	retryCount         = 3 // number of retries after a failed AddPortMapping
	randomCount        = 3 // number of random ports to try

	// SSDP search targets for Internet Gateway Devices.
	// Some routers only respond to searches for the root device type
	// (InternetGatewayDevice), not for sub-device types (WANConnectionDevice).
	// We search for both to maximize compatibility.
	URN_InternetGatewayDevice_1 = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
	URN_InternetGatewayDevice_2 = "urn:schemas-upnp-org:device:InternetGatewayDevice:2"
)

type upnp struct {
	dev         *goupnp.RootDevice
	service     string
	client      upnpClient
	mu          sync.Mutex
	lastReqTime time.Time
	rand        *rand.Rand
}

type upnpClient interface {
	GetExternalIPAddress() (string, error)
	AddPortMapping(string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMapping(string, uint16, string) error
	GetNATRSIPStatus() (sip bool, nat bool, err error)
}

func (n *upnp) natEnabled() bool {
	var ok bool
	var err error
	n.withRateLimit(func() error {
		_, ok, err = n.client.GetNATRSIPStatus()
		return err
	})
	if err != nil {
		// Many routers (e.g. Huawei) don't implement the optional
		// GetNATRSIPStatus action. Treat SOAP errors as "NAT is probably
		// enabled" and proceed - the actual port mapping call will fail
		// later if NAT is truly not available.
		logging.Debug("UPnP GetNATRSIPStatus not supported, assuming NAT is enabled", "service", n.service, "err", err)
		return true
	}
	if !ok {
		logging.Debug("UPnP device reports NAT is not enabled", "service", n.service)
		return false
	}
	logging.Debug("UPnP device confirms NAT is enabled", "service", n.service)
	return true
}

func (n *upnp) ExternalIP() (addr net.IP, err error) {
	var ipString string
	n.withRateLimit(func() error {
		ipString, err = n.client.GetExternalIPAddress()
		return err
	})

	if err != nil {
		logging.Warn("UPnP failed to get external IP", "service", n.service, "err", err)
		return nil, err
	}
	ip := net.ParseIP(ipString)
	if ip == nil {
		logging.Warn("UPnP returned invalid external IP", "service", n.service, "response", ipString)
		return nil, errors.New("bad IP in response")
	}
	logging.Debug("UPnP external IP address", "service", n.service, "ip", ip)
	return ip, nil
}

func (n *upnp) AddMapping(protocol string, extport, intport int, desc string, lifetime time.Duration) (uint16, error) {
	ip, err := n.internalAddress()
	if err != nil {
		logging.Warn("UPnP could not determine internal address", "service", n.service, "err", err)
		return 0, err
	}
	protocol = strings.ToUpper(protocol)
	lifetimeS := uint32(lifetime / time.Second)

	if extport == 0 {
		extport = intport
	}

	logging.Debug("UPnP adding port mapping", "service", n.service, "proto", protocol, "extport", extport, "intport", intport, "internal_ip", ip, "lifetime", lifetime, "desc", desc)
	return n.addAnyPortMapping(protocol, extport, intport, ip, desc, lifetimeS)
}

// addAnyPortMapping tries to add a port mapping with the specified external port.
// If the external port is already in use, it will try to assign another port.
func (n *upnp) addAnyPortMapping(protocol string, extport, intport int, ip net.IP, desc string, lifetimeS uint32) (uint16, error) {
	// IGDv2 WANIPConnection2 supports AddAnyPortMapping which lets the router
	// pick an available port if the requested one is taken.
	if client, ok := n.client.(*internetgateway2.WANIPConnection2); ok {
		return n.portWithRateLimit(func() (uint16, error) {
			return client.AddAnyPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
		})
	}
	// For IGDv1 and other v2 services, try with the specified port first.
	var lastErr error
	for i := 0; i < retryCount+1; i++ {
		lastErr = n.withRateLimit(func() error {
			return n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
		})
		if lastErr == nil {
			return uint16(extport), nil
		}
		logging.Debug("UPnP AddPortMapping attempt failed", "service", n.service, "proto", protocol, "extport", extport, "attempt", i+1, "err", lastErr)
	}

	// If that fails, retry with random ports in case of port conflicts.
	for i := 0; i < randomCount; i++ {
		extport = n.randomPort()
		lastErr = n.withRateLimit(func() error {
			return n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
		})
		if lastErr == nil {
			logging.Info("UPnP mapped to random port", "service", n.service, "proto", protocol, "extport", extport, "intport", intport)
			return uint16(extport), nil
		}
		logging.Debug("UPnP random port mapping attempt failed", "service", n.service, "proto", protocol, "extport", extport, "err", lastErr)
	}
	logging.Warn("UPnP AddPortMapping failed (all attempts exhausted)", "service", n.service, "proto", protocol, "intport", intport, "err", lastErr)
	return 0, lastErr
}

func (n *upnp) randomPort() int {
	if n.rand == nil {
		n.rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return n.rand.Intn(math.MaxUint16-10000) + 10000
}

func (n *upnp) internalAddress() (net.IP, error) {
	devaddr, err := net.ResolveUDPAddr("udp4", n.dev.URLBase.Host)
	if err != nil {
		return nil, fmt.Errorf("resolve UPnP device address %q: %v", n.dev.URLBase.Host, err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if x, ok := addr.(*net.IPNet); ok && x.Contains(devaddr.IP) {
				logging.Debug("UPnP internal address resolved", "ip", x.IP, "iface", iface.Name, "device", devaddr.IP)
				return x.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("could not find local address in same net as UPnP device %v (check that your machine and router are on the same subnet)", devaddr)
}

func (n *upnp) DeleteMapping(protocol string, extport, intport int) error {
	err := n.withRateLimit(func() error {
		return n.client.DeletePortMapping("", uint16(extport), strings.ToUpper(protocol))
	})
	if err != nil {
		logging.Debug("UPnP DeletePortMapping failed", "service", n.service, "proto", protocol, "extport", extport, "err", err)
	}
	return err
}

func (n *upnp) String() string {
	return "UPNP " + n.service
}

func (n *upnp) portWithRateLimit(pfn func() (uint16, error)) (uint16, error) {
	var port uint16
	var err error
	fn := func() error {
		port, err = pfn()
		return err
	}
	n.withRateLimit(fn)
	return port, err
}

func (n *upnp) withRateLimit(fn func() error) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	lastreq := time.Since(n.lastReqTime)
	if lastreq < rateLimit {
		time.Sleep(rateLimit - lastreq)
	}
	err := fn()
	n.lastReqTime = time.Now()
	return err
}

const (
	ssdpMulticastAddr = "239.255.255.250:1900"
	ssdpTimeout       = 5 * time.Second
)

// ssdpTargets lists all SSDP search targets to try. We search for both
// the root device type (InternetGatewayDevice) and the sub-device type
// (WANConnectionDevice) because different routers respond to different targets.
var ssdpTargets = []string{
	URN_InternetGatewayDevice_1,
	URN_InternetGatewayDevice_2,
	internetgateway1.URN_WANConnectionDevice_1,
	internetgateway2.URN_WANConnectionDevice_2,
}

// discoverUPnP searches for Internet Gateway Devices using SSDP.
// It uses a custom SSDP implementation that sends M-SEARCH to both
// the multicast group and directly to the default gateway (unicast),
// which is more reliable than multicast alone on many Linux systems.
func discoverUPnP() Interface {
	logging.Info("Searching for UPnP Internet Gateway Device...")

	// Discover device description URLs via SSDP.
	locations := ssdpDiscover()
	if len(locations) == 0 {
		logging.Warn("No UPnP gateway device discovered on the local network",
			"hint", "ensure your router has UPnP enabled and that a local firewall (ufw, iptables, nftables) is not blocking SSDP UDP traffic to/from port 1900")
		return nil
	}

	// Fetch each discovered device and look for IGD services.
	for locStr := range locations {
		loc, err := url.Parse(locStr)
		if err != nil {
			continue
		}
		root, err := goupnp.DeviceByURL(loc)
		if err != nil {
			logging.Debug("UPnP device fetch failed", "url", locStr, "err", err)
			continue
		}
		logging.Debug("UPnP inspecting device", "url", locStr, "friendly_name", root.Device.FriendlyName)
		var found *upnp
		root.Device.VisitServices(func(service *goupnp.Service) {
			if found != nil {
				return
			}
			logging.Debug("UPnP found service", "type", service.ServiceType, "id", service.ServiceId, "url", locStr)
			sc := goupnp.ServiceClient{
				SOAPClient: service.NewSOAPClient(),
				RootDevice: root,
				Location:   loc,
				Service:    service,
			}
			sc.SOAPClient.HTTPClient.Timeout = soapRequestTimeout
			u := matchIGDService(sc)
			if u == nil {
				return
			}
			u.dev = root
			logging.Debug("UPnP matched service, checking NAT status", "service", u.service)
			if u.natEnabled() {
				found = u
			}
		})
		if found != nil {
			logging.Info("UPnP gateway device found", "service", found.service, "url", locStr)
			return found
		}
	}
	logging.Warn("UPnP SSDP found devices but no valid IGD service")
	return nil
}

// ssdpDiscover performs SSDP discovery by sending M-SEARCH requests to both
// the multicast address (239.255.255.250:1900) and the default gateway
// directly (unicast). Uses a single socket bound to 0.0.0.0 for maximum
// compatibility. Returns a set of unique device description Location URLs.
func ssdpDiscover() map[string]bool {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		logging.Warn("UPnP SSDP: failed to open UDP socket", "err", err)
		return nil
	}
	defer conn.Close()

	// Resolve destinations: multicast + unicast gateways.
	multicast, _ := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	destinations := []*net.UDPAddr{multicast}

	if gws := defaultGateways(); len(gws) > 0 {
		for _, gw := range gws {
			destinations = append(destinations, &net.UDPAddr{IP: gw, Port: 1900})
		}
		logging.Debug("UPnP SSDP: will search via multicast and unicast", "gateways", gws)
	} else {
		logging.Debug("UPnP SSDP: will search via multicast only (no gateway detected)")
	}

	// Send M-SEARCH for each target to each destination, 3 times each.
	for _, target := range ssdpTargets {
		req := buildMSearchRequest(target)
		for _, dest := range destinations {
			for i := 0; i < 3; i++ {
				if _, err := conn.WriteTo(req, dest); err != nil {
					logging.Debug("UPnP SSDP: send failed", "dest", dest, "target", target, "err", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	// Collect responses.
	conn.SetDeadline(time.Now().Add(ssdpTimeout))
	locations := make(map[string]bool)
	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			break // timeout or error
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
		if err != nil {
			logging.Debug("UPnP SSDP: malformed response", "from", from, "err", err)
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if loc != "" && !locations[loc] {
			logging.Info("UPnP SSDP: discovered device", "location", loc, "from", from)
			locations[loc] = true
		}
	}
	return locations
}

// buildMSearchRequest constructs an SSDP M-SEARCH packet. The HOST header
// is always set to the standard SSDP multicast address as required by the
// UPnP specification, regardless of whether the packet is sent via multicast
// or unicast.
func buildMSearchRequest(searchTarget string) []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + ssdpMulticastAddr + "\r\n" +
		"ST: " + searchTarget + "\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"\r\n")
}

// defaultGateways returns the default gateways from the routing table,
// falling back to guessGateway where the table can't be read.
func defaultGateways() []net.IP {
	if gws := routeGateways(); len(gws) > 0 {
		return gws
	}
	if gw := guessGateway(); gw != nil {
		return []net.IP{gw}
	}
	return nil
}

// guessGateway returns the likely IP of the default gateway by
// inspecting network interfaces for private network addresses and
// assuming the gateway is at x.x.x.1. This is a best-effort heuristic
// for systems whose routing table routeGateways can't read; it misses
// routers on any other address (commonly x.x.x.254).
func guessGateway() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	privateCIDRs := []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	var privateNets []*net.IPNet
	for _, cidr := range privateCIDRs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, ipnet)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			for _, pnet := range privateNets {
				if pnet.Contains(ip4) {
					gw := make(net.IP, 4)
					copy(gw, ip4)
					gw[3] = 1
					return gw
				}
			}
		}
	}
	return nil
}

// matchIGDService checks if a goupnp ServiceClient corresponds to a known
// IGD service and returns a configured upnp instance, or nil. Used by the
// direct gateway probe fallback. For WANIPConnection:1 and WANPPPConnection:1,
// IGDv1 types are used (the SOAP interface is identical to IGDv2 for v1 URNs).
func matchIGDService(sc goupnp.ServiceClient) *upnp {
	switch sc.Service.ServiceType {
	case internetgateway1.URN_WANIPConnection_1:
		return &upnp{service: "IGDv1-IP1", client: &internetgateway1.WANIPConnection1{ServiceClient: sc}}
	case internetgateway1.URN_WANPPPConnection_1:
		return &upnp{service: "IGDv1-PPP1", client: &internetgateway1.WANPPPConnection1{ServiceClient: sc}}
	case internetgateway2.URN_WANIPConnection_2:
		return &upnp{service: "IGDv2-IP2", client: &internetgateway2.WANIPConnection2{ServiceClient: sc}}
	}
	return nil
}
