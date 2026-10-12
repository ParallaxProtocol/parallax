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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/socks"
)

// Connector establishes outbound streams to BIP155 addresses, routing
// each connection directly or through the configured SOCKS5 proxy for
// the address's network. Both dial paths (the v1 scheduler via
// NodeDialer and the v2 DialV2* family) converge here, so proxy policy
// applies to every outbound connection the node makes. PIP-0007 §1.1.
type Connector interface {
	Connect(ctx context.Context, addr addrman.NetAddr) (net.Conn, error)
}

var (
	// errUnreachableNetwork: the address's network has no configured
	// route (policy-unreachable, or a network this build doesn't dial).
	// Never counted as an addrman failure — it says nothing about the
	// address.
	errUnreachableNetwork = errors.New("p2p: no route to network")

	// errProxyDialFailed: the SOCKS5 proxy itself was unreachable or
	// failed negotiation before the destination was attempted. Core's
	// proxy_connection_failed: the destination must not be penalized.
	errProxyDialFailed = errors.New("p2p: proxy connection failed")

	errNoEndpoint = errors.New("p2p: address has no dialable endpoint")

	// ErrHostHidden is returned by DialHost for a clearnet host when
	// this node keeps its clearnet address hidden and has no proxy to
	// reach the host through: a direct connection would reveal the
	// address. It is a configuration state, not a transient failure.
	ErrHostHidden = errors.New("p2p: clearnet is hidden and not proxied; refusing a direct connection")
)

// dialCountsAsFailure classifies a Connect error for addrman accounting:
// only errors that carry evidence about the destination (TCP refusal,
// timeout, or a SOCKS reply about the destination) count toward
// IsTerrible. Routing problems on our side do not.
func dialCountsAsFailure(err error) bool {
	return !errors.Is(err, errUnreachableNetwork) && !errors.Is(err, errProxyDialFailed)
}

// netConnector is the default Connector. policy is re-read per dial —
// the torcontrol auto-proxy can swap the policy at runtime. A nil
// policy func (or one returning nil) dials clearnet directly — the
// pre-PIP-0007 behavior, and the fallback for servers constructed
// without Start in tests.
type netConnector struct {
	policy  func() *netPolicy
	timeout time.Duration
}

func (c *netConnector) currentPolicy() *netPolicy {
	if c.policy == nil {
		return nil
	}
	return c.policy()
}

func (c *netConnector) Connect(ctx context.Context, addr addrman.NetAddr) (net.Conn, error) {
	pol := c.currentPolicy()
	switch addr.Network {
	case addrman.NetIPv4, addrman.NetIPv6:
		ap, ok := addr.AddrPort()
		if !ok {
			return nil, errNoEndpoint
		}
		// Only "can we reach this network at all" is enforced here.
		// The --onlynet restriction is applied by the automatic dial
		// paths, so operator-initiated and static dials keep working
		// under it (Core parity).
		if pol != nil && !pol.hasRoute(addr.Network) {
			return nil, fmt.Errorf("%w: %s", errUnreachableNetwork, addr.Network)
		}
		if pr := pol.proxyFor(addr.Network); pr != nil {
			return c.proxyDial(ctx, pr, ap.Addr().String(), addr.Port)
		}
		d := &net.Dialer{Timeout: c.timeout}
		return d.DialContext(ctx, "tcp", ap.String())
	case addrman.NetTorV3:
		// Onion targets only ever dial as hostnames through a SOCKS5
		// proxy — the Tor daemon performs the rendezvous, and the v3
		// address's embedded ed25519 key authenticates the endpoint.
		pr := pol.proxyFor(addrman.NetTorV3)
		if pr == nil {
			return nil, fmt.Errorf("%w: %s", errUnreachableNetwork, addr.Network)
		}
		return c.proxyDial(ctx, pr, addr.OnionHostname(), addr.Port)
	}
	// I2P/CJDNS are out of PIP-0007's scope entirely.
	return nil, fmt.Errorf("%w: %s", errUnreachableNetwork, addr.Network)
}

// proxyDial runs a SOCKS5 CONNECT and classifies failures: a ReplyError
// is evidence about the destination and passes through; anything else
// means the proxy leg failed and is wrapped in errProxyDialFailed.
//
// No overall timeout is imposed here: the socks package carries Core's
// own budgets (5s to reach the proxy, 20s for the negotiation), and
// clamping the whole exchange to the direct-dial timeout was cutting
// off Tor CONNECTs mid-retry — the daemon often needs >15s to find an
// exit whose policy carries a non-standard port. ctx still propagates
// server-stop cancellation.
func (c *netConnector) proxyDial(ctx context.Context, pr *socks.Proxy, dest string, port uint16) (net.Conn, error) {
	conn, err := pr.Dial(ctx, dest, port)
	if err != nil {
		var rep *socks.ReplyError
		if errors.As(err, &rep) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", errProxyDialFailed, err)
	}
	return conn, nil
}

// netAddrFromTCP projects a *net.TCPAddr onto addrman's BIP155 form.
func netAddrFromTCP(addr *net.TCPAddr) (addrman.NetAddr, bool) {
	if addr == nil || addr.IP == nil {
		return addrman.NetAddr{}, false
	}
	return addrman.FromAddrPort(addr.AddrPort())
}

// connectorDialer adapts a Connector to the NodeDialer interface used by
// the v1 dial scheduler, so proxy policy covers legacy enode dials too.
type connectorDialer struct {
	c Connector
}

func (d connectorDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	ip, ok := netip.AddrFromSlice(dest.IP())
	if !ok {
		return nil, errNoEndpoint
	}
	na, ok := addrman.FromAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(dest.TCP())))
	if !ok {
		return nil, errNoEndpoint
	}
	return d.c.Connect(ctx, na)
}

// policy returns the current net policy. May change at runtime (the
// torcontrol auto-proxy swaps in a new value); callers must not cache
// the result across operations. Nil before Start.
func (srv *Server) policy() *netPolicy {
	return srv.netpol.Load()
}

// NetworkReachable reports whether this node has an outbound route to
// the given BIP155 network under the resolved proxy policy. Exported
// so the disc backend's ingest gate and other wiring consult the same
// source of truth as the dial path. Before Start (no policy yet) it
// answers for the default clearnet-only posture.
func (srv *Server) NetworkReachable(net addrman.NetID) bool {
	pol := srv.policy()
	if pol == nil {
		return net == addrman.NetIPv4 || net == addrman.NetIPv6
	}
	return pol.isReachable(net)
}

// networkProxied reports whether outbound dials to net are routed
// through a SOCKS5 proxy.
func (srv *Server) networkProxied(net addrman.NetID) bool {
	return srv.policy().proxyFor(net) != nil
}

// DialHost opens a TCP connection to host:port for a service outside
// the p2p network, such as the stats reporter, under the same proxy
// policy as peer dials, so such a service cannot reveal what the
// policy hides:
//
//   - a .onion host goes through the onion proxy, and is unreachable
//     without one;
//   - under --proxy, any other host goes through the proxy by name, so
//     neither the connection nor the DNS lookup leaves it (as the DNS
//     seeds do);
//   - a node whose clearnet is otherwise hidden (onion-only) refuses
//     with ErrHostHidden;
//   - otherwise the host is dialed directly.
//
// Before Start there is no policy yet, and the host is dialed directly.
func (srv *Server) DialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	pol := srv.policy()
	if strings.HasSuffix(strings.ToLower(host), ".onion") {
		pr := pol.proxyFor(addrman.NetTorV3)
		if pr == nil {
			return nil, fmt.Errorf("%w: %s", errUnreachableNetwork, addrman.NetTorV3)
		}
		return pr.Dial(ctx, host, port)
	}
	if pr := pol.nameProxy(); pr != nil {
		return pr.Dial(ctx, host, port)
	}
	if pol.clearnetHidden() {
		return nil, ErrHostHidden
	}
	d := &net.Dialer{Timeout: defaultDialTimeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// dialConnector returns the Server's connector, falling back to a
// direct-dial connector for servers that never ran Start (tests).
func (srv *Server) dialConnector() Connector {
	if srv.connector != nil {
		return srv.connector
	}
	return &netConnector{timeout: defaultDialTimeout}
}
