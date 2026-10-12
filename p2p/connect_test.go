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
	"io"
	"net"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
)

// fakeSocksProxy is a minimal single-shot no-auth SOCKS5 responder. It
// records the DOMAINNAME target of the CONNECT request and then closes.
type fakeSocksProxy struct {
	ln    net.Listener
	destC chan string
}

func startFakeSocksProxy(t *testing.T) *fakeSocksProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeSocksProxy{ln: ln, destC: make(chan string, 1)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(hdr[1]))); err != nil {
			return
		}
		conn.Write([]byte{0x05, 0x00}) // no auth
		head := make([]byte, 5)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		dest := make([]byte, int(head[4]))
		if _, err := io.ReadFull(conn, dest); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
			return
		}
		p.destC <- string(dest)
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90})
	}()
	return p
}

func mustNetAddr(t *testing.T, net addrman.NetID, addr []byte, port uint16) addrman.NetAddr {
	t.Helper()
	na, err := addrman.NewNetAddr(net, addr, port)
	if err != nil {
		t.Fatal(err)
	}
	return na
}

func TestNetConnectorDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		if c, err := ln.Accept(); err == nil {
			close(accepted)
			c.Close()
		}
	}()

	c := &netConnector{timeout: 5 * time.Second} // nil policy: direct clearnet
	ap := ln.Addr().(*net.TCPAddr)
	na := mustNetAddr(t, addrman.NetIPv4, ap.IP.To4(), uint16(ap.Port))
	conn, err := c.Connect(context.Background(), na)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never saw the direct connection")
	}
}

func TestNetConnectorViaProxy(t *testing.T) {
	proxy := startFakeSocksProxy(t)
	pol, err := newNetPolicy(&Config{ProxyAddr: proxy.ln.Addr().String(), ProxyNoRandomize: true})
	if err != nil {
		t.Fatal(err)
	}
	c := &netConnector{policy: func() *netPolicy { return pol }, timeout: 5 * time.Second}

	na := mustNetAddr(t, addrman.NetIPv4, []byte{203, 0, 113, 9}, 32110)
	conn, err := c.Connect(context.Background(), na)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case dest := <-proxy.destC:
		// The proxy must see the literal as a DOMAINNAME target — no
		// local resolution, no direct dial.
		if dest != "203.0.113.9" {
			t.Errorf("proxy saw target %q, want 203.0.113.9", dest)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never saw a CONNECT")
	}
}

func TestNetConnectorUnreachable(t *testing.T) {
	pol, err := newNetPolicy(&Config{OnlyNet: []string{"ipv4"}})
	if err != nil {
		t.Fatal(err)
	}
	c := &netConnector{policy: func() *netPolicy { return pol }, timeout: time.Second}

	// The connector enforces only "is this network routable at all".
	// --onlynet is an automatic-dial restriction applied by the dial
	// paths, so it must NOT make the connector refuse a clearnet
	// target — operator-initiated and static dials go through here
	// too and are exempt from --onlynet, as in Core.
	if !pol.hasRoute(addrman.NetIPv6) {
		t.Error("ipv6 should stay routable under onlynet=ipv4")
	}
	if pol.isReachable(addrman.NetIPv6) {
		t.Error("ipv6 should not be automatically dialable under onlynet=ipv4")
	}
	// Onion with no proxy has no route at all — refused here.
	tor := mustNetAddr(t, addrman.NetTorV3, make([]byte, 32), 32110)
	if _, err := c.Connect(context.Background(), tor); !errors.Is(err, errUnreachableNetwork) {
		t.Errorf("tor_v3 without a proxy: got %v", err)
	}
}

func TestNetConnectorOnionViaProxy(t *testing.T) {
	proxy := startFakeSocksProxy(t)
	pol, err := newNetPolicy(&Config{OnionProxyAddr: proxy.ln.Addr().String(), ProxyNoRandomize: true})
	if err != nil {
		t.Fatal(err)
	}
	c := &netConnector{policy: func() *netPolicy { return pol }, timeout: 5 * time.Second}

	onion, err := addrman.ParseOnion("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion", 32110)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.Connect(context.Background(), onion)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case dest := <-proxy.destC:
		if dest != "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion" {
			t.Errorf("proxy saw target %q, want the onion hostname", dest)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never saw the onion CONNECT")
	}

	// Without an onion route the same target is refused before any
	// socket opens.
	direct := &netConnector{timeout: time.Second}
	if _, err := direct.Connect(context.Background(), onion); !errors.Is(err, errUnreachableNetwork) {
		t.Errorf("onion without route: got %v, want errUnreachableNetwork", err)
	}
}

// TestDialV2OnionEndToEnd drives a started Server's DialV2 at an onion
// target and asserts the CONNECT reaches the proxy with the hostname —
// the full path: reachability policy → cooldown → connector → SOCKS5.
func TestDialV2OnionEndToEnd(t *testing.T) {
	proxy := startFakeSocksProxy(t)
	srv := &Server{Config: Config{
		Name:             "onion-dialer",
		MaxPeers:         10,
		NoDial:           true,
		PrivateKey:       newkey(),
		OnionProxyAddr:   proxy.ln.Addr().String(),
		ProxyNoRandomize: true,
	}}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	onion, err := addrman.ParseOnion("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion", 32110)
	if err != nil {
		t.Fatal(err)
	}
	// The dial reaches the proxy and then fails at the v2 handshake
	// (the fake proxy connects nowhere) — the assertion is the
	// CONNECT target.
	_ = srv.DialV2(onion)
	select {
	case dest := <-proxy.destC:
		if dest != onion.OnionHostname() {
			t.Errorf("proxy saw %q, want %q", dest, onion.OnionHostname())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialV2 never sent a CONNECT through the proxy")
	}
}

func TestDialCountsAsFailure(t *testing.T) {
	if dialCountsAsFailure(errUnreachableNetwork) {
		t.Error("unreachable network must not count against the address")
	}
	if dialCountsAsFailure(errProxyDialFailed) {
		t.Error("proxy failure must not count against the address")
	}
	if !dialCountsAsFailure(errors.New("connection refused")) {
		t.Error("a destination error must count")
	}
}

func TestConnectorDialerProxiesV1Dials(t *testing.T) {
	// The v1 scheduler's default NodeDialer must route through the
	// connector, so --proxy covers legacy enode dials.
	proxy := startFakeSocksProxy(t)
	pol, err := newNetPolicy(&Config{ProxyAddr: proxy.ln.Addr().String(), ProxyNoRandomize: true})
	if err != nil {
		t.Fatal(err)
	}
	d := connectorDialer{c: &netConnector{policy: func() *netPolicy { return pol }, timeout: 5 * time.Second}}

	node := newNode(randomID(), "198.51.100.42:30000")
	conn, err := d.Dial(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case dest := <-proxy.destC:
		if dest != "198.51.100.42" {
			t.Errorf("proxy saw target %q, want 198.51.100.42", dest)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never saw the v1 dial")
	}
}

// TestDialHostViaProxy — under --proxy a service host (the stats
// reporter's) goes through the proxy by name, so neither the
// connection nor the DNS lookup reveals the node.
func TestDialHostViaProxy(t *testing.T) {
	proxy := startFakeSocksProxy(t)
	pol, err := newNetPolicy(&Config{ProxyAddr: proxy.ln.Addr().String(), ProxyNoRandomize: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{}
	srv.netpol.Store(pol)

	conn, err := srv.DialHost(context.Background(), "status.parallaxprotocol.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case dest := <-proxy.destC:
		if dest != "status.parallaxprotocol.org" {
			t.Errorf("proxy saw target %q, want the hostname unresolved", dest)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never saw a CONNECT")
	}
}

// TestDialHostOnionOnly — an onion-only node has no clearnet route
// that keeps its address hidden, so a clearnet host is refused rather
// than dialed directly; an onion host goes through the onion proxy.
func TestDialHostOnionOnly(t *testing.T) {
	proxy := startFakeSocksProxy(t)
	pol, err := newNetPolicy(&Config{OnlyNet: []string{"onion"}, OnionProxyAddr: proxy.ln.Addr().String(), ProxyNoRandomize: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{}
	srv.netpol.Store(pol)

	if _, err := srv.DialHost(context.Background(), "status.parallaxprotocol.org", 443); !errors.Is(err, ErrHostHidden) {
		t.Fatalf("clearnet host on an onion-only node: got %v, want ErrHostHidden", err)
	}
	const onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	conn, err := srv.DialHost(context.Background(), onion, 80)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if dest := <-proxy.destC; dest != onion {
		t.Errorf("proxy saw target %q, want %q", dest, onion)
	}
}

// TestDialHostDirect — with no proxy configured the host is dialed
// directly, as before.
func TestDialHostDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pol, err := newNetPolicy(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{}
	srv.netpol.Store(pol)

	conn, err := srv.DialHost(context.Background(), "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
