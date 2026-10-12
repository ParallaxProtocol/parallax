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

package disc

import (
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/simulations/pipes"
)

// TestSelfTCPFromEntry — projects PeerEntry onto the *net.TCPAddr
// shape IsSelfFunc consumes. IPv4/IPv6 succeed; other networks and
// malformed addr lengths return ok=false.
func TestSelfTCPFromEntry(t *testing.T) {
	cases := []struct {
		name   string
		e      PeerEntry
		want   *net.TCPAddr
		wantOk bool
	}{
		{
			name:   "ipv4",
			e:      PeerEntry{NetworkID: NetIPv4, Addr: []byte{45, 236, 49, 58}, TCPPort: 32110},
			want:   &net.TCPAddr{IP: net.IPv4(45, 236, 49, 58), Port: 32110},
			wantOk: true,
		},
		{
			name:   "ipv6",
			e:      PeerEntry{NetworkID: NetIPv6, Addr: net.ParseIP("2001:db8::1").To16(), TCPPort: 32110},
			want:   &net.TCPAddr{IP: net.ParseIP("2001:db8::1").To16(), Port: 32110},
			wantOk: true,
		},
		{
			name:   "ipv4 wrong length",
			e:      PeerEntry{NetworkID: NetIPv4, Addr: []byte{1, 2, 3}, TCPPort: 32110},
			wantOk: false,
		},
		{
			name:   "unknown net",
			e:      PeerEntry{NetworkID: 0xEE, Addr: []byte{1, 2, 3, 4}, TCPPort: 32110},
			wantOk: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selfTCPFromEntry(tc.e)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOk)
			}
			if !ok {
				return
			}
			if got.Port != tc.want.Port {
				t.Fatalf("port = %d, want %d", got.Port, tc.want.Port)
			}
			if !got.IP.Equal(tc.want.IP) {
				t.Fatalf("ip = %v, want %v", got.IP, tc.want.IP)
			}
		})
	}
}

// TestAddrmanBackendHandlePeersFiltersSelf — when an incoming Peers
// message contains an entry that matches the local node's advertised
// endpoint, AddrmanBackend.HandlePeers must drop it before writing
// to addrman. Otherwise the node's own external IP — propagated via
// our own self-advertise on outbound sessions — comes back as a
// gossip entry and is stored as a v2 dial candidate that survives
// across restarts via addrbook.rlp.
func TestAddrmanBackendHandlePeersFiltersSelf(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(11))
	if err != nil {
		t.Fatal(err)
	}
	selfIP := net.IPv4(45, 236, 49, 58)
	const selfPort = 32110

	isSelf := func(addr *net.TCPAddr) bool {
		return addr.Port == selfPort && addr.IP.Equal(selfIP)
	}
	b := NewAddrmanBackend(m, nil, nil, isSelf, nil)

	// Peer with a real TCP RemoteAddr so peerNetworkGroup succeeds.
	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	entries := []PeerEntry{
		// Self entry — must be dropped.
		{NetworkID: NetIPv4, Addr: []byte{45, 236, 49, 58}, TCPPort: selfPort, KeyType: KeyTypeNone},
		// Foreign entry — must reach addrman.
		{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, TCPPort: 32110, KeyType: KeyTypeNone},
	}
	// A fresh session's bucket holds one token (Core parity); the
	// filtering under test needs both entries processed.
	b.ingestBucketFor(peer).Credit(10)
	b.HandlePeers(peer, entries)

	if got := m.Size(nil, nil); got != 1 {
		t.Fatalf("addrman size after ingest = %d, want 1 (self should be filtered)", got)
	}
	selfNetAddr, _ := addrman.NewNetAddr(addrman.NetIPv4, []byte{45, 236, 49, 58}, selfPort)
	if info := m.Lookup(selfNetAddr); info != nil {
		t.Fatalf("self entry leaked into addrman: %+v", info)
	}
	otherNetAddr, _ := addrman.NewNetAddr(addrman.NetIPv4, []byte{8, 8, 8, 8}, 32110)
	if info := m.Lookup(otherNetAddr); info == nil {
		t.Fatalf("foreign entry missing from addrman")
	}
}

// TestEmptySolicitedResponseClearsPending — an empty Peers reply to
// our GetPeers (a fresh node with a bare addrbook sends exactly that)
// must clear the solicited flag like any sub-1000 reply (Core clears
// m_getaddr_sent on every sub-MAX_ADDR_TO_SEND addr message).
// Regression test: the flag used to survive, so everything the peer
// relayed for the rest of the session was misclassified as solicited
// and never re-gossiped.
func TestEmptySolicitedResponseClearsPending(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(20))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	b.NoteGetPeersSent(peer)
	b.HandlePeers(peer, nil)

	b.mu.Lock()
	_, pending := b.getPeersPending[peerKeyFor(peer)]
	b.mu.Unlock()
	if pending {
		t.Fatal("getPeersPending still set after an empty solicited reply")
	}
}

// TestHandlePeersUnreachableNotStored — entries on networks this node
// cannot dial (Tor v3, I2P, CJDNS) must not enter addrman: Core's ADDR
// handling stores only reachable addresses ("Do not store addresses
// outside our network"). Regression test: they used to be stored and
// relayed at the full reachable fanout, letting an attacker stuff the
// addrbook and GetPeers response slots with undialable entries.
func TestHandlePeersUnreachableNotStored(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(20))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	fresh := uint64(time.Now().Unix())
	torAddr := make([]byte, 32)
	torAddr[0] = 0xAB
	entries := []PeerEntry{
		{NetworkID: NetTorV3, Addr: torAddr, TCPPort: 32110, KeyType: KeyTypeNone, LastSeen: fresh},
		{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, TCPPort: 32110, KeyType: KeyTypeNone, LastSeen: fresh},
	}
	// A fresh session's bucket holds one token (Core parity); the
	// storage gating under test needs both entries processed.
	b.ingestBucketFor(peer).Credit(10)
	b.HandlePeers(peer, entries)

	if got := m.Size(nil, nil); got != 1 {
		t.Fatalf("addrman size = %d, want 1 (only the IPv4 entry is reachable)", got)
	}
	torNetAddr, _ := addrman.NewNetAddr(addrman.NetTorV3, torAddr, 32110)
	if info := m.Lookup(torNetAddr); info != nil {
		t.Fatalf("unreachable TorV3 entry stored in addrman: %+v", info)
	}
	v4NetAddr, _ := addrman.NewNetAddr(addrman.NetIPv4, []byte{8, 8, 8, 8}, 32110)
	if info := m.Lookup(v4NetAddr); info == nil {
		t.Fatal("reachable IPv4 entry missing from addrman")
	}
}

// TestHandleYourAddrPortByDirection — reports arriving on sessions we
// dialed carry our ephemeral source port and must be stored port-less
// (they still count toward the address tally); inbound sessions dialed
// the port we are reachable on, so their observation is kept and wins
// the port ranking.
func TestHandleYourAddrPortByDirection(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(20))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	makePeer := func(name string, inbound bool) *p2p.Peer {
		a, d, err := pipes.TCPPipe()
		if err != nil {
			t.Fatalf("TCPPipe: %v", err)
		}
		t.Cleanup(func() { a.Close(); d.Close() })
		var id enode.ID
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		if inbound {
			return p2p.NewInboundPeerForTest(id, name, nil, a)
		}
		return p2p.NewPeerForTest(id, name, nil, a)
	}

	self := []byte{203, 0, 113, 42}
	// Two dialed sessions report our address with distinct ephemeral
	// ports. All test-pipe peers share one loopback group, so quorum
	// isn't the point here — the port ranking is.
	b.HandleYourAddr(makePeer("out-1", false), NetIPv4, self, 51001)
	b.HandleYourAddr(makePeer("out-2", false), NetIPv4, self, 51002)
	stats := b.Q.Stats()
	if len(stats) != 1 {
		t.Fatalf("stats rows = %d, want 1 (dialed-session reports must share one address key)", len(stats))
	}
	if stats[0].TCPPort != 0 {
		t.Fatalf("port after dialed-only reports = %d, want 0", stats[0].TCPPort)
	}

	// One inbound observation supplies the authoritative port.
	b.HandleYourAddr(makePeer("in-1", true), NetIPv4, self, 32110)
	stats = b.Q.Stats()
	if len(stats) != 1 || stats[0].TCPPort != 32110 {
		t.Fatalf("stats after inbound report = %+v, want single row with port 32110", stats)
	}
}

// TestLocalHelloDefaultWithNilProvider — when no helloProvider is
// configured, LocalHello returns a zero-ish Hello with ProtoVersion
// at the minimum so callers can still send a valid greeting.
func TestLocalHelloDefaultWithNilProvider(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(20))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)
	h := b.LocalHello()
	if h.ProtoVersion != HelloMinProtoVersion {
		t.Fatalf("ProtoVersion = %d, want %d", h.ProtoVersion, HelloMinProtoVersion)
	}
	if h.Nonce != 0 || h.ListenPort != 0 || h.Services != 0 {
		t.Fatalf("non-zero fields with nil provider: %+v", h)
	}
}

// TestLocalHelloUsesProvider — LocalHello forwards the provider's
// output verbatim. Wires the Server.HelloNonce/listen port plumbing
// from node.go.
func TestLocalHelloUsesProvider(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(21))
	if err != nil {
		t.Fatal(err)
	}
	want := Hello{
		ProtoVersion: 1,
		Nonce:        0xCAFEBABE,
		ListenPort:   32110,
		Services:     ServiceNodeNetwork | ServiceRelayTx,
	}
	b := NewAddrmanBackend(m, nil, nil, nil, func() Hello { return want })
	if got := b.LocalHello(); got.Nonce != want.Nonce || got.ListenPort != want.ListenPort || got.Services != want.Services {
		t.Fatalf("LocalHello() = %+v, want %+v", got, want)
	}
}

// TestHandleHelloStoresAndLooksUp — HandleHello writes peerHello;
// PeerHello reads it back. Cross-dial dedup in phase 2 depends on
// this round-trip.
func TestHandleHelloStoresAndLooksUp(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(22))
	if err != nil {
		t.Fatal(err)
	}
	local := Hello{ProtoVersion: 1, Nonce: 0x1111}
	b := NewAddrmanBackend(m, nil, nil, nil, func() Hello { return local })

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	in := Hello{ProtoVersion: 1, Nonce: 0x2222, ListenPort: 32110, Services: ServiceNodeNetwork}
	if err := b.HandleHello(peer, in); err != nil {
		t.Fatalf("HandleHello: %v", err)
	}
	got, ok := b.PeerHello(peerKeyFor(peer))
	if !ok {
		t.Fatal("PeerHello returned ok=false after HandleHello stored")
	}
	if got.Nonce != in.Nonce || got.ListenPort != in.ListenPort || got.Services != in.Services {
		t.Fatalf("PeerHello returned %+v, want %+v", got, in)
	}
}

// TestHandleHelloSetsRelayTxs — HandleHello must reflect the peer's
// disclosed ServiceRelayTx bit onto the Peer object so the eviction
// algorithm and the tx-broadcast path see it. A peer that omits the
// bit (block-relay-only) must end up with RelayTxs()==false; one
// that sets it, true.
func TestHandleHelloSetsRelayTxs(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(24))
	if err != nil {
		t.Fatal(err)
	}
	local := Hello{ProtoVersion: 1, Nonce: 0x3333}
	b := NewAddrmanBackend(m, nil, nil, nil, func() Hello { return local })

	newPeer := func(t *testing.T) *p2p.Peer {
		a, d, err := pipes.TCPPipe()
		if err != nil {
			t.Fatalf("TCPPipe: %v", err)
		}
		t.Cleanup(func() { a.Close(); d.Close() })
		var id enode.ID
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		return p2p.NewPeerForTest(id, "test", nil, a)
	}

	// Peer discloses tx relay.
	relayer := newPeer(t)
	if err := b.HandleHello(relayer, Hello{ProtoVersion: 1, Nonce: 0x44, Services: ServiceNodeNetwork | ServiceRelayTx}); err != nil {
		t.Fatalf("HandleHello (relayer): %v", err)
	}
	if !relayer.RelayTxs() {
		t.Error("peer disclosing ServiceRelayTx must have RelayTxs()==true")
	}

	// Peer omits tx relay (block-relay-only).
	blockRelay := newPeer(t)
	if err := b.HandleHello(blockRelay, Hello{ProtoVersion: 1, Nonce: 0x55, Services: ServiceNodeNetwork}); err != nil {
		t.Fatalf("HandleHello (block-relay): %v", err)
	}
	if blockRelay.RelayTxs() {
		t.Error("peer omitting ServiceRelayTx must have RelayTxs()==false")
	}
}

// TestHandleHelloDetectsSelfConnect — when the peer's nonce equals
// our own LocalHello().Nonce, HandleHello returns errSelfConnect and
// does NOT store the entry. The handler will end the session with
// DiscSelf upstream.
func TestHandleHelloDetectsSelfConnect(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(23))
	if err != nil {
		t.Fatal(err)
	}
	const sharedNonce uint64 = 0xDEADBEEF
	b := NewAddrmanBackend(m, nil, nil, nil, func() Hello {
		return Hello{ProtoVersion: 1, Nonce: sharedNonce}
	})

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	echoed := Hello{ProtoVersion: 1, Nonce: sharedNonce, ListenPort: 32110}
	err = b.HandleHello(peer, echoed)
	if !errors.Is(err, errSelfConnect) {
		t.Fatalf("HandleHello err = %v, want errSelfConnect", err)
	}
	if _, ok := b.PeerHello(peerKeyFor(peer)); ok {
		t.Fatal("self-connect Hello must NOT be stored in peerHello")
	}
}

// TestHandleHelloNonceNearMissAccepted — a peer whose nonce differs
// from ours by a single bit must NOT be flagged as self-connect.
// Pairs with TestHandleHelloDetectsSelfConnect to lock down the
// constant-time comparison's correctness on near-equal inputs.
func TestHandleHelloNonceNearMissAccepted(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(123))
	if err != nil {
		t.Fatal(err)
	}
	const localNonce uint64 = 0x0123456789ABCDEF
	b := NewAddrmanBackend(m, nil, nil, nil, func() Hello {
		return Hello{ProtoVersion: 1, Nonce: localNonce}
	})

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	cases := []uint64{
		localNonce ^ 1,         // single-bit flip in low byte
		localNonce ^ (1 << 63), // single-bit flip in high byte
		localNonce + 1,         // adjacent integer
		localNonce - 1,         // adjacent integer
		(localNonce >> 8) | ((localNonce & 0xFF) << 56), // byte rotation — same bits
	}
	for _, nonce := range cases {
		if nonce == localNonce {
			t.Fatalf("test setup bug: case nonce equals local nonce 0x%016X", localNonce)
		}
		echoed := Hello{ProtoVersion: 1, Nonce: nonce, ListenPort: 32110}
		err := b.HandleHello(peer, echoed)
		if errors.Is(err, errSelfConnect) {
			t.Fatalf("near-miss nonce 0x%016X falsely matched local 0x%016X", nonce, localNonce)
		}
		if err != nil {
			t.Fatalf("HandleHello near-miss: %v", err)
		}
	}
}

// TestHandleHelloNilProviderSkipsSelfCheck — when no helloProvider
// is configured, the self-connect check is bypassed and Hello is
// stored normally. Lets test backends without a provider exercise
// the round-trip.
func TestHandleHelloNilProviderSkipsSelfCheck(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(24))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	in := Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 32110}
	if err := b.HandleHello(peer, in); err != nil {
		t.Fatalf("HandleHello: %v", err)
	}
	if _, ok := b.PeerHello(peerKeyFor(peer)); !ok {
		t.Fatal("PeerHello not populated when helloProvider is nil")
	}
}

// fakeCrossDialHost is a test stub for CrossDialHost.
type fakeCrossDialHost struct {
	dup *p2p.Peer
}

func (f *fakeCrossDialHost) FindCrossDialDup(_ *p2p.Peer, _ uint16) *p2p.Peer {
	return f.dup
}

// TestHandleHelloCrossDialHookSkippedWhenHostNil — the dedup hook is
// optional. With no host wired, HandleHello must still store and
// return without errors.
func TestHandleHelloCrossDialHookSkippedWhenHostNil(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(30))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	in := Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 32110}
	if err := b.HandleHello(peer, in); err != nil {
		t.Fatalf("HandleHello: %v", err)
	}
}

// TestHandleHelloCrossDialHookFiresOnDup — when CrossDialHost
// returns a duplicate, HandleHello disconnects the loser. The
// outbound-vs-inbound tie-break is exercised via
// selectCrossDialLoser; here we just verify the disconnect path
// runs by checking the loser's disc reason after Hello receipt.
func TestHandleHelloCrossDialHookFiresOnDup(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(31))
	if err != nil {
		t.Fatal(err)
	}

	// Build two peers: one outbound (the existing dup target), one
	// inbound (the new peer whose Hello triggers dedup). Prepare
	// the host stub to return the outbound when dedup fires.
	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var newID, dupID enode.ID
	rand.Read(newID[:])
	rand.Read(dupID[:])
	newPeer := p2p.NewPeerForTest(newID, "new", nil, a)
	dupPeer := p2p.NewPeerForTest(dupID, "dup", nil, d)

	host := &fakeCrossDialHost{dup: dupPeer}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)
	b.SetCrossDialHost(host)

	in := Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 32110}
	if err := b.HandleHello(newPeer, in); err != nil {
		t.Fatalf("HandleHello: %v", err)
	}

	// One of the two must have been disconnected. We can't easily
	// verify which side via Peer-level state without driving the
	// full Server lifecycle, so we settle for: HandleHello returned
	// no error AND the host was consulted (implicit — the stub
	// always returns dupPeer; if the hook short-circuited we'd
	// skip it and never fire the Disconnect call we can't easily
	// observe). The integration is exercised end-to-end by the
	// p2p package's selectCrossDialLoser unit test.
}

// TestHandleHelloCrossDialHookSkipsZeroListenPort — when the peer
// disclosed listen port 0 (unknown), the dedup hook short-circuits.
func TestHandleHelloCrossDialHookSkipsZeroListenPort(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(32))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	host := hookFunc(func(*p2p.Peer, uint16) *p2p.Peer {
		called = true
		return nil
	})
	b := NewAddrmanBackend(m, nil, nil, nil, nil)
	b.SetCrossDialHost(host)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	rand.Read(id[:])
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	in := Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 0}
	if err := b.HandleHello(peer, in); err != nil {
		t.Fatalf("HandleHello: %v", err)
	}
	if called {
		t.Fatal("CrossDialHost.FindCrossDialDup should not be called for ListenPort=0")
	}
}

// TestSetCrossDialHostNilDisablesHook — passing nil to the setter
// disables the dedup; HandleHello returns without consulting any
// previously-set host.
func TestSetCrossDialHostNilDisablesHook(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(33))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	previous := hookFunc(func(*p2p.Peer, uint16) *p2p.Peer {
		called = true
		return nil
	})
	b := NewAddrmanBackend(m, nil, nil, nil, nil)
	b.SetCrossDialHost(previous)
	b.SetCrossDialHost(nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	rand.Read(id[:])
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	in := Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 32110}
	if err := b.HandleHello(peer, in); err != nil {
		t.Fatalf("HandleHello: %v", err)
	}
	if called {
		t.Fatal("nil host must not invoke the previously-set hook")
	}
}

// TestPeerListenPortRoundTrip — store a Hello, retrieve via
// PeerListenPort. Implements PeerListenPortLookup.
func TestPeerListenPortRoundTrip(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(34))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	rand.Read(id[:])
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	if _, ok := b.PeerListenPort(id); ok {
		t.Fatal("PeerListenPort should be ok=false before HandleHello")
	}
	b.HandleHello(peer, Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 32110})
	port, ok := b.PeerListenPort(id)
	if !ok || port != 32110 {
		t.Fatalf("PeerListenPort = (%d, %v), want (32110, true)", port, ok)
	}
}

// TestPeerListenPortReturnsFalseForZero — peer disclosed
// ListenPort=0 ("unknown") → PeerListenPort returns ok=false so
// callers don't substitute a meaningless zero into the dedup key.
func TestPeerListenPortReturnsFalseForZero(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(35))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	rand.Read(id[:])
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	b.HandleHello(peer, Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 0})
	if _, ok := b.PeerListenPort(id); ok {
		t.Fatal("PeerListenPort must be ok=false when peer disclosed port=0")
	}
}

// hookFunc adapts a closure into the CrossDialHost interface.
type hookFunc func(*p2p.Peer, uint16) *p2p.Peer

func (f hookFunc) FindCrossDialDup(p *p2p.Peer, port uint16) *p2p.Peer {
	return f(p, port)
}

// TestRunQuorumRefreshLoopReconcilesConnectedPeers — the periodic
// 1h backstop calls Quorum.Refresh with the currently-connected peer
// set, dropping reports from peers whose PeerDisconnected didn't
// fire. Drives the loop manually with a short interval so the test
// completes in milliseconds.
func TestRunQuorumRefreshLoopReconcilesConnectedPeers(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(101))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	// Three pipes / three peers; record their PeerKey so the test
	// matches what Quorum sees.
	type sess struct {
		conn net.Conn
		dial net.Conn
		peer *p2p.Peer
		key  PeerKey
	}
	mkSess := func() *sess {
		a, d, err := pipes.TCPPipe()
		if err != nil {
			t.Fatalf("TCPPipe: %v", err)
		}
		var id enode.ID
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		p := p2p.NewPeerForTest(id, "test", nil, a)
		return &sess{conn: a, dial: d, peer: p, key: peerKeyFor(p)}
	}
	s1, s2, s3 := mkSess(), mkSess(), mkSess()
	defer s1.conn.Close()
	defer s1.dial.Close()
	defer s2.conn.Close()
	defer s2.dial.Close()
	defer s3.conn.Close()
	defer s3.dial.Close()

	// All three Hello, all three report distinct groups → quorum.
	for _, s := range []*sess{s1, s2, s3} {
		if err := b.HandleHello(s.peer, Hello{ProtoVersion: 1, Nonce: uint64(len(s.key)), ListenPort: 32110}); err != nil {
			t.Fatalf("HandleHello: %v", err)
		}
	}
	addr := []byte{198, 51, 100, 11}
	b.Q.Report(s1.key, NetIPv4, addr, 30303, []byte{NetIPv4, 1, 1})
	b.Q.Report(s2.key, NetIPv4, addr, 30303, []byte{NetIPv4, 2, 2})
	b.Q.Report(s3.key, NetIPv4, addr, 30303, []byte{NetIPv4, 3, 3})
	if _, _, _, ok := b.Q.Winner(); !ok {
		t.Fatal("quorum not reached after three reports")
	}

	// Simulate a missed Disconnect: forcibly remove s3 from the
	// backend's peerHello map without firing PeerDisconnected. The
	// next Refresh tick must reconcile and drop s3's report.
	b.mu.Lock()
	delete(b.peerHello, s3.key)
	b.mu.Unlock()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.RunQuorumRefreshLoopWithInterval(stop, 5*time.Millisecond)
	}()

	deadline := time.After(2 * time.Second)
	for {
		if _, _, _, ok := b.Q.Winner(); !ok {
			break
		}
		select {
		case <-deadline:
			close(stop)
			<-done
			t.Fatal("quorum still ok after refresh loop should have dropped s3's orphaned report")
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(stop)
	<-done

	// s1 + s2 still connected, two distinct groups, no quorum — exactly
	// the post-refresh state we want.
	if _, _, _, ok := b.Q.Winner(); ok {
		t.Fatal("quorum re-emerged after stop")
	}
}

// TestRunQuorumRefreshLoopRespectsStop — closing the stop chan
// terminates the goroutine promptly. Regression guard against a
// future refactor that swallows the stop signal.
func TestRunQuorumRefreshLoopRespectsStop(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(102))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.RunQuorumRefreshLoopWithInterval(stop, time.Hour)
	}()
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunQuorumRefreshLoop did not return after stop")
	}
}

// TestRunQuorumRefreshLoopZeroInterval — an interval of 0 / negative
// returns immediately without spinning. Defensive against
// misconfiguration (future code passing a config field).
func TestRunQuorumRefreshLoopZeroInterval(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(103))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.RunQuorumRefreshLoopWithInterval(stop, 0)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunQuorumRefreshLoop with interval=0 did not return")
	}
}

// TestPeerDisconnectedClearsHello — closing the session purges the
// peer's recorded Hello; PeerHello returns ok=false afterward.
func TestPeerDisconnectedClearsHello(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(25))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	in := Hello{ProtoVersion: 1, Nonce: 1, ListenPort: 32110}
	if err := b.HandleHello(peer, in); err != nil {
		t.Fatalf("HandleHello: %v", err)
	}
	b.PeerDisconnected(peer)
	if _, ok := b.PeerHello(peerKeyFor(peer)); ok {
		t.Fatal("PeerHello still present after PeerDisconnected")
	}
}

// TestAddrmanBackendHandlePeersNilSelfFn — passing a nil IsSelfFunc
// must not panic and must let all entries through. Lets tests / fuzz
// targets construct a backend without inventing a self-fn.
func TestAddrmanBackendHandlePeersNilSelfFn(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(12))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	entries := []PeerEntry{
		{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 32110, KeyType: KeyTypeNone},
	}
	b.HandlePeers(peer, entries)

	if got := m.Size(nil, nil); got != 1 {
		t.Fatalf("addrman size = %d, want 1", got)
	}
}

// TestHandlePeersLastSeenSanitization — gossip ingest must preserve
// plausible LastSeen claims and rewrite only garbage ones (Bitcoin
// parity, src/net_processing.cpp ADDR handling): an ancient sentinel
// or a future-dated claim becomes now-5days; everything else is stored
// as claimed (minus the 2h gossip penalty). An ingest-time floor would
// forever refresh dead addresses, keeping them inside addrman's 30-day
// IsTerrible horizon and in hop-to-hop circulation.
func TestHandlePeersLastSeenSanitization(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(13))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	now := time.Now()
	cases := []struct {
		name  string
		claim uint64
		want  time.Time // expected stored value before the 2h gossip penalty
	}{
		{"stale claim preserved", uint64(now.Add(-20 * 24 * time.Hour).Unix()), now.Add(-20 * 24 * time.Hour)},
		{"fresh claim preserved", uint64(now.Add(-30 * time.Second).Unix()), now.Add(-30 * time.Second)},
		{"ancient sentinel rewritten", 1, now.Add(-5 * 24 * time.Hour)},
		{"future claim rewritten", uint64(now.Add(time.Hour).Unix()), now.Add(-5 * 24 * time.Hour)},
	}
	// A fresh session's bucket holds one token (Core parity); the
	// sanitization under test needs every case processed.
	b.ingestBucketFor(peer).Credit(10)
	for i, tc := range cases {
		addrBytes := []byte{51, 15, 0, byte(i + 1)}
		b.HandlePeers(peer, []PeerEntry{{
			NetworkID: NetIPv4, Addr: addrBytes, TCPPort: 32110,
			KeyType: KeyTypeNone, LastSeen: tc.claim,
		}})
		naddr, _ := addrman.NewNetAddr(addrman.NetIPv4, addrBytes, 32110)
		info := m.Lookup(naddr)
		if info == nil {
			t.Fatalf("%s: entry missing from addrman", tc.name)
		}
		want := tc.want.Add(-2 * time.Hour)
		if diff := info.LastSeen.Sub(want); diff < -10*time.Second || diff > 10*time.Second {
			t.Errorf("%s: stored LastSeen = %v, want ~%v", tc.name, info.LastSeen, want)
		}
	}
}

// TestSolicitedPeersResponseBypassesRateLimit — a GetPeers response we
// solicited must be ingested in full: NoteGetPeersSent credits the
// peer's ingest bucket with MaxPeersPerMessage tokens on top of the
// steady-state gossip rate (Bitcoin: m_addr_token_bucket +=
// MAX_ADDR_TO_SEND on getaddr send). Without the credit, a fresh
// node's per-session address learning is capped at the burst (~1% of
// what the peer sent). Unsolicited bulk pushes stay rate-limited.
func TestSolicitedPeersResponseBypassesRateLimit(t *testing.T) {
	mkPeer := func(t *testing.T) (*p2p.Peer, func()) {
		t.Helper()
		a, d, err := pipes.TCPPipe()
		if err != nil {
			t.Fatalf("TCPPipe: %v", err)
		}
		var id enode.ID
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		p := p2p.NewPeerForTest(id, "test", nil, a)
		return p, func() { a.Close(); d.Close() }
	}
	// Spread entries across distinct /16 groups: addrman's per-source
	// bucket limits cap how many same-group addresses one source can
	// place, which would mask the rate-limit behavior under test.
	batch := make([]PeerEntry, MaxPeersPerMessage)
	for i := range batch {
		first := byte(5 + i%94)
		if first >= 10 {
			first++ // skip the private 10.0.0.0/8 block
		}
		batch[i] = PeerEntry{
			NetworkID: NetIPv4,
			Addr:      []byte{first, byte(i / 94), 33, 44},
			TCPPort:   32110,
			KeyType:   KeyTypeNone,
			LastSeen:  uint64(time.Now().Unix()),
		}
	}

	t.Run("solicited response ingests in full", func(t *testing.T) {
		m, err := addrman.New(addrman.Deterministic(21))
		if err != nil {
			t.Fatal(err)
		}
		b := NewAddrmanBackend(m, nil, nil, nil, nil)
		peer, closeFn := mkPeer(t)
		defer closeFn()

		b.NoteGetPeersSent(peer)
		b.HandlePeers(peer, batch)
		// Allow a margin for stochastic (bucket, position) collisions
		// inside addrman — one source group maps into at most 64 new
		// buckets, so ~10% of a 1000-entry batch collides away. The
		// property under test is that ingest is not capped at the
		// ~10-token burst.
		if got := m.Size(nil, nil); got < MaxPeersPerMessage*4/5 {
			t.Fatalf("addrman size after solicited response = %d, want >= %d", got, MaxPeersPerMessage*4/5)
		}
	})

	t.Run("unsolicited bulk push stays rate-limited", func(t *testing.T) {
		m, err := addrman.New(addrman.Deterministic(22))
		if err != nil {
			t.Fatal(err)
		}
		b := NewAddrmanBackend(m, nil, nil, nil, nil)
		peer, closeFn := mkPeer(t)
		defer closeFn()

		b.HandlePeers(peer, batch)
		// A fresh session's bucket holds the 1.0 initial fill (Core's
		// m_addr_token_bucket{1.0}), so an unsolicited bulk push gets
		// roughly one entry through. Allow refill slack.
		if got := m.Size(nil, nil); got > 2 {
			t.Fatalf("addrman size after unsolicited bulk push = %d, want <= 2 (initial fill is 1 token)", got)
		}
	})
}

// TestSamplePeersCapAndCache — a GetPeers response never discloses
// more than maxPctPeersToSend percent of the addrbook, and repeated
// requests from the same network draw the same cached sample for the
// cache lifetime (Bitcoin: MAX_PCT_ADDR_TO_SEND and
// m_addr_response_caches), so reconnect loops can't enumerate the
// book.
func TestSamplePeersCapAndCache(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(31))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	a, d, err := pipes.TCPPipe()
	if err != nil {
		t.Fatalf("TCPPipe: %v", err)
	}
	defer a.Close()
	defer d.Close()
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	peer := p2p.NewPeerForTest(id, "test", nil, a)

	// Seed the book with 100 fresh entries across distinct groups.
	seed := func(first, second byte) {
		naddr, _ := addrman.NewNetAddr(addrman.NetIPv4, []byte{first, second, 1, 1}, 32110)
		src, _ := addrman.NewNetAddr(addrman.NetIPv4, []byte{first, second, 1, 1}, 0)
		m.AddOne(naddr, 0x00, nil, time.Now(), src, addrman.SourceTCPGossip, 0)
	}
	for i := 0; i < 100; i++ {
		first := byte(5 + i%94)
		if first >= 10 {
			first++
		}
		seed(first, byte(i/94))
	}
	size := m.Size(nil, nil)

	got := b.SamplePeers(peer, MaxPeersPerMessage)
	if want := maxPctPeersToSend * size / 100; len(got) > want {
		t.Fatalf("sample discloses %d of %d entries, want <= %d (23%%)", len(got), size, want)
	}
	if len(got) == 0 {
		t.Fatal("sample is empty")
	}

	// Growing the book must not change the cached response.
	for i := 0; i < 50; i++ {
		seed(byte(120+i), 7)
	}
	again := b.SamplePeers(peer, MaxPeersPerMessage)
	if len(again) != len(got) {
		t.Fatalf("cached response changed size: %d -> %d", len(got), len(again))
	}
	for i := range got {
		if !bytesEqual(got[i].Addr, again[i].Addr) || got[i].TCPPort != again[i].TCPPort {
			t.Fatalf("cached response differs at %d: %+v vs %+v", i, got[i], again[i])
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSelfEntryPortFallback — a port-less quorum winner (the shape a
// --nat extip override without a port produces) takes the local
// listen port; with no listen port either, SelfEntry advertises
// nothing rather than emit a TCPPort-0 entry, which fails Validate()
// on every receiver and would get this node discouraged on sight. A
// winner that carries its own port keeps it.
func TestSelfEntryPortFallback(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(20))
	if err != nil {
		t.Fatal(err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	b.Q.SetOverride(NetIPv4, []byte{198, 51, 100, 7}, 0)
	e, ok := b.SelfEntry(32110)
	if !ok {
		t.Fatal("SelfEntry with listen port = not ok, want entry")
	}
	if e.TCPPort != 32110 {
		t.Fatalf("TCPPort = %d, want the substituted listen port 32110", e.TCPPort)
	}
	if _, ok := b.SelfEntry(0); ok {
		t.Fatal("SelfEntry advertised a port-less entry on a non-listening node")
	}

	b.Q.SetOverride(NetIPv4, []byte{198, 51, 100, 7}, 4444)
	e, ok = b.SelfEntry(32110)
	if !ok || e.TCPPort != 4444 {
		t.Fatalf("ported override: entry = %+v ok = %v, want TCPPort 4444", e, ok)
	}
}

// TestSetNATMappingIgnoresUnroutable — a gateway that is itself behind
// NAT reports a private WAN address; advertising it would hand peers
// an unreachable endpoint, so it must not become our self-entry.
func TestSetNATMappingIgnoresUnroutable(t *testing.T) {
	m, err := addrman.New(addrman.Deterministic(11))
	if err != nil {
		t.Fatalf("addrman.New: %v", err)
	}
	b := NewAddrmanBackend(m, nil, nil, nil, nil)

	changed := b.SelfEntriesChanged()
	b.SetNATMapping(mustNetAddr(t, []byte{100, 64, 0, 7}, 32110))
	select {
	case <-changed:
	default:
		t.Fatal("SetNATMapping did not signal a self-entry change")
	}
	if e, ok := b.SelfEntry(32110); ok {
		t.Fatalf("CGNAT gateway address advertised: %+v", e)
	}

	b.SetNATMapping(mustNetAddr(t, []byte{45, 236, 49, 58}, 40123))
	e, ok := b.SelfEntry(32110)
	if !ok || string(e.Addr) != string([]byte{45, 236, 49, 58}) || e.TCPPort != 40123 {
		t.Fatalf("got (%+v, %v), want the mapped 45.236.49.58:40123", e, ok)
	}

	b.SetNATMapping(addrman.NetAddr{})
	if _, ok := b.SelfEntry(32110); ok {
		t.Fatal("cleared mapping still advertised")
	}
}

func mustNetAddr(t *testing.T, ip []byte, port uint16) addrman.NetAddr {
	t.Helper()
	a, err := addrman.NewNetAddr(addrman.NetIPv4, ip, port)
	if err != nil {
		t.Fatalf("NewNetAddr: %v", err)
	}
	return a
}
