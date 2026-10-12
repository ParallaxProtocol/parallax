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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
)

// testBackend captures handler callbacks so tests can assert on them.
type testBackend struct {
	mu        sync.Mutex
	sample    []PeerEntry
	gotAddrs  []YourAddr
	gotPeers  [][]PeerEntry
	gotHellos []Hello
	obsOK     bool
	self      *PeerEntry // if non-nil, SelfEntry returns (*self, true)
	// selfEntryPort records the listenPort argument of the last
	// SelfEntry call, so tests can assert the handler threads the
	// local Hello's listen port through the self-advertise.
	selfEntryPort uint16
	// localHello is the Hello returned from LocalHello(). Tests that
	// drive Hello flows can set the nonce or other fields.
	localHello Hello
	// helloErr, when non-nil, is returned from HandleHello so tests
	// can simulate a self-connect rejection.
	helloErr error
}

func (b *testBackend) Log() logging.Logger { return logging.New("mod", "disc-test") }

func (b *testBackend) ObserveTheirSource(_ *p2p.Peer) (uint8, []byte, uint16, bool) {
	if !b.obsOK {
		return 0, nil, 0, false
	}
	return NetIPv4, []byte{1, 2, 3, 4}, 30303, true
}

func (b *testBackend) HandleYourAddr(_ *p2p.Peer, net uint8, addr []byte, port uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gotAddrs = append(b.gotAddrs, YourAddr{NetworkID: net, Addr: append([]byte(nil), addr...), TCPPort: port})
}

func (b *testBackend) HandlePeers(_ *p2p.Peer, entries []PeerEntry) []PeerEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]PeerEntry, len(entries))
	copy(cp, entries)
	b.gotPeers = append(b.gotPeers, cp)
	return entries
}

func (b *testBackend) SamplePeers(_ *p2p.Peer, max int) []PeerEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sample) > max {
		return b.sample[:max]
	}
	return b.sample
}

func (b *testBackend) SelfEntries(_ *p2p.Peer, listenPort uint16) []PeerEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.selfEntryPort = listenPort
	if b.self == nil {
		return nil
	}
	return []PeerEntry{*b.self}
}

func (b *testBackend) TrackHandshake(*p2p.Peer, bool) {}
func (b *testBackend) PeerHandshake(enode.ID) string  { return "" }

func (b *testBackend) LocalHello() Hello {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.localHello
}

func (b *testBackend) HandleHello(_ *p2p.Peer, h Hello) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.helloErr != nil {
		return b.helloErr
	}
	b.gotHellos = append(b.gotHellos, h)
	return nil
}

// runHandler spins up Run on one side of a MsgPipe and returns the other
// end so the test can send messages. The session loop returns when the
// app side closes the pipe.
func runHandler(t *testing.T, backend Backend) (app *p2p.MsgPipeRW, done <-chan error) {
	return runHandlerWithPeer(t, backend, nil)
}

// runHandlerWithPeer is the runHandler variant that lets the caller
// configure the *p2p.Peer before Run starts. Tests use this to flip
// block-relay-only or other peer flags.
func runHandlerWithPeer(t *testing.T, backend Backend, configure func(*p2p.Peer)) (app *p2p.MsgPipeRW, done <-chan error) {
	t.Helper()
	// Disable Poisson jitter for the duration of the test — a 2s
	// mean per response wrecks suite runtime.
	prev := getPeersResponseJitterMean()
	SetPeersResponseJitterMean(0)
	t.Cleanup(func() { SetPeersResponseJitterMean(prev) })
	appRW, netRW := p2p.MsgPipe()
	var id enode.ID
	_, _ = rand.Read(id[:])
	peer := p2p.NewPeer(id, "test", nil)
	if configure != nil {
		configure(peer)
	}
	ch := make(chan error, 1)
	go func() {
		ch <- Run(backend, peer, netRW)
	}()
	t.Cleanup(func() {
		appRW.Close()
	})
	return appRW, ch
}

// TestHandlerBlockRelayOnlyHelloClearsRelayTxBit — when the peer is
// flagged block-relay-only, the outgoing Hello clears the
// ServiceRelayTx bit (Bitcoin Core PushNodeVersion fRelay=false on
// m_block_relay_only outbound, src/net.cpp). Other Services bits
// pass through untouched.
func TestHandlerBlockRelayOnlyHelloClearsRelayTxBit(t *testing.T) {
	b := &testBackend{
		obsOK: true,
		localHello: Hello{
			ProtoVersion: HelloMinProtoVersion,
			Nonce:        0xDEADBEEF,
			ListenPort:   32110,
			Services:     ServiceNodeNetwork | ServiceRelayTx,
		},
	}
	app, _ := runHandlerWithPeer(t, b, func(p *p2p.Peer) {
		p.SetBlockRelayOnly(true)
	})

	msg, err := app.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if msg.Code != HelloMsg {
		t.Fatalf("first msg = 0x%02x, want HelloMsg", msg.Code)
	}
	var h Hello
	if err := msg.Decode(&h); err != nil {
		t.Fatalf("decode Hello: %v", err)
	}
	if h.Services&ServiceRelayTx != 0 {
		t.Errorf("BR Hello kept ServiceRelayTx bit: %#x", h.Services)
	}
	if h.Services&ServiceNodeNetwork == 0 {
		t.Errorf("BR Hello dropped non-RelayTx bits: %#x (want NodeNetwork preserved)", h.Services)
	}
}

// TestHandlerBlockRelayOnlySkipsAddressGossip — outbound block-relay-
// only peers must not be sent self-advertise nor GetPeers. The
// outgoing greeting is Hello + YourAddr only; the third message must
// time out (handler is awaiting input, not pushing more out).
func TestHandlerBlockRelayOnlySkipsAddressGossip(t *testing.T) {
	self := PeerEntry{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 32110, KeyType: KeyTypeNone}
	b := &testBackend{
		obsOK:      true,
		self:       &self,
		localHello: Hello{ProtoVersion: HelloMinProtoVersion, ListenPort: 32110, Services: ServiceNodeNetwork},
	}
	app, _ := runHandlerWithPeer(t, b, func(p *p2p.Peer) {
		p.SetBlockRelayOnly(true)
	})

	// Greeting must be exactly Hello + YourAddr.
	first, err := app.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg #1: %v", err)
	}
	if first.Code != HelloMsg {
		t.Fatalf("first msg = 0x%02x, want HelloMsg", first.Code)
	}
	first.Discard()

	second, err := app.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg #2: %v", err)
	}
	if second.Code != YourAddrMsg {
		t.Fatalf("second msg = 0x%02x, want YourAddrMsg", second.Code)
	}
	second.Discard()

	// No third message should arrive: the handler is now in handleOne
	// reading from the wire. Anything else (Peers/self or GetPeers)
	// would be a regression. Use a short deadline to confirm the
	// pipe is idle.
	done := make(chan struct{})
	go func() {
		_, _ = app.ReadMsg()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("handler emitted a third greeting message; block-relay-only must skip self-advertise + GetPeers")
	case <-time.After(150 * time.Millisecond):
		// Expected: no further outbound traffic.
	}
}

// outboxTrackingBackend records whether RegisterPeerOutbox was called.
type outboxTrackingBackend struct {
	*testBackend
	mu         sync.Mutex
	registered bool
}

func (b *outboxTrackingBackend) RegisterPeerOutbox(_ PeerKey, _ chan<- PeerEntry) <-chan struct{} {
	b.mu.Lock()
	b.registered = true
	b.mu.Unlock()
	return make(chan struct{})
}

func (b *outboxTrackingBackend) UnregisterPeerOutbox(_ PeerKey, _ <-chan struct{}) {}

func (b *outboxTrackingBackend) wasRegistered() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.registered
}

// TestHandlerBlockRelayOnlyGetsNoRelayOutbox — block-relay-only peers
// must be excluded from the relay fan-out: no outbox is registered
// for them, so freshly-learned addresses are never pushed to a peer
// that committed not to gossip. A full-relay peer does get one.
func TestHandlerBlockRelayOnlyGetsNoRelayOutbox(t *testing.T) {
	// Block-relay-only: greeting is Hello + YourAddr only (no
	// self-advertise, no GetPeers), and no relay outbox is
	// registered. Drain the two greeting messages to unblock Run,
	// then confirm no registration happened.
	brBackend := &outboxTrackingBackend{testBackend: &testBackend{obsOK: true}}
	appBR, _ := runHandlerWithPeer(t, brBackend, func(p *p2p.Peer) {
		p.SetBlockRelayOnly(true)
	})
	drainOne(t, appBR) // Hello
	drainOne(t, appBR) // YourAddr
	time.Sleep(50 * time.Millisecond)
	if brBackend.wasRegistered() {
		t.Error("block-relay-only peer must not get a relay outbox")
	}
	appBR.Close()

	// Full-relay peer: greeting includes GetPeers, and the outbox is
	// registered.
	fullBackend := &outboxTrackingBackend{testBackend: &testBackend{obsOK: true}}
	appFull, _ := runHandlerWithPeer(t, fullBackend, nil)
	drainGreeting(t, appFull)
	time.Sleep(50 * time.Millisecond)
	if !fullBackend.wasRegistered() {
		t.Error("full-relay peer must get a relay outbox")
	}
	appFull.Close()
}

// TestHandlerBlockRelayOnlyDropsIncomingGetPeers — receiving a
// GetPeers from a block-relay-only peer is silently dropped (no
// Peers reply). The handler must not throw an error.
func TestHandlerBlockRelayOnlyDropsIncomingGetPeers(t *testing.T) {
	b := &testBackend{
		obsOK:      true,
		sample:     []PeerEntry{{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, TCPPort: 30303, KeyType: KeyTypeNone}},
		localHello: Hello{ProtoVersion: HelloMinProtoVersion, ListenPort: 32110, Services: ServiceNodeNetwork},
	}
	app, done := runHandlerWithPeer(t, b, func(p *p2p.Peer) {
		p.SetBlockRelayOnly(true)
	})

	// Greeting: Hello + YourAddr (no GetPeers because BR). Each
	// message's payload must be Discarded so the MsgPipe writer
	// side unblocks (WriteMsg waits on payload consumption).
	if msg, err := app.ReadMsg(); err != nil || msg.Code != HelloMsg {
		t.Fatalf("greeting #1: code=0x%02x err=%v", msg.Code, err)
	} else {
		msg.Discard()
	}
	if msg, err := app.ReadMsg(); err != nil || msg.Code != YourAddrMsg {
		t.Fatalf("greeting #2: code=0x%02x err=%v", msg.Code, err)
	} else {
		msg.Discard()
	}
	// Open the gate by sending a Hello.
	sendTestHello(t, app)

	// Now send GetPeers — should be silently dropped, no Peers reply.
	if err := p2p.Send(app, GetPeersMsg, GetPeers{}); err != nil {
		t.Fatalf("send GetPeers: %v", err)
	}

	noReply := make(chan struct{})
	go func() {
		_, _ = app.ReadMsg()
		close(noReply)
	}()
	select {
	case <-noReply:
		t.Fatal("handler answered GetPeers from block-relay-only peer")
	case <-time.After(150 * time.Millisecond):
		// Expected silence.
	}

	// Handler should still be alive (GetPeers drop is not a
	// disconnect-worthy violation).
	select {
	case err := <-done:
		t.Fatalf("handler exited unexpectedly: %v", err)
	default:
	}
}

// TestHandlerSendsHelloThenYourAddr — both sides write Hello first
// (carrying nonce + listen port) then YourAddr (peer's view of our
// remote source). Pinning the order so a refactor can't accidentally
// reverse it without also updating peers that expect Hello first.
func TestHandlerSendsHelloThenYourAddr(t *testing.T) {
	b := &testBackend{
		obsOK: true,
		localHello: Hello{
			ProtoVersion: HelloMinProtoVersion,
			Nonce:        0xCAFEBABE,
			ListenPort:   32110,
			Services:     ServiceNodeNetwork | ServiceRelayTx,
		},
	}
	app, _ := runHandler(t, b)

	// First: Hello.
	msg, err := app.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg #1: %v", err)
	}
	if msg.Code != HelloMsg {
		t.Fatalf("first msg code = 0x%02x, want Hello 0x%02x", msg.Code, HelloMsg)
	}
	var hello Hello
	if err := msg.Decode(&hello); err != nil {
		t.Fatalf("decode Hello: %v", err)
	}
	if hello.Nonce != b.localHello.Nonce || hello.ListenPort != b.localHello.ListenPort ||
		hello.Services != b.localHello.Services {
		t.Errorf("Hello contents unexpected: %+v vs source %+v", hello, b.localHello)
	}

	// Second: YourAddr.
	msg, err = app.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg #2: %v", err)
	}
	if msg.Code != YourAddrMsg {
		t.Fatalf("second msg code = 0x%02x, want YourAddr 0x%02x", msg.Code, YourAddrMsg)
	}
	var got YourAddr
	if err := msg.Decode(&got); err != nil {
		t.Fatalf("decode YourAddr: %v", err)
	}
	if got.NetworkID != NetIPv4 || got.TCPPort != 30303 {
		t.Errorf("YourAddr contents unexpected: %+v", got)
	}
}

// TestHandlerRejectsMessageBeforeHello — sending YourAddr / Peers /
// GetPeers before our peer has sent Hello is a protocol violation
// and ends the session.
func TestHandlerRejectsMessageBeforeHello(t *testing.T) {
	cases := []struct {
		name string
		send func(p2p.MsgWriter) error
	}{
		{"YourAddr", func(w p2p.MsgWriter) error {
			return p2p.Send(w, YourAddrMsg, YourAddr{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 30303})
		}},
		{"Peers", func(w p2p.MsgWriter) error {
			return p2p.Send(w, PeersMsg, Peers{Entries: []PeerEntry{{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, TCPPort: 30303, KeyType: KeyTypeNone}}})
		}},
		{"GetPeers", func(w p2p.MsgWriter) error {
			return p2p.Send(w, GetPeersMsg, GetPeers{})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &testBackend{obsOK: true}
			app, done := runHandler(t, b)
			drainGreeting(t, app)
			if err := tc.send(app); err != nil {
				t.Fatalf("send %s: %v", tc.name, err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("expected handler error after pre-Hello %s", tc.name)
				}
			case <-time.After(time.Second):
				t.Fatalf("handler didn't exit after pre-Hello %s", tc.name)
			}
		})
	}
}

// TestHandlerIgnoresPeersFromBlockRelayOnly — Core never sets up
// address relay on block-relay-only connections, so an addr message on
// one is ignored outright: it must feed neither addrman nor onward
// relay, and it is not a misbehavior (the session stays up).
func TestHandlerIgnoresPeersFromBlockRelayOnly(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandlerWithPeer(t, b, func(p *p2p.Peer) {
		p.SetBlockRelayOnly(true)
	})
	// Block-relay-only greetings carry no GetPeers, so drain only
	// Hello and YourAddr.
	drainOne(t, app)
	drainOne(t, app)

	hello := Hello{ProtoVersion: HelloMinProtoVersion, Nonce: 0x33, ListenPort: 32110}
	if err := p2p.Send(app, HelloMsg, hello); err != nil {
		t.Fatalf("Hello send: %v", err)
	}
	entry := PeerEntry{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, TCPPort: 30303, KeyType: KeyTypeNone}
	if err := p2p.Send(app, PeersMsg, Peers{Entries: []PeerEntry{entry}}); err != nil {
		t.Fatalf("Peers send: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("handler exited on block-relay-only Peers message: %v", err)
	default:
	}
	b.mu.Lock()
	got := len(b.gotPeers)
	b.mu.Unlock()
	if got != 0 {
		t.Fatalf("HandlePeers called %d times for a block-relay-only peer, want 0", got)
	}
}

// TestHandlerRejectsDoubleHello — second Hello on same session ends
// the session.
func TestHandlerRejectsDoubleHello(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)
	drainGreeting(t, app)

	first := Hello{ProtoVersion: HelloMinProtoVersion, Nonce: 0x11, ListenPort: 32110}
	if err := p2p.Send(app, HelloMsg, first); err != nil {
		t.Fatalf("first Hello send: %v", err)
	}
	second := Hello{ProtoVersion: HelloMinProtoVersion, Nonce: 0x22, ListenPort: 32110}
	if err := p2p.Send(app, HelloMsg, second); err != nil {
		t.Fatalf("second Hello send: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected handler error after double Hello")
		}
	case <-time.After(time.Second):
		t.Fatalf("handler didn't exit after double Hello")
	}
}

// TestHandlerHelloDecodeError — malformed Hello payload ends the
// session with a decode error.
func TestHandlerHelloDecodeError(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)
	drainGreeting(t, app)

	// Send a Hello whose payload is wrong-typed (a single byte
	// string rather than a struct list). Decode must fail.
	if err := p2p.Send(app, HelloMsg, []byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected handler decode error")
		}
	case <-time.After(time.Second):
		t.Fatalf("handler didn't exit on decode error")
	}
}

// TestHandlerHelloValidationError — an invalid Hello (ProtoVersion=0)
// ends the session.
func TestHandlerHelloValidationError(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)
	drainGreeting(t, app)

	bad := Hello{ProtoVersion: 0, Nonce: 1, ListenPort: 32110}
	if err := p2p.Send(app, HelloMsg, bad); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected handler validation error")
		}
	case <-time.After(time.Second):
		t.Fatalf("handler didn't exit on validation error")
	}
}

// TestHandlerHelloEndsSessionOnSelfNonce — when the testBackend
// returns errSelfConnect from HandleHello (simulating a peer
// echoing our own nonce), the handler ends the session.
func TestHandlerHelloEndsSessionOnSelfNonce(t *testing.T) {
	b := &testBackend{
		obsOK:    true,
		helloErr: errSelfConnect,
	}
	app, done := runHandler(t, b)
	drainGreeting(t, app)

	in := Hello{ProtoVersion: HelloMinProtoVersion, Nonce: 1, ListenPort: 32110}
	if err := p2p.Send(app, HelloMsg, in); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errSelfConnect) {
			t.Fatalf("session ended with %v, want errSelfConnect", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler didn't exit after self-nonce Hello")
	}
}

// TestHandlerHelloPropagatesToBackend — a valid Hello reaches
// backend.HandleHello and is captured.
func TestHandlerHelloPropagatesToBackend(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, _ := runHandler(t, b)
	drainGreeting(t, app)

	in := Hello{ProtoVersion: HelloMinProtoVersion, Nonce: 0xABCD, ListenPort: 32110, Services: ServiceNodeNetwork}
	if err := p2p.Send(app, HelloMsg, in); err != nil {
		t.Fatalf("send: %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		n := len(b.gotHellos)
		b.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.gotHellos) != 1 {
		t.Fatalf("backend got %d Hellos, want 1", len(b.gotHellos))
	}
	if b.gotHellos[0].Nonce != in.Nonce || b.gotHellos[0].ListenPort != in.ListenPort {
		t.Fatalf("backend got %+v, want %+v", b.gotHellos[0], in)
	}
}

// TestHandlerAcceptsValidPeersMessage — a well-formed Peers packet ends
// up in HandlePeers, entries with skippable tags are filtered out.
func TestHandlerAcceptsValidPeersMessage(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)

	// Drain our outgoing greeting and send the peer's Hello so the
	// handler will accept further messages.
	drainAndOpen(t, app)

	in := Peers{Entries: []PeerEntry{
		{NetworkID: NetIPv4, Addr: []byte{8, 8, 8, 8}, TCPPort: 30303, KeyType: KeyTypeNone},
		{NetworkID: 0xEE, Addr: []byte{0x00}, TCPPort: 30303}, // unknown net → skip
	}}
	if err := p2p.Send(app, PeersMsg, in); err != nil {
		t.Fatalf("Send: %v", err)
	}
	waitForSample(t, b, 1, 500*time.Millisecond)
	b.mu.Lock()
	got := b.gotPeers[0]
	b.mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("HandlePeers got %d entries, want 1 (after skip)", len(got))
	}
	app.Close()
	// Sess should end cleanly on pipe close.
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit on pipe close")
	}
}

// TestHandlerRejectsOversizedPeersMessage — sending a Peers with too many
// entries disconnects. The pipe close is the session end signal.
func TestHandlerRejectsOversizedPeersMessage(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)
	drainAndOpen(t, app)

	big := Peers{Entries: make([]PeerEntry, MaxPeersPerMessage+1)}
	for i := range big.Entries {
		big.Entries[i] = PeerEntry{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 30303, KeyType: KeyTypeNone}
	}
	if err := p2p.Send(app, PeersMsg, big); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected non-nil error on oversize Peers")
		} else if !errors.Is(err, ErrPeersTooLarge) {
			t.Errorf("expected ErrPeersTooLarge, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not exit on oversize Peers")
	}
}

// TestHandlerAcceptsMultipleUnsolicitedPeers — address relay pushes
// freshly-learned addresses as single-entry Peers messages
// throughout a session. The handler must ingest every one of them
// without disconnecting or flagging the peer as misbehaving; an
// earlier revision capped unsolicited Peers at one, which made
// honest relaying peers discourage each other.
func TestHandlerAcceptsMultipleUnsolicitedPeers(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)
	drainAndOpen(t, app)

	const n = 5
	for i := range n {
		msg := Peers{Entries: []PeerEntry{
			{NetworkID: NetIPv4, Addr: []byte{10, 0, 0, byte(i + 1)}, TCPPort: 30303, KeyType: KeyTypeNone},
		}}
		if err := p2p.Send(app, PeersMsg, msg); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	// All n batches should have been ingested (subject to the ingest
	// token bucket, which the testBackend does not throttle).
	waitForSample(t, b, n, time.Second)

	// The session must still be alive: no disconnect fired.
	select {
	case err := <-done:
		t.Fatalf("handler exited on unsolicited Peers stream: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	app.Close()
}

// TestHandlerRejectsDoubleYourAddr — YourAddr is single-shot; a second
// one is a protocol violation.
func TestHandlerRejectsDoubleYourAddr(t *testing.T) {
	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)
	drainAndOpen(t, app)

	for range 2 {
		if err := p2p.Send(app, YourAddrMsg, YourAddr{NetworkID: NetIPv4, Addr: []byte{5, 6, 7, 8}, TCPPort: 30303}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected non-nil error on second YourAddr")
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not exit on repeat YourAddr")
	}
}

// TestHandlerAnswersGetPeers — a GetPeers gets a Peers response with the
// backend's sample.
func TestHandlerAnswersGetPeers(t *testing.T) {
	b := &testBackend{
		obsOK: true,
		sample: []PeerEntry{
			{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 30303, KeyType: KeyTypeNone, LastSeen: 1700000000},
		},
	}
	app, _ := runHandlerWithPeer(t, b, func(p *p2p.Peer) { p.MarkInboundForTest() })
	drainAndOpenInbound(t, app)

	if err := p2p.Send(app, GetPeersMsg, GetPeers{}); err != nil {
		t.Fatal(err)
	}
	msg, err := app.ReadMsg()
	if err != nil {
		t.Fatal(err)
	}
	if msg.Code != PeersMsg {
		t.Fatalf("got code 0x%02x, want Peers", msg.Code)
	}
	var out Peers
	if err := msg.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(out.Entries))
	}
}

// TestHandlerIgnoresGetPeersOnOutboundConn — we only answer GetPeers
// from peers that connected to us. A node we dialed probing for our
// addrbook is ignored (Bitcoin: getaddr is ignored on outbound
// connections), without disconnecting the session.
func TestHandlerIgnoresGetPeersOnOutboundConn(t *testing.T) {
	b := &testBackend{
		obsOK:  true,
		sample: []PeerEntry{{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 30303, KeyType: KeyTypeNone}},
	}
	// Default harness peers carry no inbound flag: this session is
	// outbound from our side.
	app, done := runHandler(t, b)
	drainAndOpen(t, app)

	if err := p2p.Send(app, GetPeersMsg, GetPeers{}); err != nil {
		t.Fatal(err)
	}
	read := make(chan struct{}, 1)
	go func() {
		if _, err := app.ReadMsg(); err == nil {
			read <- struct{}{}
		}
	}()
	select {
	case <-read:
		t.Fatal("handler answered GetPeers on an outbound connection")
	case <-time.After(150 * time.Millisecond):
	}
	select {
	case err := <-done:
		t.Fatalf("handler exited unexpectedly: %v", err)
	default:
	}
}

// TestHandlerIgnoresRepeatGetPeers — Bitcoin parity: one response per
// session. Second GetPeers yields no response.
func TestHandlerIgnoresRepeatGetPeers(t *testing.T) {
	b := &testBackend{
		obsOK:  true,
		sample: []PeerEntry{{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 30303, KeyType: KeyTypeNone}},
	}
	app, _ := runHandlerWithPeer(t, b, func(p *p2p.Peer) { p.MarkInboundForTest() })
	drainAndOpenInbound(t, app)

	_ = p2p.Send(app, GetPeersMsg, GetPeers{})
	drainOne(t, app) // first response

	_ = p2p.Send(app, GetPeersMsg, GetPeers{})

	// Second request should produce no response; set a short read
	// deadline by racing against a timer.
	read := make(chan p2p.Msg, 1)
	go func() {
		if msg, err := app.ReadMsg(); err == nil {
			read <- msg
		}
	}()
	select {
	case <-read:
		t.Fatal("handler responded to second GetPeers")
	case <-time.After(150 * time.Millisecond):
	}
}

// drainOne reads a single message and discards the payload so MsgPipe's
// sender WriteMsg unblocks. The p2p.MsgPipe contract is that WriteMsg
// stays blocked until the receiver fully consumes the payload reader.
func drainOne(t *testing.T, rw p2p.MsgReader) {
	t.Helper()
	msg, err := rw.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	_ = msg.Discard()
}

// drainGreeting consumes the Hello + YourAddr + GetPeers that an
// outbound handler writes on session start. (p2p.NewPeer yields conn
// flags of 0, which Inbound() reports as false — so every test-harness
// handler takes the outbound branch.)
func drainGreeting(t *testing.T, rw p2p.MsgReader) {
	t.Helper()
	drainOne(t, rw) // Hello
	drainOne(t, rw) // YourAddr
	drainOne(t, rw) // GetPeers
}

// sendTestHello sends a benign Hello on the test pipe so the
// handler's "msg before Hello" gate opens. Used by tests that
// exercise post-Hello message paths (Peers, YourAddr, GetPeers).
func sendTestHello(t *testing.T, w p2p.MsgWriter) {
	t.Helper()
	h := Hello{ProtoVersion: HelloMinProtoVersion, Nonce: 0xFEEDFACE, ListenPort: 32110, Services: ServiceNodeNetwork}
	if err := p2p.Send(w, HelloMsg, h); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
}

// drainAndOpen is the standard test fixture: consume the handler's
// outgoing greeting, then send a benign Hello so the handler accepts
// subsequent messages. Tests that specifically exercise pre-Hello
// rejection should call drainGreeting alone instead.
func drainAndOpen(t *testing.T, app p2p.MsgReadWriter) {
	t.Helper()
	drainGreeting(t, app)
	sendTestHello(t, app)
}

// drainAndOpenInbound is drainAndOpen for handlers whose peer is
// marked inbound: the greeting is Hello + YourAddr only (inbound
// peers get no self-advertise or GetPeers).
func drainAndOpenInbound(t *testing.T, app p2p.MsgReadWriter) {
	t.Helper()
	drainOne(t, app) // Hello
	drainOne(t, app) // YourAddr
	sendTestHello(t, app)
}

func waitForSample(t *testing.T, b *testBackend, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		n := len(b.gotPeers)
		b.mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected %d HandlePeers calls, got timeout", want)
}

// TestHandlerDisconnectsOnMissingHello — a peer that completes
// negotiation but never sends its Hello is disconnected after the
// deadline (Bitcoin's VERSION_HANDSHAKE_TIMEOUT) instead of holding
// a slot forever with an undisclosed relay policy.
func TestHandlerDisconnectsOnMissingHello(t *testing.T) {
	prevDeadline := getHelloDeadline()
	SetHelloDeadline(50 * time.Millisecond)
	t.Cleanup(func() { SetHelloDeadline(prevDeadline) })
	prevJitter := getPeersResponseJitterMean()
	SetPeersResponseJitterMean(0)
	t.Cleanup(func() { SetPeersResponseJitterMean(prevJitter) })

	b := &testBackend{obsOK: true}
	appRW, netRW := p2p.MsgPipe()
	var id enode.ID
	_, _ = rand.Read(id[:])
	// NewPeerPipe wires Disconnect to close the handler-side pipe, so
	// the deadline disconnect actually unwinds the blocked read loop
	// the way a live Server teardown does.
	peer := p2p.NewPeerPipe(id, "test", nil, netRW)
	done := make(chan error, 1)
	go func() { done <- Run(b, peer, netRW) }()
	t.Cleanup(func() { appRW.Close() })

	// Consume the greeting but never send Hello back.
	drainGreeting(t, appRW)

	select {
	case <-done:
		// Session ended: deadline disconnect fired.
	case <-time.After(2 * time.Second):
		t.Fatal("handler still running long after the Hello deadline")
	}
}

// TestHandlerHelloBeatsDeadline — a Hello arriving inside the
// deadline keeps the session alive past it.
func TestHandlerHelloBeatsDeadline(t *testing.T) {
	prevDeadline := getHelloDeadline()
	SetHelloDeadline(150 * time.Millisecond)
	t.Cleanup(func() { SetHelloDeadline(prevDeadline) })

	b := &testBackend{obsOK: true}
	app, done := runHandler(t, b)
	drainGreeting(t, app)
	sendTestHello(t, app)

	select {
	case err := <-done:
		t.Fatalf("handler exited after timely Hello: %v", err)
	case <-time.After(400 * time.Millisecond):
		// Survived well past the deadline.
	}
}

// TestPreHelloMessageDisconnectsWithoutDiscourage — a message before
// Hello ends the session with a plain disconnect and must NOT stamp
// the discourage filter. A pre-flag-day node (protocol Length 3, no
// HelloMsg) leads every session with GetPeers or YourAddr; a
// discourage stamp would ban its address across reconnects —
// including after the node upgrades — turning a brief mixed-
// population rollout window into a longer-lived partition.
func TestPreHelloMessageDisconnectsWithoutDiscourage(t *testing.T) {
	prevJitter := getPeersResponseJitterMean()
	SetPeersResponseJitterMean(0)
	t.Cleanup(func() { SetPeersResponseJitterMean(prevJitter) })

	b := &testBackend{obsOK: true}
	appRW, netRW := p2p.MsgPipe()
	var id enode.ID
	_, _ = rand.Read(id[:])
	peer := p2p.NewPeerPipe(id, "test", nil, netRW)
	done := make(chan error, 1)
	go func() { done <- Run(b, peer, netRW) }()
	t.Cleanup(func() { appRW.Close() })

	drainGreeting(t, appRW)

	// Lead with GetPeers instead of Hello, the exact first message a
	// pre-flag-day node sends.
	if err := p2p.Send(appRW, GetPeersMsg, GetPeers{}); err != nil {
		t.Fatalf("send pre-Hello GetPeers: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("session survived a pre-Hello message")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler still running after pre-Hello message")
	}
	if peer.ShouldDiscourage() {
		t.Fatalf("pre-Hello message stamped discourage (reason %q); want plain disconnect", peer.DiscourageReason())
	}
}

// TestSelfAdvertisePassesListenPort — the handler must thread the
// local Hello's listen port into SelfEntry so a port-less quorum
// winner (e.g. a --nat extip override without a port) can fall back
// to it. Passing 0 made that fallback dead code: a port-0 winner
// would be advertised as TCPPort 0, which fails Validate() on every
// receiver and gets this node discouraged on sight.
func TestSelfAdvertisePassesListenPort(t *testing.T) {
	prevJitter := getPeersResponseJitterMean()
	SetPeersResponseJitterMean(0)
	t.Cleanup(func() { SetPeersResponseJitterMean(prevJitter) })

	b := &testBackend{
		obsOK:      true,
		localHello: Hello{ProtoVersion: HelloMinProtoVersion, ListenPort: 32110, Services: ServiceNodeNetwork},
	}
	appRW, netRW := p2p.MsgPipe()
	var id enode.ID
	_, _ = rand.Read(id[:])
	peer := p2p.NewPeerPipe(id, "test", nil, netRW)
	done := make(chan error, 1)
	go func() { done <- Run(b, peer, netRW) }()
	t.Cleanup(func() {
		appRW.Close()
		<-done
	})

	drainGreeting(t, appRW)

	b.mu.Lock()
	got := b.selfEntryPort
	b.mu.Unlock()
	if got != 32110 {
		t.Fatalf("SelfEntry called with listenPort %d, want the local Hello's 32110", got)
	}
}

// notifyingBackend is a testBackend whose self-address can change
// mid-session, signalled the way AddrmanBackend signals it.
type notifyingBackend struct {
	testBackend
	changedMu sync.Mutex
	changed   chan struct{}
}

func newNotifyingBackend() *notifyingBackend {
	return &notifyingBackend{
		testBackend: testBackend{localHello: Hello{ProtoVersion: HelloMinProtoVersion, ListenPort: 32110, Services: ServiceNodeNetwork}},
		changed:     make(chan struct{}),
	}
}

func (b *notifyingBackend) SelfEntriesChanged() <-chan struct{} {
	b.changedMu.Lock()
	defer b.changedMu.Unlock()
	return b.changed
}

func (b *notifyingBackend) setSelf(e *PeerEntry) {
	b.mu.Lock()
	b.self = e
	b.mu.Unlock()
	b.changedMu.Lock()
	close(b.changed)
	b.changed = make(chan struct{})
	b.changedMu.Unlock()
}

// readSelfAdvert reads the next message and asserts it is a Peers
// message announcing exactly want, failing if none arrives in time.
func readSelfAdvert(t *testing.T, rw p2p.MsgReader, want PeerEntry) {
	t.Helper()
	type result struct {
		p   Peers
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := rw.ReadMsg()
		if err != nil {
			ch <- result{err: err}
			return
		}
		if msg.Code != PeersMsg {
			msg.Discard()
			ch <- result{err: fmt.Errorf("got msg 0x%02x, want Peers", msg.Code)}
			return
		}
		var p Peers
		err = msg.Decode(&p)
		ch <- result{p: p, err: err}
	}()
	var p Peers
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("reading self-advertisement: %v", r.err)
		}
		p = r.p
	case <-time.After(2 * time.Second):
		t.Fatalf("no self-advertisement of %+v within 2s", want)
	}
	if len(p.Entries) != 1 || p.Entries[0].TCPPort != want.TCPPort || string(p.Entries[0].Addr) != string(want.Addr) {
		t.Fatalf("got entries %+v, want [%+v]", p.Entries, want)
	}
}

// TestSelfAdvertiseAfterAddressLearned — an outbound session that
// opened before our address was known must announce it once it
// becomes known, re-announce it when it changes, and stay quiet when
// a notification leaves it unchanged. Sending only at session start
// meant a node behind NAT, whose sessions all open at startup before
// quorum forms, never announced its address.
func TestSelfAdvertiseAfterAddressLearned(t *testing.T) {
	b := newNotifyingBackend()
	app, _ := runHandler(t, b)
	drainGreeting(t, app) // no self-entry yet: Hello, YourAddr, GetPeers

	first := PeerEntry{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 32110}
	b.setSelf(&first)
	readSelfAdvert(t, app, first)

	// Unchanged: nothing may be written. The next message must be the
	// changed entry below, not a repeat of first.
	b.setSelf(&first)
	second := PeerEntry{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 40000}
	b.setSelf(&second)
	readSelfAdvert(t, app, second)
}

// TestSelfAdvertiseRebroadcast — the self-entry is re-sent on the
// Poisson rebroadcast timer even when unchanged (Core's MaybeSendAddr).
func TestSelfAdvertiseRebroadcast(t *testing.T) {
	prev := time.Duration(selfAdvertiseInterval.Load())
	SetSelfAdvertiseInterval(10 * time.Millisecond)
	t.Cleanup(func() { SetSelfAdvertiseInterval(prev) })

	b := newNotifyingBackend()
	self := PeerEntry{NetworkID: NetIPv4, Addr: []byte{1, 2, 3, 4}, TCPPort: 32110}
	b.self = &self
	app, _ := runHandler(t, b)
	drainOne(t, app) // Hello
	drainOne(t, app) // YourAddr
	readSelfAdvert(t, app, self)
	drainOne(t, app) // GetPeers
	readSelfAdvert(t, app, self)
	readSelfAdvert(t, app, self)
}
