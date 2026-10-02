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

package p2p

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enr"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/support/event"
	"github.com/ParallaxProtocol/parallax/v2/support/metrics"
	"github.com/ParallaxProtocol/parallax/v2/util/mclock"
)

var ErrShuttingDown = errors.New("shutting down")

const (
	baseProtocolVersion    = 5
	baseProtocolLength     = uint64(16)
	baseProtocolMaxMsgSize = 2 * 1024

	snappyProtocolVersion = 5

	pingInterval = 15 * time.Second
)

const (
	// devp2p message codes
	handshakeMsg = 0x00
	discMsg      = 0x01
	pingMsg      = 0x02
	pongMsg      = 0x03
)

// protoHandshake is the RLP structure of the protocol handshake.
type protoHandshake struct {
	Version    uint64
	Name       string
	Caps       []Cap
	ListenPort uint64
	ID         []byte // secp256k1 public key

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// PeerEventType is the type of peer events emitted by a p2p.Server
type PeerEventType string

const (
	// PeerEventTypeAdd is the type of event emitted when a peer is added
	// to a p2p.Server
	PeerEventTypeAdd PeerEventType = "add"

	// PeerEventTypeDrop is the type of event emitted when a peer is
	// dropped from a p2p.Server
	PeerEventTypeDrop PeerEventType = "drop"

	// PeerEventTypeMsgSend is the type of event emitted when a
	// message is successfully sent to a peer
	PeerEventTypeMsgSend PeerEventType = "msgsend"

	// PeerEventTypeMsgRecv is the type of event emitted when a
	// message is received from a peer
	PeerEventTypeMsgRecv PeerEventType = "msgrecv"
)

// PeerEvent is an event emitted when peers are either added or dropped from
// a p2p.Server or when a message is sent or received on a peer connection
type PeerEvent struct {
	Type          PeerEventType `json:"type"`
	Peer          enode.ID      `json:"peer"`
	Error         string        `json:"error,omitempty"`
	Protocol      string        `json:"protocol,omitempty"`
	MsgCode       *uint64       `json:"msg_code,omitempty"`
	MsgSize       *uint32       `json:"msg_size,omitempty"`
	LocalAddress  string        `json:"local,omitempty"`
	RemoteAddress string        `json:"remote,omitempty"`
}

// Peer represents a connected remote node.
type Peer struct {
	rw      *conn
	running map[string]*protoRW
	log     logging.Logger
	created mclock.AbsTime

	wg       sync.WaitGroup
	protoErr chan error
	closed   chan struct{}
	pingRecv chan struct{}
	disc     chan DiscReason

	// Quality telemetry. Updated concurrently from readLoop, the
	// prl-protocol handler, and pingLoop; consumed by the eviction
	// algorithm (p2p/eviction.go). Mirrors Bitcoin Core's
	// NodeEvictionCandidate fields (src/node/eviction.h:18-33).
	//
	// minPing is the smallest RTT observed on this session's ping
	// exchanges, in nanoseconds. Zero before the first pong arrives.
	// Larger values sort lower-quality during eviction.
	minPing atomic.Int64
	// lastPingSent records when we sent the most recent pingMsg
	// (mclock.AbsTime as int64). Used to compute RTT on pong receipt.
	lastPingSent atomic.Int64
	// lastBlockRx is mclock.AbsTime of the most recent novel valid
	// block accepted from this peer (stamped by the block fetcher's
	// acceptance hook, mirroring Core's m_last_block_time on
	// new_block==true). Higher = more recently useful block-relayer.
	// Cheap announcements and duplicate blocks never move it.
	lastBlockRx atomic.Int64
	// lastTxRx is mclock.AbsTime of the most recent transaction from
	// this peer accepted into the txpool (stamped by the tx fetcher's
	// acceptance hook, mirroring Core's m_last_tx_time on mempool
	// accept). Duplicates and rejects never move it; block-relay-only
	// peers leave it at zero.
	lastTxRx atomic.Int64
	// bytesRx is the payload-only byte counter incremented in
	// readLoop after each successful ReadMsg. Framing overhead is
	// excluded; useful for admin-RPC and operator diagnostics, not
	// consumed by the eviction algorithm (Bitcoin Core's
	// NodeEvictionCandidate has no byte counter — see eviction.h).
	bytesRx atomic.Uint64
	// bytesTx is reserved for symmetric accounting at the write
	// path. Currently always zero — instrumentation lands when an
	// admin diagnostic actually needs it; the field is here so the
	// shape doesn't shift later.
	bytesTx atomic.Uint64
	// relayTxs mirrors the peer's Hello.Services & ServiceRelayTx
	// bit. Defaults true until Hello disclosure rules out tx relay.
	// Used to scope the tx-time-based protection round in eviction.
	relayTxs atomic.Bool
	// blockRelayOnly flags an outbound peer in the dial scheduler's
	// block-relay-only bucket (phase 4). Drops Transactions msgs and
	// suppresses address gossip. Set once at peer attach.
	blockRelayOnly atomic.Bool
	// discRequested is set the first time Disconnect is called and
	// never cleared. It marks a peer whose teardown is in progress
	// but whose delpeer event hasn't reached the run loop yet, so
	// the eviction algorithm can skip it as a candidate: re-picking
	// a peer that is already dying would let a concurrent admission
	// count the same victim twice and over-admit past the inbound
	// cap.
	discRequested atomic.Bool
	// preferEvictFlag marks a peer admitted from an address that was
	// in the discourage filter at admission time. Such peers absorb
	// inbound eviction before well-behaved ones (Bitcoin:
	// CNode.m_prefer_evict, set from AddrIsDiscouraged at accept).
	preferEvictFlag atomic.Bool

	// shouldDiscourage is set by MisbehavingFor when a protocol
	// violation should cause the peer to be disconnected and added
	// to the discourage Bloom filter. Bitcoin Core's
	// m_should_discourage (src/net_processing.cpp). The flag is
	// checked at session-end in run; when true, the Server's
	// banman is notified before the connection is closed.
	shouldDiscourage atomic.Bool
	// discourageReason carries the human-readable misbehavior tag
	// for logging. Set alongside shouldDiscourage; only meaningful
	// when shouldDiscourage is true.
	discourageReason atomic.Pointer[string]
	// networkGroup is the cached /16-IPv4 or /32-IPv6 prefix bytes
	// (with a network-tag byte prefix). Populated once at attach
	// time by computeAndCacheNetworkGroup; nil for peers without a
	// TCP RemoteAddr. Eviction protection passes consume this for
	// anti-eclipse diversity preservation.
	networkGroup atomic.Pointer[[]byte]
	// tcpGossipSourced is true when this peer's address came from
	// addrman with source=tcp_gossip at admit time. Set once in the
	// run loop's checkpointAddPeer branch and read on disconnect to
	// keep the per-source peer counter (which drives the
	// MinLegacyPeers floor) in sync. Read-only after admit; no
	// atomic needed.
	tcpGossipSourced bool

	// events receives message send / receive events if set
	events   *event.Feed
	testPipe *MsgPipeRW // for testing
}

// NewPeer returns a peer for testing purposes.
func NewPeer(id enode.ID, name string, caps []Cap) *Peer {
	pipe, _ := net.Pipe()
	return NewPeerForTest(id, name, caps, pipe)
}

// defaultRelayTxs sets the initial RelayTxs state. New peers are
// assumed to relay tx until Hello receipt explicitly disclaims it.
// Called from newPeer; exposed only as a documentation hook.
//
// Deliberate divergence from Bitcoin Core (m_relays_txs defaults
// false until the version message's fRelay bit is seen): Core's
// version message is mandatory, but the disc Hello is not — legacy
// peers never send one, and a false default would permanently
// disable tx relay to every legacy peer. Not exploitable as a
// protection lever: a peer that withholds its Hello has lastTxRx=0
// (no tx-round protection) and is disqualified from the block-relay
// eviction round by relayTxs=true.
func defaultRelayTxs(p *Peer) { p.relayTxs.Store(true) }

// NewPeerForTest returns a peer backed by the supplied net.Conn so
// callers in other packages can drive code paths that depend on
// Peer.RemoteAddr() / Peer.LocalAddr() — for example, AddrmanBackend
// tests that need a *net.TCPAddr remote rather than the synthetic
// pipeAddr returned by net.Pipe.
func NewPeerForTest(id enode.ID, name string, caps []Cap, fd net.Conn) *Peer {
	// Generate a fake set of local protocols to match as running caps. Almost
	// no fields needs to be meaningful here as we're only using it to cross-
	// check with the "remote" caps array.
	protos := make([]Protocol, len(caps))
	for i, cap := range caps {
		protos[i].Name = cap.Name
		protos[i].Version = cap.Version
	}
	node := enode.SignNull(new(enr.Record), id)
	conn := &conn{fd: fd, transport: nil, node: node, caps: caps, name: name}
	peer := newPeer(logging.Root(), conn, protos)
	close(peer.closed) // ensures Disconnect doesn't block
	return peer
}

// NewInboundPeerForTest is NewPeerForTest with the inbound flag set,
// for tests outside this package that depend on session direction
// (e.g. the disc protocol's quorum port handling).
func NewInboundPeerForTest(id enode.ID, name string, caps []Cap, fd net.Conn) *Peer {
	p := NewPeerForTest(id, name, caps, fd)
	p.rw.set(inboundConn, true)
	return p
}

// NewPeerPipe creates a peer for testing purposes.
// The message pipe given as the last parameter is closed when
// Disconnect is called on the peer.
func NewPeerPipe(id enode.ID, name string, caps []Cap, pipe *MsgPipeRW) *Peer {
	p := NewPeer(id, name, caps)
	p.testPipe = pipe
	return p
}

// ID returns the node's public key.
func (p *Peer) ID() enode.ID {
	return p.rw.node.ID()
}

// Node returns the peer's node descriptor.
func (p *Peer) Node() *enode.Node {
	return p.rw.node
}

// Name returns an abbreviated form of the name
func (p *Peer) Name() string {
	s := p.rw.name
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// Fullname returns the node name that the remote node advertised.
func (p *Peer) Fullname() string {
	return p.rw.name
}

// Created returns the monotonic clock time at which this peer was
// constructed. Used by cross-dial dedup and (future) eviction
// telemetry as a "connection age" signal — smaller value = older.
func (p *Peer) Created() mclock.AbsTime {
	return p.created
}

// MinPing returns the smallest RTT observed on this session's
// ping/pong exchanges, in nanoseconds. Zero if no pong has been
// received yet.
func (p *Peer) MinPing() time.Duration {
	return time.Duration(p.minPing.Load())
}

// LastBlockRx returns the monotonic time of the most recent
// block-bearing message received from this peer, or zero if none.
func (p *Peer) LastBlockRx() mclock.AbsTime {
	return mclock.AbsTime(p.lastBlockRx.Load())
}

// LastTxRx returns the monotonic time of the most recent transaction
// bearing message received from this peer, or zero if none.
func (p *Peer) LastTxRx() mclock.AbsTime {
	return mclock.AbsTime(p.lastTxRx.Load())
}

// BytesRx returns the cumulative payload bytes received from this
// peer since session start.
func (p *Peer) BytesRx() uint64 { return p.bytesRx.Load() }

// BytesTx returns the cumulative payload bytes sent to this peer
// since session start.
func (p *Peer) BytesTx() uint64 { return p.bytesTx.Load() }

// RelayTxs reports whether the peer accepts tx relay (mirror of
// Hello.Services & ServiceRelayTx). Defaults true; flipped to
// false on Hello receipt for block-relay-only peers.
func (p *Peer) RelayTxs() bool { return p.relayTxs.Load() }

// SetRelayTxs is sticky-off on block-relay-only and feeler sessions:
// the launch-time clamp must survive the remote's Hello (the disc
// backend echoes the remote's relay-service bit unconditionally), and
// any future consumer that checks only RelayTxs() must never reopen
// tx traffic on those links.
//
// SetRelayTxs is called by the disc protocol on Hello receipt with
// the peer's services flags. Concurrency-safe.
func (p *Peer) SetRelayTxs(v bool) {
	if v && (p.BlockRelayOnly() || p.Feeler()) {
		return
	}
	p.relayTxs.Store(v)
}

// BlockRelayOnly reports whether this is a block-relay-only outbound
// peer. Always false for inbound peers and full-relay outbound.
func (p *Peer) BlockRelayOnly() bool { return p.blockRelayOnly.Load() }

// SetBlockRelayOnly is called by the dial scheduler at peer attach
// time when the peer occupies a block-relay-only outbound slot.
// Sticky for the session lifetime.
func (p *Peer) SetBlockRelayOnly(v bool) { p.blockRelayOnly.Store(v) }

// MisbehavingFor flags the peer for discourage + disconnect.
// reason is a short tag (e.g., "oversized-msg", "invalid-header")
// retained for log diagnostics. Idempotent: subsequent calls keep
// the first reason. Bitcoin Core's Misbehaving() (the modern
// post-pointscore form, src/net_processing.cpp).
//
// The peer disconnects on the next message dispatch; the run loop
// notifies the BanList on session close. The wire DiscReason is
// DiscProtocolError — we don't expose a distinct "you misbehaved"
// reason on the wire (no benefit, and it'd help adversaries
// calibrate their misbehavior thresholds).
//
// Nil-safe so fuzz tests / dispatch-only paths that don't construct
// a Peer can still drive handler entry points without panicking.
func (p *Peer) MisbehavingFor(reason string) {
	if p == nil {
		return
	}
	if p.shouldDiscourage.CompareAndSwap(false, true) {
		r := reason
		p.discourageReason.Store(&r)
		// Async disconnect — Disconnect itself is async; we can't
		// hold any locks here because callers are deep in protocol
		// handlers.
		go p.Disconnect(DiscProtocolError)
	}
}

// ShouldDiscourage reports whether the peer was flagged for
// discourage during the session. Used by the Server's session-end
// hook to populate the BanList.
func (p *Peer) ShouldDiscourage() bool { return p.shouldDiscourage.Load() }

// MarkPreferEvict stamps the peer as a preferred inbound-eviction
// victim. Set at admission when the remote address was already in
// the discourage filter (Bitcoin: CNode.m_prefer_evict from
// AddrIsDiscouraged at accept). Sticky for the session.
func (p *Peer) MarkPreferEvict() { p.preferEvictFlag.Store(true) }

// PreferEvict reports the admission-time discouraged mark.
func (p *Peer) PreferEvict() bool { return p.preferEvictFlag.Load() }

// DiscourageReason returns the misbehavior tag set by the first
// MisbehavingFor call on this peer, or the empty string if none.
func (p *Peer) DiscourageReason() string {
	r := p.discourageReason.Load()
	if r == nil {
		return ""
	}
	return *r
}

// MarkBlockRx stamps the lastBlockRx telemetry to the current
// monotonic time. Called when a novel valid block sourced from this
// peer is accepted into the chain — never on mere message receipt,
// so eviction protection can't be earned without useful work
// (Bitcoin Core net_processing.cpp, m_last_block_time).
func (p *Peer) MarkBlockRx() {
	p.lastBlockRx.Store(int64(mclock.Now()))
}

// MarkTxRx stamps the lastTxRx telemetry. Called when a transaction
// sourced from this peer is accepted into the txpool — never on
// mere message receipt (Bitcoin Core net_processing.cpp,
// m_last_tx_time).
func (p *Peer) MarkTxRx() {
	p.lastTxRx.Store(int64(mclock.Now()))
}

// Caps returns the capabilities (supported subprotocols) of the remote peer.
func (p *Peer) Caps() []Cap {
	// TODO: maybe return copy
	return p.rw.caps
}

// RunningCap returns true if the peer is actively connected using any of the
// enumerated versions of a specific protocol, meaning that at least one of the
// versions is supported by both this node and the peer p.
func (p *Peer) RunningCap(protocol string, versions []uint) bool {
	if proto, ok := p.running[protocol]; ok {
		for _, ver := range versions {
			if proto.Version == ver {
				return true
			}
		}
	}
	return false
}

// RemoteAddr returns the remote address of the network connection.
func (p *Peer) RemoteAddr() net.Addr {
	return p.rw.fd.RemoteAddr()
}

// LocalAddr returns the local address of the network connection.
func (p *Peer) LocalAddr() net.Addr {
	return p.rw.fd.LocalAddr()
}

// Disconnect terminates the peer connection with the given reason.
// It returns immediately and does not wait until the connection is closed.
func (p *Peer) Disconnect(reason DiscReason) {
	p.discRequested.Store(true)
	if p.testPipe != nil {
		p.testPipe.Close()
	}

	select {
	case p.disc <- reason:
	case <-p.closed:
	}
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	id := p.ID()
	return fmt.Sprintf("Peer %x %v", id[:8], p.RemoteAddr())
}

// Inbound returns true if the peer is an inbound connection
func (p *Peer) Inbound() bool {
	return p.rw.is(inboundConn)
}

// Feeler reports whether this is a short-lived feeler/addrfetch
// probe connection. Feelers exist only to verify liveness and warm
// the addrbook; like block-relay-only peers they take no part in
// transaction relay (Bitcoin: RejectIncomingTxs covers feelers too).
func (p *Peer) Feeler() bool {
	return p.rw.is(feelerConn)
}

// OnionPeer reports whether this peer's effective network is Tor: an
// outbound dial to a .onion target, or an inbound stream delivered by
// the local Tor daemon while our onion service is active (PIP-0007
// §3.2). Onion peers' address observations never feed the
// self-address quorum, and the disc greeting advertises the onion
// self-address to them.
func (p *Peer) OnionPeer() bool {
	return p.rw.is(onionConn)
}

// DialTarget returns the address this outbound session was dialed at,
// and ok=false for inbound sessions or legacy dials that recorded
// none. It is the peer's real address even when the connection runs
// through a proxy, whose endpoint RemoteAddr would report instead.
func (p *Peer) DialTarget() (addrman.NetAddr, bool) {
	t := p.rw.dialTarget()
	return t, t.Network != 0
}

// ProxiedConn reports whether the connection was dialed through a
// SOCKS5 proxy. RemoteAddr is then the proxy, not the peer — address
// logic must not treat it as an observation of the peer.
func (p *Peer) ProxiedConn() bool {
	return p.rw.is(proxiedConn)
}

// SetDialTargetForTest stamps an outbound dial target on a
// test-constructed peer, mirroring MarkInboundForTest. Production
// conns get the target at dial time.
func (p *Peer) SetDialTargetForTest(a addrman.NetAddr) { p.rw.setDialTarget(a) }

// MarkOnionForTest sets the onion conn flag on a test-constructed
// peer, mirroring MarkInboundForTest.
func (p *Peer) MarkOnionForTest() { p.rw.set(onionConn, true) }

// MarkProxiedForTest sets the proxied conn flag on a test-constructed
// peer.
func (p *Peer) MarkProxiedForTest() { p.rw.set(proxiedConn, true) }

// MarkInboundForTest sets the inbound conn flag on a test-constructed
// peer. Production conns get the flag at accept time; test harnesses
// (NewPeer / NewPeerForTest) start with no flags and need this to
// exercise inbound-only paths such as the GetPeers response gate.
func (p *Peer) MarkInboundForTest() { p.rw.set(inboundConn, true) }

// MarkFeelerForTest sets the feeler conn flag on a test-constructed
// peer, for exercising feeler-only gates (see MarkInboundForTest).
func (p *Peer) MarkFeelerForTest() { p.rw.set(feelerConn, true) }

// UsingV2Handshake reports whether this session is authenticated via
// the PIP-0006 Phase 2b BIP324-style v2 handshake (true) or the legacy
// RLPx ECIES handshake (false). Callers use this to tell whether the
// remote supports the v2 transport: a v2 session proves v2 support,
// while a legacy session says nothing about whether the remote would
// also accept v2 — it only tells us they accepted legacy from us.
func (p *Peer) UsingV2Handshake() bool {
	_, ok := p.rw.transport.(*v2Transport)
	return ok
}

func newPeer(log logging.Logger, conn *conn, protocols []Protocol) *Peer {
	protomap := matchProtocols(protocols, conn.caps, conn)
	p := &Peer{
		rw:       conn,
		running:  protomap,
		created:  mclock.Now(),
		disc:     make(chan DiscReason),
		protoErr: make(chan error, len(protomap)+1), // protocols + pingLoop
		closed:   make(chan struct{}),
		pingRecv: make(chan struct{}, 16),
		log:      logging.New("id", conn.node.ID(), "conn", conn.flags),
	}
	defaultRelayTxs(p)
	return p
}

func (p *Peer) Log() logging.Logger {
	return p.log
}

func (p *Peer) run() (remoteRequested bool, err error) {
	var (
		writeStart = make(chan struct{}, 1)
		writeErr   = make(chan error, 1)
		readErr    = make(chan error, 1)
		reason     DiscReason // sent to the peer
	)
	p.wg.Add(2)
	go p.readLoop(readErr)
	go p.pingLoop()

	// Start all protocol handlers.
	writeStart <- struct{}{}
	p.startProtocols(writeStart, writeErr)

	// Wait for an error or disconnect.
loop:
	for {
		select {
		case err = <-writeErr:
			// A write finished. Allow the next write to start if
			// there was no error.
			if err != nil {
				reason = DiscNetworkError
				break loop
			}
			writeStart <- struct{}{}
		case err = <-readErr:
			if r, ok := err.(DiscReason); ok {
				remoteRequested = true
				reason = r
			} else {
				reason = DiscNetworkError
			}
			break loop
		case err = <-p.protoErr:
			reason = discReasonForError(err)
			break loop
		case err = <-p.disc:
			reason = discReasonForError(err)
			break loop
		}
	}

	// Mark teardown-in-flight for the eviction candidate filter: a
	// peer that died on its own (read error, remote hangup) but whose
	// delpeer hasn't been processed yet must not be picked as an
	// eviction victim — Disconnect would return instantly on the
	// closed session and the admission would be granted without any
	// capacity actually freed. Core's fDisconnect covers every
	// teardown path the same way.
	p.discRequested.Store(true)
	close(p.closed)
	p.rw.close(reason)
	p.wg.Wait()
	return remoteRequested, err
}

func (p *Peer) pingLoop() {
	defer p.wg.Done()

	ping := time.NewTimer(pingInterval)
	defer ping.Stop()

	for {
		select {
		case <-ping.C:
			// Stamp send time BEFORE the SendItems call returns so a
			// fast pong reply (test pipes) can't observe an unset
			// lastPingSent. Stamp only when no ping is outstanding
			// (the pong consumes the stamp via Swap): overwriting an
			// outstanding stamp would measure a late pong for ping N
			// against ping N+1's send time and under-report minPing.
			// One outstanding ping at a time is also Core's
			// m_ping_nonce_sent discipline.
			p.lastPingSent.CompareAndSwap(0, int64(mclock.Now()))
			if err := SendItems(p.rw, pingMsg); err != nil {
				p.protoErr <- err
				return
			}
			ping.Reset(pingInterval)
		case <-p.pingRecv:
			SendItems(p.rw, pongMsg)

		case <-p.closed:
			return
		}
	}
}

// recordPongRTT computes RTT from the most recent ping send time
// and updates minPing if the new sample improves on the running
// minimum. Called from handle() on pongMsg receipt.
//
// A zero lastPingSent means we received a pong without an
// outstanding ping (test scaffolding, an adversarial peer, or a
// duplicate pong); skip the update. The Swap consumes the stamp so
// each ping is measured against at most one pong. Negative RTT
// (clock skew, monotonic-broken stub) is also ignored.
func (p *Peer) recordPongRTT() {
	sent := p.lastPingSent.Swap(0)
	if sent == 0 {
		return
	}
	rtt := int64(mclock.Now()) - sent
	if rtt <= 0 {
		return
	}
	for {
		cur := p.minPing.Load()
		if cur != 0 && rtt >= cur {
			return
		}
		if p.minPing.CompareAndSwap(cur, rtt) {
			return
		}
	}
}

func (p *Peer) readLoop(errc chan<- error) {
	defer p.wg.Done()
	for {
		msg, err := p.rw.ReadMsg()
		if err != nil {
			errc <- err
			return
		}
		// Payload-only counter — framing overhead is excluded so
		// inter-peer comparisons remain meaningful regardless of
		// transport (rlpx vs v2Transport may differ on framing).
		p.bytesRx.Add(uint64(msg.Size))
		msg.ReceivedAt = time.Now()
		if err = p.handle(msg); err != nil {
			errc <- err
			return
		}
	}
}

func (p *Peer) handle(msg Msg) error {
	switch {
	case msg.Code == pingMsg:
		msg.Discard()
		select {
		case p.pingRecv <- struct{}{}:
		case <-p.closed:
		}
	case msg.Code == pongMsg:
		msg.Discard()
		p.recordPongRTT()
	case msg.Code == discMsg:
		// This is the last message. We don't need to discard or
		// check errors because, the connection will be closed after it.
		return decodeDisconnectMessage(msg.Payload)
	case msg.Code < baseProtocolLength:
		// ignore other base protocol messages
		return msg.Discard()
	default:
		// it's a subprotocol message
		proto, err := p.getProto(msg.Code)
		if err != nil {
			return fmt.Errorf("msg code out of range: %v", msg.Code)
		}
		if metrics.Enabled {
			m := fmt.Sprintf("%s/%s/%d/%#02x", ingressMeterName, proto.Name, proto.Version, msg.Code-proto.offset)
			metrics.GetOrRegisterMeter(m, nil).Mark(int64(msg.meterSize))
			metrics.GetOrRegisterMeter(m+"/packets", nil).Mark(1)
		}
		select {
		case proto.in <- msg:
			return nil
		case <-p.closed:
			return io.EOF
		}
	}
	return nil
}

// decodeDisconnectMessage decodes the payload of discMsg.
func decodeDisconnectMessage(r io.Reader) (reason DiscReason) {
	s := rlp.NewStream(r, 100)
	k, _, err := s.Kind()
	if err != nil {
		return DiscInvalid
	}
	if k == rlp.List {
		s.List()
		err = s.Decode(&reason)
	} else {
		// Legacy path: some implementations, including older Parallax and
		// geth releases, sent the disconnect reason as a byte array by
		// accident.
		err = s.Decode(&reason)
	}
	if err != nil {
		reason = DiscInvalid
	}
	return reason
}

func countMatchingProtocols(protocols []Protocol, caps []Cap) int {
	n := 0
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				n++
			}
		}
	}
	return n
}

// matchProtocols creates structures for matching named subprotocols.
func matchProtocols(protocols []Protocol, caps []Cap, rw MsgReadWriter) map[string]*protoRW {
	sort.Sort(capsByNameAndVersion(caps))
	offset := baseProtocolLength
	result := make(map[string]*protoRW)

outer:
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				// If an old protocol version matched, revert it
				if old := result[cap.Name]; old != nil {
					offset -= old.Length
				}
				// Assign the new match
				result[cap.Name] = &protoRW{Protocol: proto, offset: offset, in: make(chan Msg), w: rw}
				offset += proto.Length

				continue outer
			}
		}
	}
	return result
}

func (p *Peer) startProtocols(writeStart <-chan struct{}, writeErr chan<- error) {
	p.wg.Add(len(p.running))
	for _, proto := range p.running {
		proto.closed = p.closed
		proto.wstart = writeStart
		proto.werr = writeErr
		var rw MsgReadWriter = proto
		if p.events != nil {
			rw = newMsgEventer(rw, p.events, p.ID(), proto.Name, p.Info().Network.RemoteAddress, p.Info().Network.LocalAddress)
		}
		p.log.Trace(fmt.Sprintf("Starting protocol %s/%d", proto.Name, proto.Version))
		go func() {
			defer p.wg.Done()
			err := proto.Run(p, rw)
			if err == nil {
				p.log.Trace(fmt.Sprintf("Protocol %s/%d returned", proto.Name, proto.Version))
				err = errProtocolReturned
			} else if err != io.EOF {
				p.log.Trace(fmt.Sprintf("Protocol %s/%d failed", proto.Name, proto.Version), "err", err)
			}
			p.protoErr <- err
		}()
	}
}

// getProto finds the protocol responsible for handling
// the given message code.
func (p *Peer) getProto(code uint64) (*protoRW, error) {
	for _, proto := range p.running {
		if code >= proto.offset && code < proto.offset+proto.Length {
			return proto, nil
		}
	}
	return nil, newPeerError(errInvalidMsgCode, "%d", code)
}

type protoRW struct {
	Protocol
	in     chan Msg        // receives read messages
	closed <-chan struct{} // receives when peer is shutting down
	wstart <-chan struct{} // receives when write may start
	werr   chan<- error    // for write results
	offset uint64
	w      MsgWriter
}

func (rw *protoRW) WriteMsg(msg Msg) (err error) {
	if msg.Code >= rw.Length {
		return newPeerError(errInvalidMsgCode, "not handled")
	}
	msg.meterCap = rw.cap()
	msg.meterCode = msg.Code

	msg.Code += rw.offset

	select {
	case <-rw.wstart:
		err = rw.w.WriteMsg(msg)
		// Report write status back to Peer.run. It will initiate
		// shutdown if the error is non-nil and unblock the next write
		// otherwise. The calling protocol code should exit for errors
		// as well but we don't want to rely on that.
		rw.werr <- err
	case <-rw.closed:
		err = ErrShuttingDown
	}
	return err
}

func (rw *protoRW) ReadMsg() (Msg, error) {
	select {
	case msg := <-rw.in:
		msg.Code -= rw.offset
		return msg, nil
	case <-rw.closed:
		return Msg{}, io.EOF
	}
}

// PeerInfo represents a short summary of the information known about a connected
// peer. Sub-protocol independent fields are contained and initialized here, with
// protocol specifics delegated to all connected sub-protocols.
type PeerInfo struct {
	// ENR is the peer's Parallax Node Record. Emitted only for
	// legacy-RLPx-authenticated peers; v2 sessions have no ENR
	// (session-scoped identity derived from ephemeral X25519 keys)
	// so the field marshals as null there.
	ENR *string `json:"enr"`
	// Enode is the peer's enode URL. Emitted for legacy peers;
	// marshals as null for v2 peers for the same reason as ENR.
	Enode *string `json:"enode"`
	// ID is the peer's persistent node identifier. Emitted only for
	// legacy peers; v2 sessions have no persistent identity (the
	// underlying hash rotates on every reconnect) so the field
	// marshals as null for them. Operators correlate v2 peers via
	// (RemoteAddress, LocalAddress) instead.
	ID      *string  `json:"id"`
	Name    string   `json:"name"` // Name of the node, including client type, version, OS, custom data
	Caps    []string `json:"caps"` // Protocols advertised by this peer
	Network struct {
		LocalAddress  string `json:"localAddress"`  // Local endpoint of the TCP data connection
		RemoteAddress string `json:"remoteAddress"` // Remote endpoint of the TCP data connection
		// Address is the peer's logical address when known — the
		// outbound dial target ("ip:port" or "host.onion:port"),
		// meaningful when the socket's RemoteAddress is only a SOCKS5
		// proxy. Empty for inbound proxied/onion peers, which are
		// anonymous by design. Core's getpeerinfo "addr" analog.
		Address string `json:"address,omitempty"`
		// Network classifies the peer's transport: "ipv4", "ipv6" or
		// "onion". Core's getpeerinfo "network" field.
		Network string `json:"network"`
		Inbound bool   `json:"inbound"`
		Trusted bool   `json:"trusted"`
		Static  bool   `json:"static"`
	} `json:"network"`
	Protocols map[string]any `json:"protocols"` // Sub-protocol specific metadata fields
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *Peer) Info() *PeerInfo {
	// Gather the protocol capabilities
	var caps []string
	for _, cap := range p.Caps() {
		caps = append(caps, cap.String())
	}
	// Assemble the generic peer metadata. Enode, ENR, and ID all
	// describe a PERSISTENT identity — for v2 peers none of them is
	// persistent, so all three marshal as null. Operators correlate
	// v2 peers via RemoteAddress + LocalAddress and the
	// parallax-disc.handshake="v2" tag.
	info := &PeerInfo{
		Name:      p.Fullname(),
		Caps:      caps,
		Protocols: make(map[string]any),
	}
	if !p.UsingV2Handshake() {
		url := p.Node().URLv4()
		id := p.ID().String()
		info.Enode = &url
		info.ID = &id
		if p.Node().Seq() > 0 {
			enr := p.Node().String()
			info.ENR = &enr
		}
	}
	info.Network.LocalAddress = p.LocalAddr().String()
	info.Network.RemoteAddress = p.RemoteAddr().String()
	info.Network.Inbound = p.rw.is(inboundConn)
	info.Network.Trusted = p.rw.is(trustedConn)
	info.Network.Static = p.rw.is(staticDialedConn)
	target := p.rw.dialTarget()
	if target.Network != 0 {
		info.Network.Address = target.String()
	}
	// Classify from the dial target when we have one: a proxied
	// peer's socket address is the SOCKS5 proxy (usually loopback
	// IPv4), which would mislabel every proxied IPv6 peer.
	switch {
	case p.rw.is(onionConn) || target.Network == addrman.NetTorV3:
		info.Network.Network = "onion"
	case target.Network == addrman.NetIPv6:
		info.Network.Network = "ipv6"
	case target.Network == addrman.NetIPv4:
		info.Network.Network = "ipv4"
	default:
		info.Network.Network = "ipv4"
		if ra, ok := p.RemoteAddr().(*net.TCPAddr); ok && ra.IP.To4() == nil {
			info.Network.Network = "ipv6"
		}
	}

	// Gather all the running protocol infos
	for _, proto := range p.running {
		protoInfo := any("unknown")
		if query := proto.Protocol.PeerInfo; query != nil {
			if metadata := query(p.ID()); metadata != nil {
				protoInfo = metadata
			} else {
				protoInfo = "handshake"
			}
		}
		info.Protocols[proto.Name] = protoInfo
	}
	return info
}
