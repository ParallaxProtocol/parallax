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
	"bytes"
	"errors"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
)

// Backend is the host-integration surface. The handler calls into Backend
// for observed-address reports, addrbook ingest, addrbook sampling, and
// the self-entry used during the outbound greeting sequence.
//
// The production implementation is AddrmanBackend; tests can supply
// their own.
type Backend interface {
	// ObserveTheirSource records the observed remote TCP source of an
	// inbound or outbound connection. Used to compose our outgoing
	// YourAddr message and, on the peer's side, to feed quorum.
	ObserveTheirSource(peer *p2p.Peer) (network uint8, addr []byte, port uint16, ok bool)

	// HandleYourAddr feeds a peer's reported view of our external
	// address into the quorum tally.
	HandleYourAddr(peer *p2p.Peer, net uint8, addr []byte, port uint16)

	// HandlePeers ingests gossiped entries, applying any per-peer rate
	// limits and the 2-hour gossip LastSeen penalty. Returns the
	// entries that passed the rate limit so the caller can mark
	// exactly those as known to the peer (Core: AddAddressKnown
	// runs after the rate limit).
	HandlePeers(peer *p2p.Peer, entries []PeerEntry) []PeerEntry

	// SamplePeers returns up to max entries for a GetPeers response,
	// subject to reachability filtering. May return nil; the handler
	// still sends a valid (empty) Peers message.
	SamplePeers(peer *p2p.Peer, max int) []PeerEntry

	// SelfEntries returns the PeerEntries we should advertise on an
	// outbound session with the given peer — empty when no
	// self-address has reached quorum and no override or onion
	// service exists. Per-network (PIP-0007 §3.3, Core's
	// GetLocalAddrForPeer): onion peers are told the onion address
	// only (never the IP — an onion-only operator's IP must not leak
	// over a Tor circuit); clearnet peers get the IP plus the onion
	// address, which receivers without a Tor route still relay at the
	// reduced unreachable fanout. listenPort is the TCP port we
	// listen on (used when the quorum winner has port=0).
	SelfEntries(peer *p2p.Peer, listenPort uint16) []PeerEntry

	// TrackHandshake records which handshake variant a peer session
	// was established with. The handler calls this once on session
	// start. Used by admin.peers to show whether a peer is
	// v2-authenticated or legacy+v2.
	TrackHandshake(peer *p2p.Peer, usingV2 bool)

	// PeerHandshake returns the handshake variant recorded for a
	// peer by TrackHandshake, or an empty string if the peer isn't
	// known (connection torn down, never parallax-disc/1-negotiated).
	PeerHandshake(id enode.ID) string

	// LocalHello returns the Hello the handler should send on the
	// outgoing greeting. Carries the local nonce, listen port, and
	// services flag. Bitcoin Core analog: PushNodeVersion.
	LocalHello() Hello

	// HandleHello consumes the peer's Hello on receipt. Must run the
	// self-connect nonce check (returning an error to end the
	// session if the peer's nonce matches our own) and may store
	// the Hello for later lookup.
	HandleHello(peer *p2p.Peer, h Hello) error

	// Log returns the logger to use for protocol-level events.
	Log() logging.Logger
}

// state holds per-peer handler state — one struct per session.
type state struct {
	// sentHello / gotHello track the v2 Hello exchange. Hello is the
	// first message in both directions; receiving any other message
	// before Hello is a protocol violation. Once gotHello is set,
	// it's never reset — a second Hello is also a violation.
	sentHello atomic.Bool
	gotHello  atomic.Bool

	// sentYourAddr: we've written our YourAddr message for this
	// session. Each side sends exactly one, immediately after Hello.
	sentYourAddr atomic.Bool

	// gotYourAddr: we've seen the peer's YourAddr for this session.
	gotYourAddr atomic.Bool

	// peersReceived counts Peers messages received on this session.
	// Retained for diagnostics; no longer gates disconnection, since
	// address relay legitimately pushes unsolicited Peers messages
	// throughout a session (see handlePeers).
	peersReceived atomic.Uint32

	// getPeersSent counts GetPeers requests we've issued to this peer.
	// One-request-per-session is the rule (Bitcoin parity).
	getPeersSent atomic.Uint32

	// getPeersReceived counts GetPeers from the peer. Bitcoin parity:
	// one response per session; further requests are silently ignored.
	getPeersReceived atomic.Uint32

	// knownAddr is the rolling bloom filter tracking addresses the
	// peer is known to have — both ones we sent it and ones it sent
	// us. Used to skip re-relaying addresses the peer already has
	// (Phase 4 RelayAddress discipline, Bitcoin's m_addr_known).
	knownAddr rollingBloom
}

// Run is the per-peer entry point. Called by p2p.Server once the
// subprotocol has been negotiated.
func Run(backend Backend, peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	log := backend.Log().New("peer", peer.ID())
	log.Trace("parallax-disc/1 session starting")

	backend.TrackHandshake(peer, peer.UsingV2Handshake())

	st := &state{}

	// First action on both sides: send Hello carrying the local
	// nonce, listen port, and services flag. Receivers compare the
	// nonce against their own to detect self-connect, and use the
	// listen port to dedup cross-dial pairs (phase 2). Bitcoin Core
	// analog: PushNodeVersion (src/net.cpp).
	if err := sendHello(backend, peer, rw, st); err != nil {
		log.Debug("parallax-disc/1: Hello send failed", "err", err)
	}

	// YourAddr follows Hello: peer's view of our remote source for
	// quorum. Order-independent on the wire because RLPx is
	// multiplexed — but logically Hello must precede YourAddr.
	if err := sendYourAddr(backend, peer, rw, st); err != nil {
		log.Debug("parallax-disc/1: YourAddr send failed", "err", err)
	}

	// Bitcoin's address-relay discipline is direction-sensitive:
	// outbound peers get addr(self) + getaddr, inbound peers get
	// nothing unsolicited. The distinction matters because an inbound
	// peer could be an adversary probing our addrbook.
	//
	// Block-relay-only outbound peers also skip both: by spec they
	// don't participate in address gossip (Bitcoin Core
	// src/net_processing.cpp:3681 — fRelayTxes=false implies no
	// addr or addr_v2 relay). Self-advertise leaks our endpoint to
	// a peer that won't gossip it; GetPeers solicits gossip from a
	// peer we shouldn't accept gossip from.
	//
	// Our self-address is often unknown when an outbound session
	// opens — at startup every session opens before the quorum forms —
	// so the advertisement is repeated for the life of the session:
	// whenever the address changes, and on Core's ~24h rebroadcast
	// cadence. Sending it only at session start left a node behind
	// NAT, whose outbound sessions are long-lived, effectively never
	// announced, so peers never learned to dial its open port.
	if !peer.Inbound() && !peer.BlockRelayOnly() {
		var changed <-chan struct{}
		notifier, canNotify := backend.(selfEntriesNotifier)
		if canNotify {
			changed = notifier.SelfEntriesChanged()
		}
		announced, err := sendSelfAdvertise(backend, peer, rw, st, nil)
		if err != nil {
			log.Debug("parallax-disc/1: self-advertise send failed", "err", err)
		}
		if err := RequestPeers(backend, peer, st, rw); err != nil {
			log.Debug("parallax-disc/1: GetPeers send failed", "err", err)
		}
		if canNotify {
			advStop, advDone := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(advDone)
				runSelfAdvertise(backend, notifier, peer, rw, st, announced, changed, advStop, log)
			}()
			defer func() {
				close(advStop)
				<-advDone
			}()
		}
	}

	// Per-peer relay outbox: RelayAddress fans newly-learned
	// addresses into our outbox; the drain goroutine writes them on
	// the wire (gated by the per-peer known-addr bloom so we don't
	// repeat what the peer already told us). Buffer 16 means we drop
	// at most a small burst if the underlying connection is slow —
	// Bitcoin's behavior.
	//
	// Lifecycle: RegisterPeerOutbox returns a stop channel the drain
	// selects on; UnregisterPeerOutbox closes it. The outbox itself is
	// NEVER closed by either side — closing would race with concurrent
	// in-flight RelayAddress sends that snapshotted the outbox pointer
	// before we unregistered, and Go panics on send to a closed channel
	// even inside a select-with-default (default fires only on full,
	// not on closed). The drain exits on stop OR on a wire-write error.
	type outboxRegistrar interface {
		RegisterPeerOutbox(PeerKey, chan<- PeerEntry) <-chan struct{}
		UnregisterPeerOutbox(PeerKey, <-chan struct{})
	}
	var (
		outbox chan PeerEntry
		stop   <-chan struct{}
	)
	// Block-relay-only peers are excluded from the relay fan-out for
	// the same reason they get no self-advertise or GetPeers above:
	// by spec they don't participate in address gossip. Registering
	// their outbox would both leak addrbook entries to a peer that
	// committed not to gossip and waste a fan-out slot per address.
	if reg, ok := backend.(outboxRegistrar); ok && !peer.BlockRelayOnly() {
		outbox = make(chan PeerEntry, relayOutboxBuffer)
		stop = reg.RegisterPeerOutbox(peerKeyFor(peer), outbox)
	}

	relayDone := make(chan struct{})
	if outbox != nil {
		go func() {
			defer close(relayDone)
			runRelayDrain(peer, rw, st, outbox, stop, log)
		}()
	} else {
		close(relayDone)
	}

	// A peer that completes capability negotiation but never sends
	// its Hello would occupy a slot indefinitely with an undisclosed
	// relay policy (RelayTxs defaults true pre-Hello). Disconnect if
	// the Hello hasn't arrived within the deadline — Bitcoin's
	// VERSION_HANDSHAKE_TIMEOUT (60s).
	helloTimer := time.AfterFunc(getHelloDeadline(), func() {
		if !st.gotHello.Load() {
			log.Debug("parallax-disc/1: no Hello within deadline, disconnecting")
			peer.Disconnect(p2p.DiscUselessPeer)
		}
	})
	defer helloTimer.Stop()

	defer func() {
		// Release per-peer state from the backend's maps on session
		// close. AddrmanBackend exposes PeerDisconnected; other
		// backends may not, so check via type assertion.
		// UnregisterPeerOutbox closes the stop channel, which the
		// drain selects on; we then wait for the drain to exit. We do
		// NOT close the outbox — see the lifecycle comment above.
		// Passing our stop token scopes the cleanup to THIS session's
		// registration: if a re-register replaced it, the replacement
		// stays untouched.
		if reg, ok := backend.(outboxRegistrar); ok {
			reg.UnregisterPeerOutbox(peerKeyFor(peer), stop)
		}
		<-relayDone
		if cleaner, ok := backend.(interface{ PeerDisconnected(*p2p.Peer) }); ok {
			cleaner.PeerDisconnected(peer)
		}
	}()

	for {
		if err := handleOne(backend, peer, rw, st); err != nil {
			log.Debug("parallax-disc/1: session ending", "err", err)
			return err
		}
	}
}

// relayOutboxBuffer is the per-peer relay outbox depth. Sized so a
// small burst of new addresses doesn't drop while the drain
// goroutine is mid-WriteMsg, but kept tight enough that a peer with
// a slow underlying TCP connection doesn't pile up megabytes of
// queued entries. Bitcoin's outbound rate of 1.0 addr/s + burst 10
// means 16 covers ~16s of worst-case backlog before drops.
const relayOutboxBuffer = 16

// runRelayDrain is the per-peer goroutine that pulls entries from
// the relay outbox and writes them to the wire. Skips entries the
// peer already knows about (per the rolling known-addr bloom in
// st.knownAddr), which is the m_addr_known dedup half of Bitcoin's
// RelayAddress contract.
//
// Returns when stop fires (UnregisterPeerOutbox closed it on session
// teardown) or when a wire write fails. The outbox is never closed,
// so the drain cannot rely on a range-loop termination; the explicit
// stop-channel select is what unwinds the goroutine.
func runRelayDrain(peer *p2p.Peer, rw p2p.MsgReadWriter, st *state, outbox <-chan PeerEntry, stop <-chan struct{}, log logging.Logger) {
	for {
		var entry PeerEntry
		select {
		case <-stop:
			return
		case entry = <-outbox:
		}
		key := addressKey(entry.NetworkID, entry.Addr, entry.TCPPort)
		if st.knownAddr.Contains(key) {
			// Peer already knows. Bitcoin: m_addr_known dedup.
			continue
		}
		st.knownAddr.Add(key)
		if err := p2p.Send(rw, PeersMsg, Peers{Entries: []PeerEntry{entry}}); err != nil {
			log.Trace("parallax-disc/1: relay write failed; ending drain", "peer", peer.ID(), "err", err)
			return
		}
	}
}

// selfEntriesNotifier is implemented by backends that signal changes
// to their self-address set (AddrmanBackend). Backends without it get
// the session-start advertisement only.
type selfEntriesNotifier interface {
	SelfEntriesChanged() <-chan struct{}
}

// selfAdvertiseInterval is the mean (in nanoseconds) of the Poisson
// delay between unconditional re-advertisements of our address on a
// session. Atomic so tests can shorten it. Production value matches
// Bitcoin Core's AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL.
var selfAdvertiseInterval atomic.Int64

func init() { selfAdvertiseInterval.Store(int64(24 * time.Hour)) }

// SetSelfAdvertiseInterval overrides the mean re-advertisement
// interval. Exposed for tests.
func SetSelfAdvertiseInterval(d time.Duration) { selfAdvertiseInterval.Store(int64(d)) }

// runSelfAdvertise keeps an outbound session's view of our address
// current. It re-sends our self-entries when they change from what was
// last announced on the session (announced, as returned by
// sendSelfAdvertise), and unconditionally on a Poisson timer so peers
// that dropped the entry relearn it — Bitcoin Core's MaybeSendAddr
// rebroadcast. Returns when stop is closed or a write fails.
func runSelfAdvertise(backend Backend, notifier selfEntriesNotifier, peer *p2p.Peer, rw p2p.MsgReadWriter, st *state, announced [][]byte, changed <-chan struct{}, stop <-chan struct{}, log logging.Logger) {
	rebroadcast := time.NewTimer(poissonDelay(time.Duration(selfAdvertiseInterval.Load())))
	defer rebroadcast.Stop()
	for {
		force := false
		select {
		case <-stop:
			return
		case <-changed:
		case <-rebroadcast.C:
			force = true
			rebroadcast.Reset(poissonDelay(time.Duration(selfAdvertiseInterval.Load())))
		}
		// Re-arm before reading the entries, so a change landing
		// between the read and the next select still wakes us.
		changed = notifier.SelfEntriesChanged()
		last := announced
		if force {
			last = nil
		}
		var err error
		if announced, err = sendSelfAdvertise(backend, peer, rw, st, last); err != nil {
			log.Trace("parallax-disc/1: self-advertise write failed; ending loop", "peer", peer.ID(), "err", err)
			return
		}
	}
}

// sendSelfAdvertise writes a Peers message containing our current
// self-address claims to an outbound peer. Mirrors Bitcoin's
// addr(self) sequence on outbound-full-relay peers, extended
// per-network by PIP-0007 §3.3 (at most two entries: IP and onion).
// Skipped silently if no self-address is available (no quorum, no
// mapping, no override, no onion service), or if the entries equal
// last, the keys this session was last sent (nil forces a send). The
// local listen port is passed so SelfEntries can complete a port-less
// quorum winner (e.g. a --nat extip override without a port):
// advertising TCPPort 0 would fail Validate() on every receiver and
// get this node discouraged on sight.
//
// Returns the address keys now announced on the session: the entries
// sent, last when the send was skipped as unchanged, or nil when there
// is nothing to advertise.
func sendSelfAdvertise(backend Backend, peer *p2p.Peer, rw p2p.MsgReadWriter, st *state, last [][]byte) ([][]byte, error) {
	entries := backend.SelfEntries(peer, backend.LocalHello().ListenPort)
	if len(entries) == 0 {
		return nil, nil
	}
	keys := make([][]byte, len(entries))
	for i, e := range entries {
		keys[i] = addressKey(e.NetworkID, e.Addr, e.TCPPort)
	}
	if last != nil && sameKeys(keys, last) {
		return last, nil
	}
	if err := p2p.Send(rw, PeersMsg, Peers{Entries: entries}); err != nil {
		return last, err
	}
	for _, k := range keys {
		st.knownAddr.Add(k)
	}
	return keys, nil
}

func sameKeys(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// handleOne reads and dispatches one inbound message. Returns on read
// error, oversized payload, or protocol violation — the caller closes
// the session. Protocol-discipline violations (oversized payload,
// pre-Hello message, malformed decode) also flag the peer for
// discourage via MisbehavingFor so the BanMan layer's accept-time
// check can hard-reject reconnects from this source under inbound
// saturation.
func handleOne(backend Backend, peer *p2p.Peer, rw p2p.MsgReadWriter, st *state) error {
	msg, err := rw.ReadMsg()
	if err != nil {
		return err
	}
	defer msg.Discard()

	if msg.Size > MaxMessageSize {
		peer.MisbehavingFor("disc-oversized-msg")
		return fmt.Errorf("disc: message too large: %d > %d", msg.Size, MaxMessageSize)
	}

	// Enforce the protocol's first-message ordering: Hello must be
	// the first message on every session. Anything else before Hello
	// ends the session — but with a plain disconnect, NOT a
	// discourage stamp. A pre-flag-day node (protocol Length 3, no
	// HelloMsg) leads every session with GetPeers or YourAddr;
	// stamping it would ban the address across reconnects, including
	// after that node upgrades, turning a brief mixed-population
	// rollout window into a longer-lived partition. A malicious peer
	// skipping Hello costs us one accepted connection, which the
	// disconnect already answers. Once gotHello is true, the rule is
	// satisfied; the Hello message itself bypasses the gate.
	if msg.Code != HelloMsg && !st.gotHello.Load() {
		return fmt.Errorf("disc: msg 0x%02x before Hello", msg.Code)
	}

	switch msg.Code {
	case HelloMsg:
		return handleHello(backend, peer, st, msg)
	case GetPeersMsg:
		return handleGetPeers(backend, peer, rw, st, msg)
	case PeersMsg:
		return handlePeers(backend, peer, st, msg)
	case YourAddrMsg:
		return handleYourAddr(backend, peer, st, msg)
	}
	return fmt.Errorf("disc: unknown msg code 0x%02x", msg.Code)
}

func handleGetPeers(backend Backend, peer *p2p.Peer, rw p2p.MsgReadWriter, st *state, msg p2p.Msg) error {
	var req GetPeers
	if err := msg.Decode(&req); err != nil {
		// GetPeers has no payload; anything is a decode error.
		peer.MisbehavingFor("disc-getpeers-decode")
		return fmt.Errorf("disc: GetPeers decode: %w", err)
	}
	// Block-relay-only outbound peers don't participate in address
	// gossip (Bitcoin Core src/net_processing.cpp:3681). Silently
	// drop the request without responding — answering would leak
	// our addrbook sample to a peer that committed not to gossip.
	if peer.BlockRelayOnly() {
		return nil
	}
	// Only answer peers that connected to us. We chose our outbound
	// peers; a node we dialed asking for our addrbook is the shape of
	// an addrman-poisoning probe, and Bitcoin ignores getaddr on
	// outbound connections for the same cache-leak reason
	// (net_processing.cpp "Ignore getaddr message on outbound
	// connections").
	if !peer.Inbound() {
		backend.Log().Trace("parallax-disc/1: ignoring GetPeers on outbound connection", "peer", peer.ID())
		return nil
	}
	count := st.getPeersReceived.Add(1)
	if count > 1 {
		// Bitcoin parity: repeat GetPeers in the same session is a
		// silent no-op. Don't even log at info — this is expected
		// under adversarial probing.
		backend.Log().Trace("parallax-disc/1: ignoring repeat GetPeers", "peer", peer.ID())
		return nil
	}
	sample := backend.SamplePeers(peer, MaxPeersPerMessage)
	if sample == nil {
		sample = []PeerEntry{}
	}
	if len(sample) > MaxPeersPerMessage {
		sample = sample[:MaxPeersPerMessage]
	}
	// Mark these addresses as sent-to-this-peer so RelayAddress
	// doesn't re-relay them later in the session.
	for _, e := range sample {
		st.knownAddr.Add(addressKey(e.NetworkID, e.Addr, e.TCPPort))
	}
	// Apply Poisson jitter so the response doesn't arrive on a
	// predictable cadence — matches Bitcoin's PoissonNextSend
	// scheduling on address trickle. Bitcoin schedules the response
	// asynchronously, and so do we: sleeping in the read loop would
	// stall every subsequent message from this peer for up to the
	// jitter cap. The max-delay cap is a practical truncation against
	// Poisson's long tail (a natural draw can exceed 10x mean; we cap
	// at 3x to bound the worst case). A send after session teardown
	// fails with ErrShuttingDown and is dropped silently.
	if mean := getPeersResponseJitterMean(); mean > 0 {
		delay := poissonDelay(mean)
		if delay > 3*mean {
			delay = 3 * mean
		}
		go func() {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			<-timer.C
			if err := p2p.Send(rw, PeersMsg, Peers{Entries: sample}); err != nil {
				backend.Log().Trace("parallax-disc/1: delayed Peers response dropped", "peer", peer.ID(), "err", err)
			}
		}()
		return nil
	}
	return p2p.Send(rw, PeersMsg, Peers{Entries: sample})
}

// helloDeadline is the time (in nanoseconds) a session may run
// without the peer's Hello before we disconnect it. Atomic so tests
// can shorten it. Production value mirrors Bitcoin's
// VERSION_HANDSHAKE_TIMEOUT.
var helloDeadline atomic.Int64

func init() { helloDeadline.Store(int64(60 * time.Second)) }

func getHelloDeadline() time.Duration {
	return time.Duration(helloDeadline.Load())
}

// SetHelloDeadline overrides the no-Hello disconnect deadline.
// Exposed for tests.
func SetHelloDeadline(d time.Duration) { helloDeadline.Store(int64(d)) }

// peersResponseJitterMean is the mean Poisson delay (in nanoseconds)
// applied to GetPeers responses. Atomic because tests mutate it while
// handler goroutines read it. Production value matches Bitcoin's
// 2-second address-trickle cadence.
var peersResponseJitterMean atomic.Int64

func init() { peersResponseJitterMean.Store(int64(2 * time.Second)) }

func getPeersResponseJitterMean() time.Duration {
	return time.Duration(peersResponseJitterMean.Load())
}

// SetPeersResponseJitterMean overrides the Poisson mean used in the
// response delay. Exposed for tests; pass 0 to disable jitter.
func SetPeersResponseJitterMean(d time.Duration) { peersResponseJitterMean.Store(int64(d)) }

// poissonDelay returns a Poisson-distributed delay with the given mean.
// Follows Bitcoin's PoissonNextSend(mean) helper: draw U∈(0,1],
// delay = -ln(U) * mean.
func poissonDelay(mean time.Duration) time.Duration {
	u := 1.0 - mrand.Float64() // open interval (0, 1]
	return time.Duration(-math.Log(u) * float64(mean))
}

func handlePeers(backend Backend, peer *p2p.Peer, st *state, msg p2p.Msg) error {
	var pkt Peers
	if err := msg.Decode(&pkt); err != nil {
		peer.MisbehavingFor("disc-peers-decode")
		return fmt.Errorf("disc: Peers decode: %w", err)
	}
	if err := pkt.Validate(); err != nil {
		peer.MisbehavingFor("disc-peers-validate")
		return err
	}
	st.peersReceived.Add(1)

	// Block-relay-only links exist for block propagation alone: Core
	// ignores addr messages on them outright (SetupAddressRelay is
	// never set up for block-relay-only connections), so their Peers
	// messages must feed neither addrman nor onward relay. Ignore
	// without a misbehavior mark — sending one is legal, it just does
	// nothing.
	if peer.BlockRelayOnly() {
		return nil
	}

	// Unsolicited Peers messages are expected on an ongoing basis:
	// address relay (RelayAddress) pushes freshly-learned addresses to
	// its fan-out targets as single-entry Peers messages throughout a
	// session, exactly like Bitcoin Core's unsolicited ADDR pushes.
	// We therefore do NOT disconnect a peer for sending more than one
	// unsolicited Peers message. DoS is bounded the way Bitcoin Core
	// bounds it: MaxPeersPerMessage caps entries per message (oversize
	// is a disconnect via Validate above), and the per-peer ingest
	// token bucket in HandlePeers drops entries that exceed the addr
	// ingest rate. An earlier revision capped unsolicited messages at
	// one, which made honest relaying peers disconnect and discourage
	// each other and broke gossip between upgraded nodes.

	// Filter out skippable entries; disconnect on any shape violation.
	kept := pkt.Entries[:0]
	for i := range pkt.Entries {
		skip, err := pkt.Entries[i].Validate()
		if err != nil {
			peer.MisbehavingFor("disc-peerentry-shape")
			return err
		}
		if skip {
			continue
		}
		kept = append(kept, pkt.Entries[i])
	}
	// Mark only the entries that passed the ingest rate limit as
	// known to the peer (Bitcoin: AddAddressKnown after the token
	// bucket). Marking pre-limit would let a peer churn our filter
	// generations with unlimited rate-limited pushes and suppress
	// our future relay of addresses it never actually processed.
	for _, e := range backend.HandlePeers(peer, kept) {
		st.knownAddr.Add(addressKey(e.NetworkID, e.Addr, e.TCPPort))
	}
	return nil
}

func handleYourAddr(backend Backend, peer *p2p.Peer, st *state, msg p2p.Msg) error {
	var y YourAddr
	if err := msg.Decode(&y); err != nil {
		peer.MisbehavingFor("disc-youraddr-decode")
		return fmt.Errorf("disc: YourAddr decode: %w", err)
	}
	skip, err := y.Validate()
	if err != nil {
		peer.MisbehavingFor("disc-youraddr-shape")
		return err
	}
	if !st.gotYourAddr.CompareAndSwap(false, true) {
		// Bitcoin's version message is single-shot; we mirror that —
		// a second YourAddr is a protocol violation.
		peer.MisbehavingFor("disc-double-youraddr")
		return errors.New("disc: multiple YourAddr messages from one peer")
	}
	if skip {
		return nil
	}
	backend.HandleYourAddr(peer, y.NetworkID, y.Addr, y.TCPPort)
	return nil
}

// sendHello writes the local node's Hello (nonce, listen port,
// services). Idempotent via the CAS on sentHello — runs at most
// once per session, even if Run is restarted by a higher layer.
//
// On block-relay-only outbound sessions, ServiceRelayTx is cleared
// so the peer treats us as a block-relay-only neighbor on their
// side too (mirrors Bitcoin Core's PushNodeVersion which sets
// fRelay=false on m_block_relay_only outbound; src/net.cpp).
func sendHello(backend Backend, peer *p2p.Peer, rw p2p.MsgReadWriter, st *state) error {
	if !st.sentHello.CompareAndSwap(false, true) {
		return nil
	}
	h := backend.LocalHello()
	if peer.BlockRelayOnly() {
		h.Services &^= ServiceRelayTx
	}
	return p2p.Send(rw, HelloMsg, h)
}

// handleHello processes the peer's Hello on the receive side.
// Single-shot per session via gotHello — a second Hello is a
// protocol violation. Decode + Validate + delegate to backend; the
// backend runs the self-connect nonce check and stores the entry
// for later cross-dial dedup lookups.
func handleHello(backend Backend, peer *p2p.Peer, st *state, msg p2p.Msg) error {
	var h Hello
	if err := msg.Decode(&h); err != nil {
		peer.MisbehavingFor("disc-hello-decode")
		return fmt.Errorf("disc: Hello decode: %w", err)
	}
	if !st.gotHello.CompareAndSwap(false, true) {
		peer.MisbehavingFor("disc-double-hello")
		return errors.New("disc: multiple Hello messages from one peer")
	}
	if err := h.Validate(); err != nil {
		peer.MisbehavingFor("disc-hello-validate")
		return err
	}
	return backend.HandleHello(peer, h)
}

// sendYourAddr is the handshake-time "here's what I see as your source"
// message. Idempotent — repeated calls in the same session are no-ops
// thanks to the CAS on sentYourAddr.
func sendYourAddr(backend Backend, peer *p2p.Peer, rw p2p.MsgReadWriter, st *state) error {
	if !st.sentYourAddr.CompareAndSwap(false, true) {
		return nil
	}
	net, addr, port, ok := backend.ObserveTheirSource(peer)
	if !ok {
		// We can't resolve the peer's apparent source — common in
		// tests. Send an all-zero YourAddr so the peer knows we
		// support the subprotocol but has nothing actionable to
		// feed quorum. Matches the PIP-0006 "0 if unknown" rule
		// for TCPPort.
		return p2p.Send(rw, YourAddrMsg, YourAddr{})
	}
	return p2p.Send(rw, YourAddrMsg, YourAddr{
		NetworkID: net,
		Addr:      addr,
		TCPPort:   port,
	})
}

// RequestPeers sends a GetPeers on the session. Callers (the dialer in
// Phase 4) invoke this once per outbound session. Repeated calls are
// dropped silently. Backends that track solicited responses (the
// production AddrmanBackend) are notified so the response bypasses
// the ingest rate limit and its entries are excluded from onward
// relay — Bitcoin's m_getaddr_sent + getaddr bucket-credit pattern.
func RequestPeers(backend Backend, peer *p2p.Peer, st *state, rw p2p.MsgReadWriter) error {
	if !st.getPeersSent.CompareAndSwap(0, 1) {
		return nil
	}
	if noter, ok := backend.(interface{ NoteGetPeersSent(*p2p.Peer) }); ok {
		noter.NoteGetPeersSent(peer)
	}
	return p2p.Send(rw, GetPeersMsg, GetPeers{})
}
