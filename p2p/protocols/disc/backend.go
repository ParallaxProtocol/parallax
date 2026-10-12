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
	"crypto/subtle"
	"encoding/binary"
	"errors"
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
)

// IsSelfFunc reports whether addr matches the local node's own
// advertised endpoint. AddrmanBackend consults it before writing
// gossiped entries to addrman so a peer can't (accidentally or
// otherwise) cause us to ingest our own external IP as a peer.
// nil disables the check.
type IsSelfFunc func(addr *net.TCPAddr) bool

// HelloProvider returns the local node's outgoing Hello (nonce,
// listen port, services). Called once per outbound session by the
// handler before sending. nil disables Hello sending entirely (used
// by test backends that don't need the v2 greeting).
type HelloProvider func() Hello

// CrossDialHost is the minimal slice of *p2p.Server that
// AddrmanBackend.HandleHello calls to resolve cross-dial duplicates
// after a peer discloses its listen port. Defined as an interface
// (rather than taking *p2p.Server directly) so backend tests can
// drive the dedup hook with a stub.
type CrossDialHost interface {
	FindCrossDialDup(newPeer *p2p.Peer, listenPort uint16) *p2p.Peer
}

// errSelfConnect is returned from HandleHello when the remote's
// echoed nonce matches our own. The session ends; the connection is
// torn down with DiscSelf upstream.
var errSelfConnect = errors.New("disc: self-connect detected via Hello nonce")

// AddrmanBackend is the production Backend implementation. It routes
// parallax-disc/1 traffic into an addrman.AddrMan for storage and
// maintains the external-address Quorum tally. Per-peer rate-limit
// state is kept in handler.go's state struct; the Backend provides the
// buckets on demand via NewIngestBucket.
type AddrmanBackend struct {
	m               *addrman.AddrMan
	Q               *Quorum
	log             logging.Logger
	isSelf          IsSelfFunc
	helloProv       HelloProvider
	crossDialHost   CrossDialHost
	crossDialHostMu sync.RWMutex

	// reachableFn, when set, decides which BIP155 networks gossiped
	// entries may be stored for (PIP-0007: reachability is local
	// configuration — onion becomes storable once the node has an
	// onion route) and which networks self-addresses may be
	// advertised on (Core's AddLocal gate: --onlynet exclusions are
	// never advertised). nil falls back to IPv4/IPv6-only, the v2.0
	// behavior. Set once at wiring time, before any peer session
	// exists; not synchronized.
	reachableFn func(addrman.NetID) bool

	// onionSelf is our own onion service address while one is
	// established (PIP-0007 §3.3). Authoritative — the address comes
	// from ADD_ONION, not from peer votes, so it bypasses quorum the
	// way a --nat extip override does. Guarded by onionSelfMu, since
	// the torcontrol goroutine updates it while sessions read it.
	onionSelfMu  sync.Mutex
	onionSelf    addrman.NetAddr
	onionSelfSet bool

	// selfChanged is closed and replaced whenever an input to
	// SelfEntries may have changed (a YourAddr report, the NAT
	// mapping, the onion service), waking every outbound session's
	// self-advertise loop to re-check what it last announced. Guarded
	// by selfChangedMu.
	selfChangedMu sync.Mutex
	selfChanged   chan struct{}

	mu          sync.Mutex
	peerBuckets map[PeerKey]*tokenBucket
	// handshakeByID maps peer enode IDs to the human-readable
	// handshake variant ("v2" / "legacy+v2") for admin.peers output.
	// Populated on session start by TrackHandshake, purged on
	// PeerDisconnected.
	handshakeByID map[enode.ID]string
	// peerHello is the per-session record of each peer's Hello.
	// Populated on Hello receipt, purged in PeerDisconnected.
	// Looked up by Server.peerListenAddr to dedup cross-dial pairs
	// (phase 2) and by future eviction telemetry (phase 3).
	peerHello map[PeerKey]Hello

	// peerOutboxes is the per-peer relay channel registered by
	// handler.Run. RelayAddress fans newly-learned addresses into
	// the chosen subset of these. See relay.go for the picker.
	peerOutboxes map[PeerKey]*peerRelayState

	// getPeersPending marks peers we have solicited a GetPeers
	// response from that has not yet arrived. Entries received while
	// the response is pending are ingested but never relayed onward
	// (Bitcoin: the !peer.m_getaddr_sent gate in the ADDR relay
	// path). Set by NoteGetPeersSent, cleared by the first Peers
	// message smaller than a full response (Bitcoin: m_getaddr_sent
	// is cleared by any addr message under 1000 entries).
	getPeersPending map[PeerKey]bool

	// peersReply caches the GetPeers response per requestor network
	// for ~a day, so reconnecting requestors keep drawing the same
	// sample instead of a fresh one per session. Without it an
	// attacker enumerates the whole addrbook in a handful of
	// reconnects and can fingerprint the node across network
	// identities (Bitcoin: CConnman::m_addr_response_caches, ~21-27h
	// per cache entry).
	peersReply map[uint8]peersReplyCache

	// relayKey is the per-process secret used as the keyed-hash key
	// for the address-relay PRF. 32 random bytes from crypto/rand at
	// backend construction; never persisted, never rotated. Rotating
	// per-process means an observer can't predict our pick set across
	// restarts; rotating per-process-not-per-day means the daily
	// pick rotation is the work of the day-bucket input, not the key.
	relayKey [32]byte
}

// NewAddrmanBackend wraps an addrman and a quorum tally into the
// Backend interface used by Run. isSelf may be nil when the host
// has no notion of self (tests, fuzzing) — in production it should
// be Server.IsSelfEndpoint so a quorum-confirmed self-IP echoed
// back to us via gossip is dropped at the ingest boundary.
// helloProvider may be nil when the host doesn't speak the Hello
// extension (legacy tests). In production it returns the Hello the
// Server wants to advertise.
func NewAddrmanBackend(m *addrman.AddrMan, q *Quorum, log logging.Logger, isSelf IsSelfFunc, helloProvider HelloProvider) *AddrmanBackend {
	if q == nil {
		q = NewQuorum()
	}
	if log == nil {
		log = logging.Root()
	}
	b := &AddrmanBackend{
		m:               m,
		Q:               q,
		log:             log,
		isSelf:          isSelf,
		helloProv:       helloProvider,
		peerBuckets:     make(map[PeerKey]*tokenBucket),
		handshakeByID:   make(map[enode.ID]string),
		peerHello:       make(map[PeerKey]Hello),
		peerOutboxes:    make(map[PeerKey]*peerRelayState),
		getPeersPending: make(map[PeerKey]bool),
		peersReply:      make(map[uint8]peersReplyCache),
		selfChanged:     make(chan struct{}),
	}
	if _, err := rand.Read(b.relayKey[:]); err != nil {
		// crypto/rand failures are catastrophic (see crypto.io's
		// unfailing-by-design guarantee on linux/getrandom). Panic
		// rather than ship with a zero-key relay PRF.
		panic("disc: cannot read randomness for relayKey: " + err.Error())
	}
	return b
}

// SetReachableFunc installs the per-network reachability predicate
// consulted by the ingest storage gate (typically
// p2p.Server.NetworkReachable). Must be called before the first peer
// session — it is read unsynchronized from ingest goroutines.
func (b *AddrmanBackend) SetReachableFunc(f func(addrman.NetID) bool) {
	b.reachableFn = f
}

// entryReachable reports whether entries on the given wire network may
// be stored, and whether self-addresses on it may be advertised
// (Core's AddLocal reachability gate). Falls back to IPv4/IPv6-only
// when no predicate is wired.
func (b *AddrmanBackend) entryReachable(wireNet uint8) bool {
	if b.reachableFn != nil {
		return b.reachableFn(addrmanNetID(wireNet))
	}
	return wireNet == NetIPv4 || wireNet == NetIPv6
}

// TrackHandshake records the handshake variant used for this session.
// Called by handler.Run once per peer on session start. Used by
// PeerInfo to answer admin.peers' "is this peer v2-only or
// legacy+v2".
func (b *AddrmanBackend) TrackHandshake(peer *p2p.Peer, usingV2 bool) {
	variant := "legacy+v2"
	if usingV2 {
		variant = "v2"
	}
	b.mu.Lock()
	b.handshakeByID[peer.ID()] = variant
	b.mu.Unlock()
}

// PeerHandshake returns the handshake variant previously recorded for
// id, or the empty string if the peer is not currently tracked.
func (b *AddrmanBackend) PeerHandshake(id enode.ID) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.handshakeByID[id]
}

func (b *AddrmanBackend) Log() logging.Logger { return b.log }

// ObserveTheirSource extracts the remote TCP source so the peer's
// YourAddr report can feed quorum on their side. Falls back to
// (0, nil, 0, false) for peers without a resolvable RemoteAddr (test
// pipes, tunneled transports) — the handler sends an all-zero YourAddr
// in that case and the peer ignores it during quorum.
func (b *AddrmanBackend) ObserveTheirSource(peer *p2p.Peer) (uint8, []byte, uint16, bool) {
	// A proxied conn's RemoteAddr is the proxy and an inbound onion
	// stream's is the local Tor daemon — a YourAddr built from either
	// would tell the peer "you are my SOCKS5 endpoint" or "you are
	// 127.0.0.1", which a peer without the same guard would feed into
	// its own self-address quorum. Send the all-zero YourAddr instead
	// (PIP-0007), exactly as HandleYourAddr refuses their reports.
	if peer.ProxiedConn() || peer.OnionPeer() {
		return 0, nil, 0, false
	}
	ra := peer.RemoteAddr()
	if ra == nil {
		return 0, nil, 0, false
	}
	tcp, ok := ra.(*net.TCPAddr)
	if !ok {
		return 0, nil, 0, false
	}
	if v4 := tcp.IP.To4(); v4 != nil {
		return NetIPv4, v4, uint16(tcp.Port), true
	}
	return NetIPv6, tcp.IP.To16(), uint16(tcp.Port), true
}

// HandleYourAddr feeds a peer's claim about our external address into
// the quorum. The peer's network group for the distinct-group test is
// derived from the peer's own RemoteAddr, NOT from the reported addr —
// the attack being mitigated is one group sybil-voting for a single
// address.
func (b *AddrmanBackend) HandleYourAddr(peer *p2p.Peer, net uint8, addr []byte, port uint16) {
	if net == 0 || len(addr) == 0 {
		// Peer couldn't resolve our address (common behind NAT, or
		// for test pipes). Nothing to feed quorum.
		return
	}
	// Onion peers observe the Tor daemon's loopback stream, not our
	// address — their reports would poison self-discovery (PIP-0007
	// §3.2). Same for anything we dialed through a proxy: that
	// peer's view of us is the proxy's exit.
	if peer.OnionPeer() || peer.ProxiedConn() {
		return
	}
	peerNet, peerAddr, ok := peerNetworkGroup(peer)
	if !ok {
		return
	}
	group := computeGroup(peerNet, peerAddr)
	if len(group) == 0 {
		return
	}
	// On sessions we dialed, the peer observed our ephemeral source
	// port, not our listen port. Zero it so the report still counts
	// toward the address tally (the quorum key ignores ports) without
	// polluting the port ranking; inbound sessions dialed the port we
	// are actually reachable on, so their observation is kept.
	if !peer.Inbound() {
		port = 0
	}
	b.Q.Report(peerKeyFor(peer), net, addr, port, group)
	b.notifySelfChanged()
}

// SelfEntriesChanged returns a channel that is closed the next time an
// input to SelfEntries may change. Callers fetch a fresh channel after
// each wake-up, and fetch it before reading SelfEntries so a change
// landing in between is not missed.
func (b *AddrmanBackend) SelfEntriesChanged() <-chan struct{} {
	b.selfChangedMu.Lock()
	defer b.selfChangedMu.Unlock()
	return b.selfChanged
}

func (b *AddrmanBackend) notifySelfChanged() {
	b.selfChangedMu.Lock()
	close(b.selfChanged)
	b.selfChanged = make(chan struct{})
	b.selfChangedMu.Unlock()
}

// SetNATMapping records the external endpoint our NAT gateway
// (UPnP/NAT-PMP) forwards to the listener, or clears it when addr is
// the zero value. Addresses that aren't publicly routable — a gateway
// that is itself behind NAT or CGNAT reports its private WAN address
// — are treated as cleared: advertising them would only hand peers an
// endpoint they can't reach.
func (b *AddrmanBackend) SetNATMapping(addr addrman.NetAddr) {
	if (addr.Network == addrman.NetIPv4 || addr.Network == addrman.NetIPv6) && addr.Valid() {
		b.Q.SetMapped(uint8(addr.Network), addr.Bytes(), addr.Port)
	} else {
		b.Q.SetMapped(0, nil, 0)
	}
	b.notifySelfChanged()
}

// ancientLastSeen is the garbage-timestamp sentinel threshold: any
// claimed LastSeen at or below it (about March 1973 in Unix seconds)
// is treated as unset. Mirrors Bitcoin's 100000000-second cutoff in
// the ADDR ingest path (src/net_processing.cpp).
const ancientLastSeen = 100000000

// maxRelayBatch is the largest Peers message whose entries are
// eligible for onward relay. Genuine relay pushes arrive as 1-entry
// messages; anything larger is bulk transfer, not gossip. Mirrors
// Bitcoin's vAddr.size() <= 10 gate in the ADDR relay path.
const maxRelayBatch = 10

// NoteGetPeersSent records that we solicited a GetPeers response from
// peer. Entries arriving while the response is pending are ingested
// but never relayed onward; the mark is cleared by the first Peers
// message smaller than a full response. Called by RequestPeers.
func (b *AddrmanBackend) NoteGetPeersSent(peer *p2p.Peer) {
	b.mu.Lock()
	b.getPeersPending[peerKeyFor(peer)] = true
	b.mu.Unlock()
	// Accept a full response on top of the steady-state gossip rate.
	// Without this credit a solicited 1000-entry response would be
	// ~99% rate-limit-dropped and bootstrap would lean entirely on
	// seed nodes (Bitcoin: m_addr_token_bucket += MAX_ADDR_TO_SEND
	// when sending getaddr).
	b.ingestBucketFor(peer).Credit(MaxPeersPerMessage)
}

// HandlePeers ingests a batch of gossiped PeerEntry records into
// addrman with source=tcp_gossip. The 2-hour gossip penalty on
// LastSeen (PIP-0006 Phase 2 rule: "Subtract a 2-hour penalty when the
// source is gossip rather than direct observation") is applied here.
// Rate limiting is enforced per-peer via the ingest bucket.
//
// Returns the entries that made it past the token bucket, so the
// handler can mark exactly those in the peer's known-address bloom —
// Core calls AddAddressKnown after the rate limit, and marking
// rate-limited entries would let a peer suppress our future relay of
// addresses it never actually processed.
func (b *AddrmanBackend) HandlePeers(peer *p2p.Peer, entries []PeerEntry) []PeerEntry {
	if b.m == nil {
		return nil
	}
	// Relay eligibility is per-message (Bitcoin's ADDR relay gates,
	// net_processing.cpp): entries from a solicited GetPeers response
	// are never re-gossiped, and only small unsolicited batches (the
	// shape a genuine relay push has — RelayAddress sends 1-entry
	// messages) qualify. Without the solicited-response gate, every
	// 1000-entry GetPeers response would fan out again as up to 2000
	// relayed messages. Any batch smaller than a full response also
	// completes a pending solicited exchange — including an empty one
	// from a fresh node with a bare addrbook — mirroring Core's
	// clearing of m_getaddr_sent on any sub-1000-entry addr message.
	// Leaving the flag set would misclassify everything that peer
	// relays for the rest of the session as solicited (never
	// re-gossiped).
	key := peerKeyFor(peer)
	b.mu.Lock()
	solicited := b.getPeersPending[key]
	if len(entries) < MaxPeersPerMessage {
		delete(b.getPeersPending, key)
	}
	b.mu.Unlock()
	if len(entries) == 0 {
		return nil
	}
	bucket := b.ingestBucketFor(peer)
	sourceNet, sourceAddr, ok := peerNetworkGroup(peer)
	if !ok {
		// Can't bucket the source — addrman needs a CNetAddr for
		// the source-group portion of newBucket. Drop the whole
		// batch; per-peer loss is acceptable.
		return nil
	}
	source, err := addrman.NewNetAddr(addrmanNetID(sourceNet), sourceAddr, 0)
	if err != nil {
		return nil
	}
	mayRelay := !solicited && len(entries) <= maxRelayBatch

	// Shuffle before the rate-limited loop (Core: std::shuffle before
	// processing) so token-bucket drops aren't a deterministic prefix
	// of the sender's ordering — otherwise the tail of every large
	// honest batch is systematically lost.
	mrand.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })

	now := time.Now()
	rateLimited := 0
	accepted := make([]PeerEntry, 0, len(entries))
	for _, e := range entries {
		if !bucket.Take(now) {
			// Rate-limit drop — no disconnect, no misbehavior mark
			// (Bitcoin parity), but counted for diagnostics like
			// Core's m_addr_rate_limited.
			rateLimited++
			continue
		}
		accepted = append(accepted, e)
		net := addrmanNetID(e.NetworkID)
		naddr, err := addrman.NewNetAddr(net, e.Addr, e.TCPPort)
		if err != nil {
			continue
		}
		// Drop any entry that names our own advertised endpoint.
		// Once our quorum-confirmed external IP propagates to peers
		// (we self-advertise it on every outbound session) it can
		// come back to us via gossip; without this filter we'd
		// write a self-loop into addrman that survives across
		// restarts via addrbook.rlp.
		if b.isSelfEntry(e) {
			continue
		}
		// Sanitize LastSeen the way Bitcoin ingests addr timestamps
		// (net_processing.cpp ADDR handling): an ancient sentinel
		// (pre-2001) or a claim more than 10 minutes in the future is
		// replaced with now-5days; every other claim is preserved
		// as-is. Preserving old claims is what lets dead addresses age
		// out — addrman's IsTerrible drops entries past the 30-day
		// horizon, which an ingest-time floor would forever reset,
		// keeping zombie addresses in circulation hop-to-hop.
		claimed := time.Unix(int64(e.LastSeen), 0)
		if e.LastSeen <= ancientLastSeen || claimed.After(now.Add(10*time.Minute)) {
			claimed = now.Add(-5 * 24 * time.Hour)
		}
		e.LastSeen = uint64(claimed.Unix())
		// Store only addresses on networks this node can dial.
		// Core's ADDR handling ("Do not store addresses outside our
		// network", net_processing.cpp) keeps the rest out of addrman
		// — otherwise an attacker stuffs the addrbook and GetPeers
		// response slots with undialable entries — while still
		// relaying them (below, at the reduced unreachable fanout) so
		// they propagate toward nodes that serve those networks.
		// Which networks are dialable is local configuration
		// (PIP-0007): IPv4/IPv6 always, onion iff a Tor route exists.
		reachable := b.entryReachable(e.NetworkID)
		if reachable {
			// Plus the 2-hour gossip penalty applied by the Add path.
			b.m.AddOne(naddr, e.KeyType, e.NodeID, claimed, source, addrman.SourceTCPGossip, 2*time.Hour)
		}
		// Bitcoin's per-entry relay gates: only a fresh claim (under
		// 10 minutes old) on a routable address is gossiped onward,
		// and only from a message that passed the per-message gates
		// above. Relay is independent of whether addrman stored the
		// entry — an already-known address still propagates (Core
		// relays before AddrMan::Add); the per-destination knownAddr
		// bloom in the relay drain is what suppresses repeats to the
		// same peer, exactly like Core's m_addr_known. Freshness
		// expiring 10 minutes after the original claim bounds any
		// relay loop.
		if mayRelay && naddr.Valid() && claimed.After(now.Add(-10*time.Minute)) {
			b.RelayAddress(peer, e, reachable)
		}
	}
	if rateLimited > 0 {
		b.log.Debug("parallax-disc/1: rate-limited address ingest",
			"peer", peer.ID(), "dropped", rateLimited, "received", len(entries))
	}
	return accepted
}

// maxPctPeersToSend caps a GetPeers response at this percentage of
// the addrbook, whichever of it and MaxPeersPerMessage is smaller.
// Mirrors Bitcoin's MAX_PCT_ADDR_TO_SEND=23: one response never
// discloses more than about a quarter of the book.
const maxPctPeersToSend = 23

// peersReplyCache is one cached GetPeers response (see peersReply).
type peersReplyCache struct {
	entries []PeerEntry
	expires time.Time
}

// SamplePeers returns up to max entries for a GetPeers response.
// Draws from addrman.GetAddr with filtered=true so IsTerrible entries
// are dropped, capped at maxPctPeersToSend percent of the book, and
// caches the response per requestor network for ~a day so repeated
// requests can't enumerate the addrbook. Maps each entry back to the
// PeerEntry wire format with the stored KeyType/NodeID.
func (b *AddrmanBackend) SamplePeers(peer *p2p.Peer, max int) []PeerEntry {
	if b.m == nil || max <= 0 {
		return nil
	}
	// Cache key: the requestor's network. Coarser than Bitcoin's
	// (network, local socket) key, but Parallax nodes run a single
	// listener, so the network alone carries the same intent — all
	// same-network requestors share one long-lived sample. Callers
	// must treat the returned slice as read-only.
	netID, _, ok := peerNetworkGroup(peer)
	if !ok {
		netID = 0
	}
	now := time.Now()
	b.mu.Lock()
	if c, hit := b.peersReply[netID]; hit && now.Before(c.expires) {
		b.mu.Unlock()
		return c.entries
	}
	b.mu.Unlock()

	// Ask addrman for up to max*2 entries so we have slack after
	// filtering out entries that can't be serialized on the wire.
	sample := b.m.GetAddr(max*2, maxPctPeersToSend, nil, true)
	out := make([]PeerEntry, 0, len(sample))
	for _, addr := range sample {
		if len(out) >= max {
			break
		}
		info := b.m.Lookup(addr)
		if info == nil {
			continue
		}
		// KeyType=0x00 entries gossip with empty NodeID; KeyType=0x01
		// carry 64-byte pubkey.
		out = append(out, PeerEntry{
			NetworkID: uint8(addr.Network),
			Addr:      addr.Bytes(),
			TCPPort:   addr.Port,
			KeyType:   info.KeyType,
			NodeID:    append([]byte(nil), info.NodeID...),
			LastSeen:  uint64(info.LastSeen.Unix()),
		})
	}
	// Bitcoin's cache lifetime: 21h plus up to 6h of jitter, chosen
	// so scraped data is mostly stale by the time a full scrape could
	// complete, while honest requestors still get a usably fresh
	// sample (churn is bounded by the 30-day IsTerrible horizon).
	b.mu.Lock()
	b.peersReply[netID] = peersReplyCache{
		entries: out,
		expires: now.Add(21*time.Hour + time.Duration(mrand.Int64N(int64(6*time.Hour)))),
	}
	b.mu.Unlock()
	return out
}

// SelfEntry returns the PeerEntry we should advertise to newly-connected
// outbound peers (Bitcoin's addr(self) + getaddr sequence). Empty if no
// self-address has quorum, an override or a NAT mapping, or if --onlynet excludes the
// winner's network — Core's AddLocal refuses addresses on unreachable
// networks (net.cpp), so an --onlynet=onion node never advertises its
// IP. Called by handler.Run on outbound sessions.
func (b *AddrmanBackend) SelfEntry(listenPort uint16) (PeerEntry, bool) {
	net, addr, port, ok := b.Q.Winner()
	if !ok || !b.entryReachable(net) {
		return PeerEntry{}, false
	}
	// If the quorum returned a port of 0 (observation without a port
	// hint), substitute our listen port.
	if port == 0 {
		port = listenPort
	}
	// Still no port — a port-less winner on a non-listening node.
	// A PeerEntry with TCPPort 0 fails Validate() on every receiver
	// and flags us as misbehaving, so advertise nothing.
	if port == 0 {
		return PeerEntry{}, false
	}
	return PeerEntry{
		NetworkID: net,
		Addr:      addr,
		TCPPort:   port,
		KeyType:   KeyTypeNone, // v2.0-native self
		NodeID:    nil,
		LastSeen:  uint64(time.Now().Unix()),
	}, true
}

// SetOnionService records our established onion service address for
// self-advertisement. Called by the node wiring when torcontrol's
// ADD_ONION succeeds.
func (b *AddrmanBackend) SetOnionService(addr addrman.NetAddr) {
	b.onionSelfMu.Lock()
	b.onionSelf, b.onionSelfSet = addr, addr.Network == addrman.NetTorV3
	b.onionSelfMu.Unlock()
	b.notifySelfChanged()
}

// ClearOnionService stops advertising the onion address — the control
// connection dropped and Tor discarded the service with it.
func (b *AddrmanBackend) ClearOnionService() {
	b.onionSelfMu.Lock()
	b.onionSelf, b.onionSelfSet = addrman.NetAddr{}, false
	b.onionSelfMu.Unlock()
	b.notifySelfChanged()
}

// onionSelfEntry renders the onion service as a PeerEntry, ok=false
// when no service is established or when --onlynet excludes onion —
// Core's AddLocal refuses addresses on unreachable networks (net.cpp),
// so under -onlynet=ipv4 the onion service runs but is never
// advertised. isSelfEntry stays ungated: copies gossiped before the
// restriction still name this node and must be dropped at ingest.
func (b *AddrmanBackend) onionSelfEntry() (PeerEntry, bool) {
	if !b.entryReachable(NetTorV3) {
		return PeerEntry{}, false
	}
	b.onionSelfMu.Lock()
	addr, ok := b.onionSelf, b.onionSelfSet
	b.onionSelfMu.Unlock()
	if !ok {
		return PeerEntry{}, false
	}
	return PeerEntry{
		NetworkID: NetTorV3,
		Addr:      append([]byte(nil), addr.Bytes()...),
		TCPPort:   addr.Port,
		KeyType:   KeyTypeNone,
		NodeID:    nil,
		LastSeen:  uint64(time.Now().Unix()),
	}, true
}

// SelfEntries implements the per-network self-advertisement rule
// (PIP-0007 §3.3, Core's GetLocalAddrForPeer): onion peers are told
// only the onion address — advertising the IP over a Tor circuit
// would deanonymize an onion-only operator — while clearnet peers get
// the IP claim plus the onion address, which propagates through
// clearnet gossip at the reduced unreachable fanout on nodes without
// a Tor route.
func (b *AddrmanBackend) SelfEntries(peer *p2p.Peer, listenPort uint16) []PeerEntry {
	onion, hasOnion := b.onionSelfEntry()
	if peer != nil && peer.OnionPeer() {
		if !hasOnion {
			return nil
		}
		return []PeerEntry{onion}
	}
	var out []PeerEntry
	if ip, ok := b.SelfEntry(listenPort); ok {
		out = append(out, ip)
	}
	if hasOnion {
		out = append(out, onion)
	}
	return out
}

// isSelfEntry reports whether a gossiped entry names this node's own
// advertised endpoint, on any network. Without the onion arm our own
// onion address — which we advertise on every outbound clearnet
// session — comes back through gossip, passes the reachability gate
// on any Tor-routed node and is stored in our own addrbook, a
// self-loop that survives restarts in addrbook.rlp and burns
// candidate-iteration budget until the dial guard rejects it.
func (b *AddrmanBackend) isSelfEntry(e PeerEntry) bool {
	if e.NetworkID == NetTorV3 {
		b.onionSelfMu.Lock()
		self, ok := b.onionSelf, b.onionSelfSet
		b.onionSelfMu.Unlock()
		// Port-insensitive, like the dial-side onion self check: our
		// service answers on whatever port a peer gossips for it.
		return ok && len(e.Addr) == 32 && string(e.Addr) == string(self.Bytes())
	}
	if b.isSelf == nil {
		return false
	}
	tcp, ok := selfTCPFromEntry(e)
	return ok && b.isSelf(tcp)
}

// ingestBucketFor returns (creating if needed) the per-peer token
// bucket for parallax-disc/1 address ingest.
func (b *AddrmanBackend) ingestBucketFor(peer *p2p.Peer) *tokenBucket {
	key := peerKeyFor(peer)
	b.mu.Lock()
	defer b.mu.Unlock()
	bk, ok := b.peerBuckets[key]
	if ok {
		return bk
	}
	bk = newTokenBucket(addrRatePerSecond, addrTokenBucketCap, addrTokenBucketInit)
	b.peerBuckets[key] = bk
	return bk
}

// PeerDisconnected is a hook Server invokes on session close. Cleans
// per-peer state from the backend's maps so they don't leak.
func (b *AddrmanBackend) PeerDisconnected(peer *p2p.Peer) {
	key := peerKeyFor(peer)
	b.mu.Lock()
	delete(b.peerBuckets, key)
	delete(b.handshakeByID, peer.ID())
	delete(b.peerHello, key)
	delete(b.getPeersPending, key)
	b.mu.Unlock()
	b.Q.Disconnect(key)
}

// connectedPeerKeys snapshots the set of peers currently tracked by the
// backend (those that have completed Hello and not yet disconnected).
// Used by RunQuorumRefreshLoop to reconcile Quorum's report tally
// against the actually-connected set — the "drop reports for peers no
// longer connected" half of PIP-0006 §Phase 4's quorum re-eval.
//
// Passed to Quorum.Refresh as a function (not a pre-taken value) so the
// snapshot is captured under the quorum's report lock, atomically with
// respect to a peer completing Hello+YourAddr — see Refresh's contract.
func (b *AddrmanBackend) connectedPeerKeys() map[PeerKey]struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[PeerKey]struct{}, len(b.peerHello))
	for k := range b.peerHello {
		out[k] = struct{}{}
	}
	return out
}

// RunQuorumRefreshLoop is the 1h periodic backstop that recomputes
// Quorum's tally — runs evictStaleLocked plus a connected-peer-set
// reconciliation. Returns when stop fires; caller is responsible for
// goroutine lifetime. Safe to call exactly once per backend.
//
// In production Server.Start spawns this as part of the parallax-disc/1
// wiring. Tests invoke it directly with a synthetic stop chan, or
// exercise Quorum.Refresh in isolation.
func (b *AddrmanBackend) RunQuorumRefreshLoop(stop <-chan struct{}) {
	b.RunQuorumRefreshLoopWithInterval(stop, QuorumRefreshInterval)
}

// RunQuorumRefreshLoopWithInterval is the test-facing variant of
// RunQuorumRefreshLoop. Internal to the package.
func (b *AddrmanBackend) RunQuorumRefreshLoopWithInterval(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			// Pass the snapshot function, not a pre-taken snapshot, so
			// Refresh evaluates it under the quorum lock — a peer that
			// finishes its handshake mid-tick can't be seen as "in the
			// tally but absent from the snapshot" and lose its vote.
			dropped := b.Q.Refresh(now, b.connectedPeerKeys)
			if dropped > 0 {
				b.log.Debug("parallax-disc/1: quorum refresh dropped reports from disconnected peers",
					"dropped", dropped)
			}
		}
	}
}

// LocalHello returns the local node's outgoing Hello (the value sent
// on every outbound parallax-disc/1 session). Returns the zero
// Hello with ProtoVersion=HelloMinProtoVersion if no provider is
// configured — keeps tests usable without a full Server context.
func (b *AddrmanBackend) LocalHello() Hello {
	if b.helloProv == nil {
		return Hello{ProtoVersion: HelloMinProtoVersion}
	}
	return b.helloProv()
}

// HandleHello stores the peer's claimed Hello and runs the
// self-connect check. Returns errSelfConnect when the peer's nonce
// matches our own — the handler propagates this to end the session
// with DiscSelf upstream.
//
// After storing the Hello (and only when a CrossDialHost is wired
// — production: the Server; tests: a stub), runs the cross-dial
// dedup hook: if any other peer's effective listen-addr matches
// the IP+listen-port the new peer just disclosed, those two
// connections are duplicates of the same logical neighbor.
// Tie-break (matches Bitcoin Core's preference for outbound):
//   - if exactly one of the two is inbound, drop it;
//   - same-direction tie: keep the older (smaller p.created).
//
// Disconnection is asynchronous (Disconnect just closes the peer);
// Server's run loop processes delpeer in the next iteration.
func (b *AddrmanBackend) HandleHello(peer *p2p.Peer, h Hello) error {
	if b.helloProv != nil {
		local := b.helloProv()
		var hbuf, lbuf [8]byte
		binary.BigEndian.PutUint64(hbuf[:], h.Nonce)
		binary.BigEndian.PutUint64(lbuf[:], local.Nonce)
		if subtle.ConstantTimeCompare(hbuf[:], lbuf[:]) == 1 {
			return errSelfConnect
		}
	}
	// Record the peer's disclosed tx-relay intent on the Peer object
	// so the eviction algorithm and the tx-broadcast path can see it.
	// A peer that connected to us block-relay-only clears
	// ServiceRelayTx in its Hello (sendHello), and we must not push
	// transactions to it nor mis-protect it in the tx-relay eviction
	// round. Bitcoin Core tracks this as CNode::m_relays_txs, set
	// from the version message's fRelay bit.
	peer.SetRelayTxs(h.Services&ServiceRelayTx != 0)

	key := peerKeyFor(peer)
	b.mu.Lock()
	b.peerHello[key] = h
	b.mu.Unlock()

	// Sessions are never correlated by Hello nonce. The nonce is
	// per-node-lifetime and unauthenticated, so any peer of a peer
	// learns it and could replay it to make us drop a genuine
	// session — an eclipse assist. Mutual connections (we dial a
	// peer's address while it dials ours) therefore persist as two
	// sessions, exactly as they do in Bitcoin Core, which cannot
	// detect them at all. The self-connect check above still uses
	// the nonce, where a match can only ever cost the attacker their
	// own session.

	b.crossDialHostMu.RLock()
	host := b.crossDialHost
	b.crossDialHostMu.RUnlock()
	if host == nil || h.ListenPort == 0 {
		return nil
	}
	dup := host.FindCrossDialDup(peer, h.ListenPort)
	if dup == nil {
		return nil
	}
	loser := selectCrossDialLoser(dup, peer)
	b.log.Debug("parallax-disc/1: cross-dial dup detected, dropping loser",
		"loser", loser.RemoteAddr(), "loserInbound", loser.Inbound(),
		"keep", winnerOf(dup, peer, loser).RemoteAddr())
	loser.Disconnect(p2p.DiscAlreadyConnected)
	return nil
}

// selectCrossDialLoser picks which of (existing, incoming) to drop
// when both represent the same logical neighbor. Prefers outbound
// retention; on same-direction ties keeps the older connection.
// Exported only to the test scope via the test file in this
// package (lowercase keeps the surface narrow).
func selectCrossDialLoser(existing, incoming *p2p.Peer) *p2p.Peer {
	existingIn := existing.Inbound()
	incomingIn := incoming.Inbound()
	if existingIn != incomingIn {
		// Drop whichever IS inbound.
		if existingIn {
			return existing
		}
		return incoming
	}
	// Same direction. Drop the younger. p.Created() is mclock.AbsTime
	// (monotonic, smaller=older).
	if existing.Created() < incoming.Created() {
		return incoming
	}
	return existing
}

// winnerOf returns the survivor of the (a,b) pair given which one
// was selected as the loser. Used only for log formatting.
func winnerOf(a, b, loser *p2p.Peer) *p2p.Peer {
	if loser == a {
		return b
	}
	return a
}

// PeerHello returns the Hello previously recorded for id, or
// (zero, false) if no Hello has been received on the peer's session.
// Used by Server.peerListenAddr (phase 2) to project an inbound
// peer's effective listen endpoint for cross-dial dedup.
func (b *AddrmanBackend) PeerHello(key PeerKey) (Hello, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h, ok := b.peerHello[key]
	return h, ok
}

// PeerListenPort returns the listen port the peer disclosed in its
// Hello, or (0, false) if no Hello has been received yet (or the
// peer disclosed port=0, "unknown"). Implements
// p2p.PeerListenPortLookup so the Server can dedup inbound peers in
// alreadyConnectedTo and friends.
func (b *AddrmanBackend) PeerListenPort(id enode.ID) (uint16, bool) {
	h, ok := b.PeerHello(PeerKey(id.String()))
	if !ok || h.ListenPort == 0 {
		return 0, false
	}
	return h.ListenPort, true
}

// SetCrossDialHost wires the Server (or a test stub) for the
// cross-dial dedup path that runs in HandleHello. Called once at
// node setup; nil disables the dedup (Hello is still stored, but
// the hook doesn't fire).
func (b *AddrmanBackend) SetCrossDialHost(h CrossDialHost) {
	b.crossDialHostMu.Lock()
	b.crossDialHost = h
	b.crossDialHostMu.Unlock()
}

// peerKeyFor returns the stable PeerKey for the session lifetime: the
// enode.ID hex. For v2 handshakes the ID derives from ephemeral
// session keys, so it's unique per connection; for legacy peers it's
// the persistent node ID, stable across that peer's reconnects (only
// one live session per legacy ID exists at a time, so per-session
// state keyed on it cannot collide).
func peerKeyFor(peer *p2p.Peer) PeerKey {
	id := peer.ID()
	return PeerKey(id.String())
}

// peerNetworkGroup returns the peer's (BIP155 net, raw addr) pair from
// their RemoteAddr. Used by the quorum to tag reports with the
// reporter's network group.
func peerNetworkGroup(peer *p2p.Peer) (uint8, []byte, bool) {
	// The dial target outranks the socket address: under a proxy
	// RemoteAddr is the proxy and for an inbound onion peer it is the
	// local Tor daemon, so every such peer would share one source
	// group and their gossip would collapse into the same few addrman
	// new-table buckets — losing exactly the source diversity the
	// bucketing exists for.
	if t, ok := peer.DialTarget(); ok {
		switch t.Network {
		case addrman.NetIPv4:
			return NetIPv4, append([]byte(nil), t.Bytes()...), true
		case addrman.NetIPv6:
			return NetIPv6, append([]byte(nil), t.Bytes()...), true
		case addrman.NetTorV3:
			return NetTorV3, append([]byte(nil), t.Bytes()...), true
		}
	}
	ra := peer.RemoteAddr()
	if ra == nil {
		return 0, nil, false
	}
	tcp, ok := ra.(*net.TCPAddr)
	if !ok {
		return 0, nil, false
	}
	if v4 := tcp.IP.To4(); v4 != nil {
		return NetIPv4, v4, true
	}
	if v6 := tcp.IP.To16(); v6 != nil {
		return NetIPv6, v6, true
	}
	return 0, nil, false
}

// computeGroup derives the canonical network-group bytes for a peer's
// address. Mirrors addrman's group() — /16 for IPv4, /32 for IPv6.
// Kept local so this package doesn't import addrman's internal helper.
func computeGroup(net uint8, addr []byte) []byte {
	switch net {
	case NetTorV3:
		// Top 4 bits of the service key — addrman's rule for onion.
		if len(addr) != 32 {
			return nil
		}
		return []byte{NetTorV3, addr[0] | 0x0F}
	case NetIPv4:
		if len(addr) != 4 {
			return nil
		}
		return []byte{net, addr[0], addr[1]}
	case NetIPv6:
		if len(addr) != 16 {
			return nil
		}
		return []byte{net, addr[0], addr[1], addr[2], addr[3]}
	}
	return nil
}

// addrmanNetID maps the disc-package NetID to addrman's NetID. They're
// structurally identical (same BIP155 codes) but Go's type system
// requires the conversion.
func addrmanNetID(n uint8) addrman.NetID { return addrman.NetID(n) }

// selfTCPFromEntry projects a PeerEntry onto the *net.TCPAddr shape
// IsSelfFunc consumes. Returns ok=false for non-IPv4/IPv6 entries —
// those can never be the local node's listen endpoint.
func selfTCPFromEntry(e PeerEntry) (*net.TCPAddr, bool) {
	switch e.NetworkID {
	case NetIPv4:
		if len(e.Addr) != 4 {
			return nil, false
		}
		return &net.TCPAddr{IP: net.IPv4(e.Addr[0], e.Addr[1], e.Addr[2], e.Addr[3]), Port: int(e.TCPPort)}, true
	case NetIPv6:
		if len(e.Addr) != 16 {
			return nil, false
		}
		return &net.TCPAddr{IP: append(net.IP(nil), e.Addr...), Port: int(e.TCPPort)}, true
	}
	return nil, false
}
