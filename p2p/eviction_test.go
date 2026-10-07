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
	"encoding/json"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/internal/testlog"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enr"
	"github.com/ParallaxProtocol/parallax/v2/util/mclock"
)

// makeEvictionPeer constructs a synthetic *Peer suitable for the
// eviction test surface: inbound (default), addressable for network
// group computation, with caller-controlled telemetry. Use opts to
// flip flags (trusted, static, outbound) and set telemetry values.
type evictionOpts struct {
	id         enode.ID
	ip         net.IP
	createdAge time.Duration // age relative to now; 0 = "just connected"
	minPing    int64         // ns
	lastBlock  int64         // mclock.AbsTime ns
	lastTx     int64         // mclock.AbsTime ns
	relayTxs   bool
	inbound    bool
	trusted    bool
	static     bool
}

func makeEvictionPeer(t *testing.T, opts evictionOpts) *Peer {
	t.Helper()
	if opts.id == (enode.ID{}) {
		opts.id = randomID()
	}
	if opts.ip == nil {
		opts.ip = net.IPv4(1, 2, 3, 4)
	}
	pipe, _ := net.Pipe()
	fake := &fakeAddrConn{Conn: pipe, remoteAddr: &net.TCPAddr{IP: opts.ip, Port: 32110}}
	t.Cleanup(func() { _ = fake.Close() })
	p := NewPeerForTest(opts.id, "fake", nil, fake)
	p.computeAndCacheNetworkGroup()

	if opts.inbound {
		p.rw.set(inboundConn, true)
	}
	if opts.trusted {
		p.rw.set(trustedConn, true)
	}
	if opts.static {
		p.rw.set(staticDialedConn, true)
	}
	// Override created so age-sensitive rounds are testable. We set
	// the field directly because there's no public mutator.
	p.created = mclock.Now() - mclock.AbsTime(opts.createdAge)

	p.minPing.Store(opts.minPing)
	p.lastBlockRx.Store(opts.lastBlock)
	p.lastTxRx.Store(opts.lastTx)
	p.relayTxs.Store(opts.relayTxs)
	return p
}

// setTestLocalNode attaches a real localnode so the self-connect
// check in postHandshakeChecks has a valid srv.localnode.ID() to
// compare against. The check runs before eviction, so any test that
// drives postHandshakeChecks with a saturated pool must set one.
func setTestLocalNode(t *testing.T, srv *Server) {
	t.Helper()
	db, err := enode.OpenDB("")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(db.Close)
	srv.localnode = enode.NewLocalNode(db, newkey())
}

func peerSet(peers ...*Peer) map[enode.ID]*Peer {
	out := make(map[enode.ID]*Peer, len(peers))
	for _, p := range peers {
		out[p.ID()] = p
	}
	return out
}

func contains(slice []*Peer, target *Peer) bool {
	return slices.Contains(slice, target)
}

// TestEvictionCandidatesExcludesTrusted — trustedConn peers are
// never candidates regardless of their telemetry.
func TestEvictionCandidatesExcludesTrusted(t *testing.T) {
	good := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	trusted := makeEvictionPeer(t, evictionOpts{inbound: true, trusted: true, createdAge: time.Minute})

	got := evictionCandidates(peerSet(good, trusted))
	if contains(got, trusted) {
		t.Fatal("trustedConn peer must not be an eviction candidate")
	}
	if !contains(got, good) {
		t.Fatal("regular inbound peer should be a candidate")
	}
}

// TestEvictionCandidatesExcludesStatic — staticDialedConn peers are
// never candidates.
func TestEvictionCandidatesExcludesStatic(t *testing.T) {
	good := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	static := makeEvictionPeer(t, evictionOpts{inbound: true, static: true, createdAge: time.Minute})

	got := evictionCandidates(peerSet(good, static))
	if contains(got, static) {
		t.Fatal("staticDialedConn peer must not be an eviction candidate")
	}
}

// TestEvictionCandidatesExcludesOutbound — outbound peers are never
// candidates (eviction is inbound-only; outbounds are managed by
// the dial scheduler).
func TestEvictionCandidatesExcludesOutbound(t *testing.T) {
	in := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	out := makeEvictionPeer(t, evictionOpts{inbound: false, createdAge: time.Minute})

	got := evictionCandidates(peerSet(in, out))
	if contains(got, out) {
		t.Fatal("outbound peer must not be an eviction candidate")
	}
	if !contains(got, in) {
		t.Fatal("inbound peer should be a candidate")
	}
}

// TestEvictionCandidatesIncludesYoungPeers — Bitcoin Core has no
// minimum-age filter on eviction candidates (AttemptToEvictConnection
// builds from all inbound non-noban peers), so brand-new inbound
// connections are valid victims. This is what makes churn attacks
// self-defeating: the attacker's own newest connection is the
// natural pick of the youngest-in-largest-group rule.
func TestEvictionCandidatesIncludesYoungPeers(t *testing.T) {
	young := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 1 * time.Second})
	old := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})

	got := evictionCandidates(peerSet(young, old))
	if !contains(got, young) {
		t.Fatal("young peer must be a candidate (Core has no min-age filter)")
	}
	if !contains(got, old) {
		t.Fatal("old peer should be a candidate")
	}
}

// TestEvictionCandidatesExcludesDisconnecting — a peer whose
// Disconnect has already been requested (Core: fDisconnect) must
// not be picked again, or concurrent admissions would all charge
// the same victim and over-admit past the inbound cap.
func TestEvictionCandidatesExcludesDisconnecting(t *testing.T) {
	dying := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	alive := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	dying.discRequested.Store(true)

	got := evictionCandidates(peerSet(dying, alive))
	if contains(got, dying) {
		t.Fatal("disconnecting peer must not be an eviction candidate")
	}
	if !contains(got, alive) {
		t.Fatal("live peer should be a candidate")
	}
}

// TestProtectLastKFastestPing — protects the k peers with the
// smallest measured minPing values.
func TestProtectLastKFastestPing(t *testing.T) {
	a := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, minPing: 5})
	b := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, minPing: 10})
	c := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, minPing: 15})
	candidates := []*Peer{c, b, a}

	got := protectLastK(candidates, 2, lessMinPingReverse, nil)
	if len(got) != 1 {
		t.Fatalf("survivors = %d, want 1", len(got))
	}
	if got[0] != c {
		t.Fatalf("survivor = peer with ping %d, want %d", got[0].minPing.Load(), c.minPing.Load())
	}
}

// TestProtectLastKUnmeasuredPingIsWorst — a peer that never
// answered a pong (minPing == 0) counts as the WORST ping, not the
// best. Core initializes m_min_ping_time to microseconds::max()
// for exactly this reason: otherwise an attacker who simply never
// replies to pings holds a permanent protection slot.
func TestProtectLastKUnmeasuredPingIsWorst(t *testing.T) {
	silent := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, minPing: 0})
	fast := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, minPing: 50})
	slow := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, minPing: 500})
	candidates := []*Peer{silent, fast, slow}

	got := protectLastK(candidates, 2, lessMinPingReverse, nil)
	if len(got) != 1 || got[0] != silent {
		t.Fatalf("unmeasured-ping peer must be the sole survivor (worst), got %v", got)
	}
}

// TestProtectLastKNewestBlock — protects the k peers with the
// largest lastBlockRx.
func TestProtectLastKNewestBlock(t *testing.T) {
	a := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastBlock: 100})
	b := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastBlock: 200})
	c := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastBlock: 300})
	candidates := []*Peer{a, b, c}

	got := protectLastK(candidates, 2, lessBlockTime, nil)
	if len(got) != 1 {
		t.Fatalf("survivors = %d, want 1", len(got))
	}
	if got[0] != a {
		t.Fatalf("survivor = peer with block %d, want %d", got[0].lastBlockRx.Load(), a.lastBlockRx.Load())
	}
}

// TestProtectLastKWindowPredicate — Core's EraseLastKElements
// applies the predicate only INSIDE the last-k window: window
// members failing it stay candidates, and the window does not
// extend to protect additional matching peers below it.
func TestProtectLastKWindowPredicate(t *testing.T) {
	// Sorted by lessBlockRelayOnlyTime: relayer sorts first (least
	// protected), then non-relayers by block time. Window k=1 covers
	// only the newest-block non-relayer.
	relayer := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastBlock: 999, relayTxs: true})
	brOld := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastBlock: 100})
	brNew := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastBlock: 200})
	candidates := []*Peer{relayer, brOld, brNew}

	got := protectLastK(candidates, 1, lessBlockRelayOnlyTime,
		func(p *Peer) bool { return !p.relayTxs.Load() })
	if contains(got, brNew) {
		t.Fatal("newest-block non-relayer should be protected")
	}
	if !contains(got, brOld) || !contains(got, relayer) {
		t.Fatalf("relayer and older non-relayer should survive, got %v", got)
	}

	// With k=1 and the relayer alone in the window (all
	// non-relayers removed), the window member fails the predicate
	// and nobody is protected.
	got = protectLastK([]*Peer{relayer}, 1, lessBlockRelayOnlyTime,
		func(p *Peer) bool { return !p.relayTxs.Load() })
	if !contains(got, relayer) {
		t.Fatal("window member failing the predicate must stay a candidate")
	}
}

// TestLessTxTimeTieBreaks — equal lastTxRx falls through to
// "tx-relayers protected over non-relayers", then to
// "longest-connected protected" (CompareNodeTXTime chain), so ties
// are deterministic instead of map-iteration-order.
func TestLessTxTimeTieBreaks(t *testing.T) {
	relayer := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastTx: 100, relayTxs: true})
	nonrelayer := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, lastTx: 100, relayTxs: false})
	if !lessTxTime(nonrelayer, relayer) || lessTxTime(relayer, nonrelayer) {
		t.Fatal("tx-relayer must sort as more protected on equal lastTx")
	}
	older := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 2 * time.Minute, lastTx: 100, relayTxs: true})
	newer := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 1 * time.Minute, lastTx: 100, relayTxs: true})
	if !lessTxTime(newer, older) || lessTxTime(older, newer) {
		t.Fatal("longest-connected must sort as more protected on full tie")
	}
}

// TestKeyedNetGroupSemantics — peers sharing a /16 share a keyed
// value; distinct groups differ; peers with no derivable group get
// per-peer singleton values (never one shared bucket).
func TestKeyedNetGroupSemantics(t *testing.T) {
	a1 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, ip: net.IPv4(11, 0, 0, 1)})
	a2 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, ip: net.IPv4(11, 0, 0, 2)})
	b := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute, ip: net.IPv4(12, 0, 0, 1)})
	if keyedNetGroup(a1) != keyedNetGroup(a2) {
		t.Fatal("same /16 must share a keyed netgroup value")
	}
	if keyedNetGroup(a1) == keyedNetGroup(b) {
		t.Fatal("distinct /16s must not share a keyed netgroup value")
	}
}

// TestPreferEvictNarrowsToDiscouraged — when any surviving
// candidate is flagged for discouragement, the eviction pick is
// restricted to the flagged set (Core prefer_evict,
// eviction.cpp:209-215).
func TestPreferEvictNarrowsToDiscouraged(t *testing.T) {
	good := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	bad := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	bad.MisbehavingFor("test-misbehavior")

	got := preferEvict([]*Peer{good, bad})
	if len(got) != 1 || got[0] != bad {
		t.Fatalf("preferEvict must narrow to the discouraged peer, got %v", got)
	}

	// Without any flagged peer the set passes through unchanged.
	got = preferEvict([]*Peer{good})
	if len(got) != 1 || got[0] != good {
		t.Fatal("preferEvict must be a no-op without flagged peers")
	}

	// A peer admitted from a discouraged address (m_prefer_evict
	// stamped at accept) is preferred even if it behaved perfectly
	// this session.
	reoffender := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: time.Minute})
	reoffender.MarkPreferEvict()
	got = preferEvict([]*Peer{good, reoffender})
	if len(got) != 1 || got[0] != reoffender {
		t.Fatalf("preferEvict must narrow to the admission-time discouraged peer, got %v", got)
	}
}

// TestProtectByRatioProtectsHalfOldest — exactly half the candidate
// pool (rounded down) is protected; the protected set is the
// oldest by Created().
func TestProtectByRatioProtectsHalfOldest(t *testing.T) {
	// Younger first so the array order doesn't accidentally pass.
	young := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 31 * time.Second})
	mid := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 60 * time.Second})
	older := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 90 * time.Second})
	oldest := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 120 * time.Second})
	candidates := []*Peer{young, mid, older, oldest}

	got := protectByRatio(candidates)
	if len(got) != 2 {
		t.Fatalf("survivors = %d, want 2 (half of 4)", len(got))
	}
	if contains(got, oldest) || contains(got, older) {
		t.Fatalf("oldest two should be protected, got survivors %v", got)
	}
	if !contains(got, young) || !contains(got, mid) {
		t.Fatalf("youngest two should survive, got %v", got)
	}
}

// TestProtectByRatioReservesLocalhost — up to a quarter of the
// candidates (half the protected slots) go to localhost peers first,
// longest-connected local ahead, even when public peers have more
// uptime. Regression test: the reservation used to be a no-op, and
// since keyedNetGroup buckets all loopback peers into one group,
// co-hosted peers were preferential victims of the largest-group
// rule — the opposite of Core's ProtectEvictionCandidatesByRatio.
func TestProtectByRatioReservesLocalhost(t *testing.T) {
	local1 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 10 * time.Second, ip: net.IPv4(127, 0, 0, 1)})
	local2 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 20 * time.Second, ip: net.IPv4(127, 0, 0, 2)})
	pub1 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 100 * time.Second, ip: net.IPv4(30, 0, 0, 1)})
	pub2 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 90 * time.Second, ip: net.IPv4(40, 0, 0, 1)})
	candidates := []*Peer{local1, local2, pub1, pub2}

	got := protectByRatio(candidates)
	if len(got) != 2 {
		t.Fatalf("survivors = %d, want 2 (half of 4 protected)", len(got))
	}
	// The network slot protects local2 (longest-connected local);
	// the uptime slot protects pub1 (most uptime overall).
	if contains(got, local2) {
		t.Fatal("longest-connected localhost peer must be protected by the network reservation")
	}
	if contains(got, pub1) {
		t.Fatal("highest-uptime public peer must be protected by the uptime slot")
	}
	if !contains(got, local1) || !contains(got, pub2) {
		t.Fatalf("unexpected survivor set: %v", got)
	}
}

// TestPickEvictionVictimYoungestInLargestGroup — final pick rule.
func TestPickEvictionVictimYoungestInLargestGroup(t *testing.T) {
	// Group A has 1 member; group B has 3 members. Victim must
	// come from group B; among B, the youngest.
	a := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 100 * time.Second, ip: net.IPv4(10, 0, 0, 1)})
	b1 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 90 * time.Second, ip: net.IPv4(20, 0, 0, 1)})
	b2 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 60 * time.Second, ip: net.IPv4(20, 0, 0, 2)})
	b3 := makeEvictionPeer(t, evictionOpts{inbound: true, createdAge: 30 * time.Second, ip: net.IPv4(20, 0, 0, 3)})
	candidates := []*Peer{a, b1, b2, b3}

	victim := pickEvictionVictim(candidates)
	if victim != b3 {
		t.Fatalf("victim = %v, want b3 (youngest in largest group)", victim.ID())
	}
}

// TestPickEvictionVictimEmptyReturnsNil — no candidates → nil.
func TestPickEvictionVictimEmptyReturnsNil(t *testing.T) {
	if v := pickEvictionVictim(nil); v != nil {
		t.Fatalf("victim = %v, want nil for empty input", v)
	}
}

// TestEvictInboundFullPipelineWithLargePool — with enough
// candidates to survive every protection round (28+ in the
// default constants), evictInbound succeeds and returns true.
// Asserts the pipeline composes correctly end-to-end.
func TestEvictInboundFullPipelineWithLargePool(t *testing.T) {
	srv := &Server{log: testlog.Logger(t, logging.LvlTrace)}

	// 40 inbound peers: 30 in distinct singleton groups + 10 in
	// one big group. After all protection rounds at least one
	// candidate from the big group will survive.
	peers := map[enode.ID]*Peer{}
	for i := range 30 {
		p := makeEvictionPeer(t, evictionOpts{
			inbound: true, createdAge: time.Duration(60+i) * time.Second,
			ip: net.IPv4(byte(10+i), 0, 0, 1), minPing: int64(i + 1),
			lastBlock: int64(1000 + i), relayTxs: true,
		})
		peers[p.ID()] = p
	}
	for i := range 10 {
		p := makeEvictionPeer(t, evictionOpts{
			inbound: true, createdAge: time.Duration(45+i) * time.Second,
			ip: net.IPv4(192, 168, 0, byte(i)), minPing: int64(500 + i),
			lastBlock: int64(50 + i), relayTxs: true,
		})
		peers[p.ID()] = p
	}

	if !srv.evictInbound(peers) {
		t.Fatal("evictInbound returned false despite a 40-peer pool; protection rounds over-applied")
	}
}

// TestEvictInboundReturnsFalseWhenNoCandidates — empty pool → no-op.
func TestEvictInboundReturnsFalseWhenNoCandidates(t *testing.T) {
	srv := &Server{log: testlog.Logger(t, logging.LvlTrace)}
	if srv.evictInbound(map[enode.ID]*Peer{}) {
		t.Fatal("evictInbound returned true on empty map")
	}
}

// TestEvictInboundReturnsFalseWhenEverythingProtected — when all
// candidates are protected by the various rounds, eviction is a
// no-op.
func TestEvictInboundReturnsFalseWhenEverythingProtected(t *testing.T) {
	srv := &Server{log: testlog.Logger(t, logging.LvlTrace)}

	// Add only trusted/static peers — eviction should find no
	// candidates and return false.
	peers := peerSet(
		makeEvictionPeer(t, evictionOpts{inbound: true, trusted: true, createdAge: time.Minute}),
		makeEvictionPeer(t, evictionOpts{inbound: true, static: true, createdAge: time.Minute}),
	)
	if srv.evictInbound(peers) {
		t.Fatal("evictInbound returned true with only trusted/static peers")
	}
}

// TestPostHandshakeChecksTriggersEviction — when the inbound pool
// is saturated, postHandshakeChecks triggers evictInbound instead
// of hard-rejecting, and accepts the new peer optimistically when
// eviction succeeds.
func TestPostHandshakeChecksTriggersEviction(t *testing.T) {
	srv := &Server{
		log:    testlog.Logger(t, logging.LvlTrace),
		Config: Config{MaxPeers: 50, NoDiscovery: true, NoDial: true},
	}

	// Build 40 inbound candidates so the eviction pipeline can
	// land on a victim.
	peers := map[enode.ID]*Peer{}
	for i := range 40 {
		p := makeEvictionPeer(t, evictionOpts{
			inbound:    true,
			createdAge: time.Duration(60+i) * time.Second,
			ip:         net.IPv4(byte(10+i), 0, 0, 1),
			minPing:    int64(i + 1),
			lastBlock:  int64(1000 + i),
			relayTxs:   true,
		})
		peers[p.ID()] = p
	}

	// Set localnode so the self-connect check (which now runs before
	// eviction) has a valid srv.localnode.ID() to compare against.
	setTestLocalNode(t, srv)

	// Synthesize a new inbound conn that triggers saturation.
	// maxInboundConns by default returns MaxPeers - dialedConns
	// = 50 - 16 (default DialRatio=3, so 16 outbound). But the
	// test config explicitly drives saturation by passing a high
	// inboundCount.
	pipe, _ := net.Pipe()
	fake := &fakeAddrConn{Conn: pipe, remoteAddr: &net.TCPAddr{IP: net.IPv4(99, 99, 99, 99), Port: 32110}}
	defer fake.Close()
	newConn := &conn{
		fd:        fake,
		transport: &v2Transport{},
		node:      enode.SignNull(new(enr.Record), randomID()),
		flags:     inboundConn,
	}

	err := srv.postHandshakeChecks(peers, srv.maxInboundConns(), 0, newConn)
	if err != nil {
		t.Fatalf("postHandshakeChecks returned %v; expected nil after successful eviction", err)
	}
}

// TestPostHandshakeChecksRejectsDuplicateUnderSaturation — a
// duplicate node ID arriving while the inbound pool is saturated
// must be rejected as DiscAlreadyConnected, NOT admitted via
// eviction. Regression: the saturation case used to fall through
// the switch, skipping the duplicate check, which let a second
// connection clobber the peers-map entry of a live peer.
func TestPostHandshakeChecksRejectsDuplicateUnderSaturation(t *testing.T) {
	srv := &Server{
		log:    testlog.Logger(t, logging.LvlTrace),
		Config: Config{MaxPeers: 50, NoDiscovery: true, NoDial: true},
	}
	setTestLocalNode(t, srv)

	peers := map[enode.ID]*Peer{}
	for i := range 40 {
		p := makeEvictionPeer(t, evictionOpts{
			inbound:    true,
			createdAge: time.Duration(60+i) * time.Second,
			ip:         net.IPv4(byte(10+i), 0, 0, 1),
			minPing:    int64(i + 1),
			lastBlock:  int64(1000 + i),
			relayTxs:   true,
		})
		peers[p.ID()] = p
	}
	var dupID enode.ID
	for id := range peers {
		dupID = id
		break
	}

	pipe, _ := net.Pipe()
	fake := &fakeAddrConn{Conn: pipe, remoteAddr: &net.TCPAddr{IP: net.IPv4(99, 99, 99, 99), Port: 32110}}
	defer fake.Close()
	dup := &conn{
		fd:        fake,
		transport: &v2Transport{},
		node:      enode.SignNull(new(enr.Record), dupID),
		flags:     inboundConn,
	}
	if err := srv.postHandshakeChecks(peers, srv.maxInboundConns(), 0, dup); err != DiscAlreadyConnected {
		t.Fatalf("duplicate ID under saturation = %v, want DiscAlreadyConnected", err)
	}
}

// TestPostHandshakeChecksRejectsSelfUnderSaturation — our own node
// ID arriving as an inbound conn under saturation must be rejected
// as DiscSelf, not admitted via eviction (same fall-through
// regression as the duplicate case).
func TestPostHandshakeChecksRejectsSelfUnderSaturation(t *testing.T) {
	srv := &Server{
		log:    testlog.Logger(t, logging.LvlTrace),
		Config: Config{MaxPeers: 50, NoDiscovery: true, NoDial: true},
	}
	setTestLocalNode(t, srv)

	peers := map[enode.ID]*Peer{}
	for i := range 40 {
		p := makeEvictionPeer(t, evictionOpts{
			inbound:    true,
			createdAge: time.Duration(60+i) * time.Second,
			ip:         net.IPv4(byte(10+i), 0, 0, 1),
		})
		peers[p.ID()] = p
	}

	pipe, _ := net.Pipe()
	fake := &fakeAddrConn{Conn: pipe, remoteAddr: &net.TCPAddr{IP: net.IPv4(99, 99, 99, 99), Port: 32110}}
	defer fake.Close()
	self := &conn{
		fd:        fake,
		transport: &v2Transport{},
		node:      enode.SignNull(new(enr.Record), srv.localnode.ID()),
		flags:     inboundConn,
	}
	if err := srv.postHandshakeChecks(peers, srv.maxInboundConns(), 0, self); err != DiscSelf {
		t.Fatalf("self ID under saturation = %v, want DiscSelf", err)
	}
}

// TestAddPeerChecksEvictsOnlyOnce — the admission checks run at both
// the post-handshake and add-peer checkpoints. A single connection
// must not evict two victims: once it has paid for its slot at the
// first checkpoint (recorded on c.evicted), the second checkpoint
// must not evict again. Regression: without the guard, one
// admission dropped two peers, doubling inbound churn cost.
func TestAddPeerChecksEvictsOnlyOnce(t *testing.T) {
	srv := &Server{
		log:    testlog.Logger(t, logging.LvlTrace),
		Config: Config{MaxPeers: 50, NoDiscovery: true, NoDial: true},
	}
	setTestLocalNode(t, srv)

	peers := map[enode.ID]*Peer{}
	for i := range 40 {
		p := makeEvictionPeer(t, evictionOpts{
			inbound:    true,
			createdAge: time.Duration(60+i) * time.Second,
			ip:         net.IPv4(byte(10+i), 0, 0, 1),
			minPing:    int64(i + 1),
			lastBlock:  int64(1000 + i),
			relayTxs:   true,
		})
		peers[p.ID()] = p
	}

	pipe, _ := net.Pipe()
	fake := &fakeAddrConn{Conn: pipe, remoteAddr: &net.TCPAddr{IP: net.IPv4(99, 99, 99, 99), Port: 32110}}
	defer fake.Close()
	c := &conn{
		fd:        fake,
		transport: &v2Transport{},
		node:      enode.SignNull(new(enr.Record), randomID()),
		flags:     inboundConn,
	}

	countDisconnecting := func() int {
		n := 0
		for _, p := range peers {
			if p.discRequested.Load() {
				n++
			}
		}
		return n
	}

	// First checkpoint: evicts one victim and marks the conn.
	if err := srv.postHandshakeChecks(peers, srv.maxInboundConns(), 0, c); err != nil {
		t.Fatalf("first checkpoint = %v, want nil", err)
	}
	if !c.evicted {
		t.Fatal("conn should be marked evicted after first checkpoint")
	}
	if got := countDisconnecting(); got != 1 {
		t.Fatalf("after first checkpoint %d peers disconnecting, want 1", got)
	}

	// Second checkpoint (addPeerChecks): must NOT evict again. The
	// already-disconnecting victim is also no longer a candidate, so
	// even without the c.evicted guard the count must stay 1.
	if err := srv.addPeerChecks(peers, srv.maxInboundConns(), 0, c); err != nil {
		t.Fatalf("second checkpoint = %v, want nil", err)
	}
	if got := countDisconnecting(); got != 1 {
		t.Fatalf("after second checkpoint %d peers disconnecting, want 1 (no double eviction)", got)
	}
}

// TestNodeNetworkGroupKeyExemptsLoopback — loopback / link-local
// addresses bypass the diversity gate so dev-loopback tests don't
// degrade to one peer total.
func TestNodeNetworkGroupKeyExemptsLoopback(t *testing.T) {
	if k := ipNetworkGroupKey(net.ParseIP("127.0.0.1")); k != "" {
		t.Errorf("loopback yielded non-empty key %q", k)
	}
	if k := ipNetworkGroupKey(net.ParseIP("169.254.1.1")); k != "" {
		t.Errorf("link-local yielded non-empty key %q", k)
	}
	if k := ipNetworkGroupKey(net.IPv4(8, 8, 8, 8)); k == "" {
		t.Error("public IPv4 yielded empty key")
	}
}

// TestPostHandshakeChecksHardRejectsWhenEvictionFails — when the
// inbound pool is saturated AND every peer is protected from
// eviction (trusted/static), postHandshakeChecks falls through to
// DiscTooManyPeers.
func TestPostHandshakeChecksHardRejectsWhenEvictionFails(t *testing.T) {
	srv := &Server{
		log:    testlog.Logger(t, logging.LvlTrace),
		Config: Config{MaxPeers: 4, NoDiscovery: true, NoDial: true},
	}
	setTestLocalNode(t, srv)

	// Two trusted inbound peers — neither is evictable.
	peers := peerSet(
		makeEvictionPeer(t, evictionOpts{inbound: true, trusted: true, createdAge: time.Minute}),
		makeEvictionPeer(t, evictionOpts{inbound: true, trusted: true, createdAge: time.Minute}),
	)

	pipe, _ := net.Pipe()
	fake := &fakeAddrConn{Conn: pipe, remoteAddr: &net.TCPAddr{IP: net.IPv4(99, 99, 99, 99), Port: 32110}}
	defer fake.Close()
	newConn := &conn{
		fd:        fake,
		transport: &v2Transport{},
		node:      enode.SignNull(new(enr.Record), randomID()),
		flags:     inboundConn,
	}

	// Pass inboundCount >= maxInboundConns to force the saturation
	// branch.
	err := srv.postHandshakeChecks(peers, srv.maxInboundConns(), 0, newConn)
	if err != DiscTooManyPeers {
		t.Fatalf("postHandshakeChecks = %v, want DiscTooManyPeers", err)
	}
}

// TestPeerInfoMinPing checks that Info reports the session's minimum
// ping RTT in seconds, and omits it before any pong has arrived.
func TestPeerInfoMinPing(t *testing.T) {
	silent := makeEvictionPeer(t, evictionOpts{})
	if got := silent.Info().MinPing; got != 0 {
		t.Fatalf("MinPing without samples = %v, want 0", got)
	}
	blob, err := json.Marshal(silent.Info())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "minPing") {
		t.Fatalf("minPing should be omitted without samples: %s", blob)
	}
	pinged := makeEvictionPeer(t, evictionOpts{minPing: int64(25 * time.Millisecond)})
	if got := pinged.Info().MinPing; got != 0.025 {
		t.Fatalf("MinPing = %v, want 0.025", got)
	}
}
