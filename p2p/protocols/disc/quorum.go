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
	"sync"
	"time"
)

// QuorumThreshold is the minimum number of distinct address-group peers
// that must agree on a reported external address before it becomes our
// self-advertised address. Fixed at 3 per PIP-0006 Phase 4 — raising it
// costs propagation latency, lowering it weakens sybil resistance.
const QuorumThreshold = 3

// QuorumEvictAfter caps how long a *disconnected* peer's YourAddr report
// lingers in the tally. YourAddr is single-shot per session (handler.go
// treats a second one as a disconnect offense), so a live long-lived
// peer never refreshes its receivedAt. The age sweep therefore exempts
// reports whose peer is still in the last-known connected set (see
// evictStaleLocked) and only reaps orphans — reports from a peer whose
// Disconnect() hook never fired (a crash mid-shutdown, or a code path
// that bypasses handler.Run's defer). Genuinely-gone peers are removed
// promptly by Refresh's connected-set reconciliation; this cap is the
// defense-in-depth backstop for the window between a silent disconnect
// and the next Refresh tick.
const QuorumEvictAfter = 3 * time.Hour

// QuorumRefreshInterval is how often the periodic backstop sweep runs.
// PIP-0006 §Phase 4: "re-evaluate quorum every 1h and on peer churn".
// Peer churn is already covered by Disconnect; this tick is the
// defense-in-depth backstop against missed Disconnect propagation, and
// the synchronization point for Refresh's connected-peer reconciliation.
const QuorumRefreshInterval = time.Hour

// PeerKey uniquely identifies a peer within the quorum tally. We want
// per-peer reports (one peer, one vote). The production key is the
// session's enode.ID in hex (see peerKeyFor) — unique per session for
// v2 handshakes (ephemeral-key-derived) and stable across a legacy
// peer's reconnects. Replaced on reconnect either way.
type PeerKey string

// reportedAddr is a (NetID, Addr bytes) pair. Stored as the
// service-key byte form so it's usable as a map key.
//
// The port is deliberately NOT part of the key. Peers we dialed
// observe our ephemeral source port, so their YourAddr reports would
// each land under a distinct (addr, port) key and never aggregate —
// an outbound-only (NAT'd) node could never reach quorum. Bitcoin
// Core keys mapLocalHost on the CNetAddr alone for the same reason
// (src/net.cpp SeenLocal); the port is a per-report property ranked
// separately by portForLocked.
type reportedAddr string

// makeReportedAddr packs (net, addr) into the reportedAddr form.
func makeReportedAddr(net uint8, addr []byte) reportedAddr {
	b := make([]byte, 0, 1+len(addr))
	b = append(b, net)
	b = append(b, addr...)
	return reportedAddr(b)
}

// unpackReportedAddr returns the components of a reportedAddr key.
// Length validation is done before packing so this cannot fail on a
// key that round-tripped through Report.
func unpackReportedAddr(r reportedAddr) (net uint8, addr []byte) {
	b := []byte(r)
	if len(b) < 2 {
		return 0, nil
	}
	return b[0], b[1:]
}

// Quorum tracks peer reports about our external address. Threadsafe.
//
// Reports are stored per (address, peer-key); quorum is reached when
// reports from ≥3 distinct address groups back the same address. The
// distinct-group check is what gives sybil resistance — a small
// colluding set in one /16 cannot outvote a single honest peer from
// another network.
//
// Not persisted: on restart we wait for fresh reports to re-establish
// quorum. That's the plan's design, and it's what keeps an attacker
// who briefly controlled our peers from carrying a bogus advertisement
// across reboots.
type Quorum struct {
	mu sync.Mutex

	// reports[addr][peerKey] = (group, receivedAt).
	reports map[reportedAddr]map[PeerKey]reportEntry

	// connected is the last-known set of live peer keys, refreshed by
	// Refresh from the caller's authoritative connected set.
	// evictStaleLocked consults it so a still-connected peer's
	// single-shot YourAddr report is never aged out of quorum. nil until
	// the first Refresh, before which no report can be old enough to age
	// out anyway.
	connected map[PeerKey]struct{}

	// override* are set when the operator configured --nat extip:<IP>.
	// Short-circuits quorum entirely.
	overrideNet     uint8
	overrideAddr    []byte
	overridePort    uint16
	overrideWinning bool

	// mapped* hold the external endpoint a UPnP/NAT-PMP gateway
	// reported and forwards to us. Unlike the override it never beats
	// the tally: it is the address advertised until quorum forms (a
	// node behind NAT would otherwise announce nothing for its first
	// minutes online, which is when its outbound sessions open), and it
	// completes a quorum winner's missing port with the externally
	// mapped one, which the listen port may not equal. Bitcoin Core
	// did the same with its UPnP-discovered address (LOCAL_MAPPED).
	mappedNet  uint8
	mappedAddr []byte
	mappedPort uint16
}

type reportEntry struct {
	group      []byte
	receivedAt time.Time

	// port is the TCP port the reporter observed alongside the
	// address, or 0 when the observation carries no usable port
	// (reports arriving on sessions we dialed — the reporter saw our
	// ephemeral source port). Ranked across reporters by
	// portForLocked; a zero winner makes SelfEntry substitute the
	// listen port.
	port uint16
}

// NewQuorum returns an empty tally.
func NewQuorum() *Quorum {
	return &Quorum{reports: make(map[reportedAddr]map[PeerKey]reportEntry)}
}

// SetOverride configures an operator-supplied external address. All
// subsequent Winner() calls return this address regardless of tally.
// Pass empty (net==0) to clear.
func (q *Quorum) SetOverride(net uint8, addr []byte, port uint16) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if net == 0 || len(addr) == 0 {
		q.overrideNet, q.overrideAddr, q.overridePort = 0, nil, 0
		q.overrideWinning = false
		return
	}
	q.overrideNet = net
	q.overrideAddr = append([]byte(nil), addr...)
	q.overridePort = port
	q.overrideWinning = true
}

// SetMapped records the external endpoint a NAT gateway maps to us.
// Pass net==0 or port==0 to clear it (the mapping lapsed or the
// gateway's address is unusable).
func (q *Quorum) SetMapped(net uint8, addr []byte, port uint16) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if net == 0 || len(addr) == 0 || port == 0 {
		q.mappedNet, q.mappedAddr, q.mappedPort = 0, nil, 0
		return
	}
	q.mappedNet = net
	q.mappedAddr = append([]byte(nil), addr...)
	q.mappedPort = port
}

// Report records a peer's YourAddr claim. group is the peer's network
// group (passed in by the caller so Quorum doesn't depend on addrman's
// grouping primitive). Returns the address and ok=true if this report
// caused quorum to be reached.
func (q *Quorum) Report(peerKey PeerKey, net uint8, addr []byte, port uint16, group []byte) (winningNet uint8, winningAddr []byte, winningPort uint16, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.evictStaleLocked(time.Now())

	key := makeReportedAddr(net, addr)
	byPeer, exists := q.reports[key]
	if !exists {
		byPeer = make(map[PeerKey]reportEntry)
		q.reports[key] = byPeer
	}
	byPeer[peerKey] = reportEntry{group: append([]byte(nil), group...), receivedAt: time.Now(), port: port}

	return q.winnerLocked(key)
}

// Disconnect removes all of peerKey's reports. Called on session close.
func (q *Quorum) Disconnect(peerKey PeerKey) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for key, byPeer := range q.reports {
		delete(byPeer, peerKey)
		if len(byPeer) == 0 {
			delete(q.reports, key)
		}
	}
}

// Winner returns the external address to advertise, or ok=false if
// there is none. An operator override is always returned first, then
// the address with quorum, then the gateway-mapped endpoint.
func (q *Quorum) Winner() (net uint8, addr []byte, port uint16, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.evictStaleLocked(time.Now())

	if q.overrideWinning {
		return q.overrideNet, append([]byte(nil), q.overrideAddr...), q.overridePort, true
	}

	// Score every address at quorum and pick deterministically. A
	// well-connected node typically has exactly one address at
	// quorum, but when several coexist (an attacker holding three
	// groups at quorum alongside the honest tally, or our own address
	// having just changed) the pick must not flap with map-iteration
	// order — a flapping winner hands ~half of all outbound
	// self-advertisements to whichever address shouldn't win.
	//
	// Ranking: most distinct groups first (an attacker must now
	// out-group the full honest tally, not merely reach threshold);
	// ties broken by the freshest backing report, so when our address
	// changes, new sessions voting for the new address overtake the
	// static old tally as churn accrues; final tie broken by key
	// order for determinism.
	var (
		found     bool
		bestKey   reportedAddr
		bestScore int
		bestFresh time.Time
	)
	for key, byPeer := range q.reports {
		score := countDistinctGroups(byPeer, 0)
		if score < QuorumThreshold {
			continue
		}
		var latest time.Time
		for _, e := range byPeer {
			if e.receivedAt.After(latest) {
				latest = e.receivedAt
			}
		}
		better := !found ||
			score > bestScore ||
			(score == bestScore && latest.After(bestFresh)) ||
			(score == bestScore && latest.Equal(bestFresh) && key < bestKey)
		if better {
			found, bestKey, bestScore, bestFresh = true, key, score, latest
		}
	}
	if !found {
		if q.mappedNet != 0 {
			return q.mappedNet, append([]byte(nil), q.mappedAddr...), q.mappedPort, true
		}
		return 0, nil, 0, false
	}
	n, a := unpackReportedAddr(bestKey)
	port = q.portForLocked(bestKey)
	if port == 0 && n == q.mappedNet && bytes.Equal(a, q.mappedAddr) {
		// No inbound peer has reported a port yet, but the gateway
		// told us which external port it forwards for this address.
		port = q.mappedPort
	}
	return n, append([]byte(nil), a...), port, true
}

// winnerLocked checks whether the specified address has quorum.
func (q *Quorum) winnerLocked(key reportedAddr) (uint8, []byte, uint16, bool) {
	if q.overrideWinning {
		return q.overrideNet, append([]byte(nil), q.overrideAddr...), q.overridePort, true
	}
	byPeer, ok := q.reports[key]
	if !ok {
		return 0, nil, 0, false
	}
	if countDistinctGroups(byPeer, QuorumThreshold) < QuorumThreshold {
		return 0, nil, 0, false
	}
	n, a := unpackReportedAddr(key)
	return n, append([]byte(nil), a...), q.portForLocked(key), true
}

// portForLocked ranks the ports reported for an address and returns
// the plurality winner among non-zero observations: most reporters
// first, ties broken by the lower port for determinism. Returns 0
// when no reporter carried a usable port (all reports arrived on
// sessions we dialed) — SelfEntry then substitutes the listen port,
// mirroring Bitcoin Core's GetListenPort() attachment.
func (q *Quorum) portForLocked(key reportedAddr) uint16 {
	counts := make(map[uint16]int)
	for _, e := range q.reports[key] {
		if e.port != 0 {
			counts[e.port]++
		}
	}
	var (
		best  uint16
		bestN int
	)
	for p, n := range counts {
		if n > bestN || (n == bestN && p < best) {
			best, bestN = p, n
		}
	}
	return best
}

// countDistinctGroups counts the distinct non-empty network groups in
// a report set, stopping early at cap when cap > 0. O(N²) over
// reporters — small N. Malformed (empty) groups never contribute to
// quorum, per the PIP-0006 Phase 4 rule.
func countDistinctGroups(byPeer map[PeerKey]reportEntry, cap int) int {
	var groups [][]byte
outer:
	for _, entry := range byPeer {
		if len(entry.group) == 0 {
			continue
		}
		for _, existing := range groups {
			if bytes.Equal(existing, entry.group) {
				continue outer
			}
		}
		groups = append(groups, entry.group)
		if cap > 0 && len(groups) >= cap {
			break
		}
	}
	return len(groups)
}

// evictStaleLocked removes reports older than QuorumEvictAfter whose
// reporting peer is no longer connected. O(N). Called opportunistically —
// quorum state is small enough that a full sweep on every Report/Winner
// is fine.
//
// A still-connected peer is exempt from the age sweep: YourAddr is
// single-shot per session, so a long-lived peer's receivedAt never
// advances and would otherwise decay out of quorum while the peer is
// right there — silently stopping self-advertisement on a stable
// topology. Removal of genuinely-gone peers is Refresh's job (it
// reconciles against the authoritative connected set); this sweep only
// reaps orphans whose Disconnect() hook was missed and which are absent
// from the last-known connected set.
func (q *Quorum) evictStaleLocked(now time.Time) {
	for key, byPeer := range q.reports {
		for pk, entry := range byPeer {
			if now.Sub(entry.receivedAt) <= QuorumEvictAfter {
				continue
			}
			if _, live := q.connected[pk]; live {
				continue
			}
			delete(byPeer, pk)
		}
		if len(byPeer) == 0 {
			delete(q.reports, key)
		}
	}
}

// Refresh runs the periodic re-evaluation called for in PIP-0006 §Phase
// 4: reconcile the tally against the peers that are actually connected,
// dropping reports from peers no longer present, then age out any stale
// orphans. The connected set is supplied by the caller (so Quorum
// doesn't depend on Server).
//
// connectedFn is invoked *under q.mu* — the same lock that guards report
// insertion (Report). This makes the snapshot atomic with respect to a
// peer completing its handshake: any YourAddr report that has committed
// by the time this reconciliation runs was preceded, in that peer's
// handler goroutine, by the Hello that registers the peer as connected,
// so a snapshot taken here observes the peer and will not delete its
// fresh, single-shot vote. Snapshotting eagerly before locking would
// leave a window in which a just-connected peer is absent from the
// snapshot yet present in the tally, and its vote — unrecoverable,
// because YourAddr is single-shot — would be dropped for the whole
// session.
//
// A nil connectedFn skips the connected-set reconciliation (the age
// sweep still runs) — useful for tests that exercise only the
// time-eviction path.
//
// Returns the number of reports dropped by the connected-set check (the
// time-eviction count is not surfaced; it's defense-in-depth and
// rare). Callers can log or metric this.
func (q *Quorum) Refresh(now time.Time, connectedFn func() map[PeerKey]struct{}) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	if connectedFn != nil {
		// Record the live set before the age sweep so evictStaleLocked
		// exempts still-connected peers.
		q.connected = connectedFn()
	}

	q.evictStaleLocked(now)

	if connectedFn == nil {
		return 0
	}
	dropped := 0
	for key, byPeer := range q.reports {
		for pk := range byPeer {
			if _, ok := q.connected[pk]; !ok {
				delete(byPeer, pk)
				dropped++
			}
		}
		if len(byPeer) == 0 {
			delete(q.reports, key)
		}
	}
	return dropped
}

// Stats returns the current tally for operator diagnostics. Dumps (addr,
// distinct-group count). Used by `parallax-cli addrbook status` in
// Phase 6.
func (q *Quorum) Stats() []QuorumStat {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.evictStaleLocked(time.Now())

	out := make([]QuorumStat, 0, len(q.reports))
	for key, byPeer := range q.reports {
		n, a := unpackReportedAddr(key)
		seen := make(map[string]struct{}, len(byPeer))
		for _, entry := range byPeer {
			seen[string(entry.group)] = struct{}{}
		}
		out = append(out, QuorumStat{
			NetworkID:     n,
			Addr:          append([]byte(nil), a...),
			TCPPort:       q.portForLocked(key),
			Reporters:     len(byPeer),
			DistinctGroup: len(seen),
		})
	}
	return out
}

// QuorumStat is one row of Stats output. Stable shape — consumed by
// operator tooling.
type QuorumStat struct {
	NetworkID     uint8
	Addr          []byte
	TCPPort       uint16
	Reporters     int
	DistinctGroup int
}
