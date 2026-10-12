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
	"fmt"
	"testing"
	"time"
)

// TestQuorumReachedAtThreshold — three reports from distinct groups
// activate quorum; fewer don't.
func TestQuorumReachedAtThreshold(t *testing.T) {
	q := NewQuorum()
	addr := []byte{203, 0, 113, 42}

	// Two reports from same group — no quorum.
	q.Report("peer-1", NetIPv4, addr, 30303, []byte{NetIPv4, 8, 8})
	q.Report("peer-2", NetIPv4, addr, 30303, []byte{NetIPv4, 8, 8})
	if _, _, _, ok := q.Winner(); ok {
		t.Error("quorum reached with only one distinct group")
	}

	// Third peer from a new group — still not enough (only 2 distinct).
	q.Report("peer-3", NetIPv4, addr, 30303, []byte{NetIPv4, 1, 1})
	if _, _, _, ok := q.Winner(); ok {
		t.Error("quorum reached with two distinct groups (threshold=3)")
	}

	// Fourth peer from a third group — quorum.
	q.Report("peer-4", NetIPv4, addr, 30303, []byte{NetIPv4, 9, 9})
	net, a, p, ok := q.Winner()
	if !ok {
		t.Fatal("quorum not reached at 3 distinct groups")
	}
	if net != NetIPv4 || string(a) != string(addr) || p != 30303 {
		t.Errorf("wrong winner: got (%d, %x, %d)", net, a, p)
	}
}

// TestQuorumRejectsGroupZero — empty/malformed groups must not count.
func TestQuorumRejectsGroupZero(t *testing.T) {
	q := NewQuorum()
	addr := []byte{1, 2, 3, 4}
	// Three reports with empty group — should never reach quorum.
	for i := range 5 {
		q.Report(PeerKey(string(rune('a'+i))), NetIPv4, addr, 30303, nil)
	}
	if _, _, _, ok := q.Winner(); ok {
		t.Error("empty-group reports contributed to quorum")
	}
}

// TestQuorumDistinctGroupMonotonic — adding reports within the same
// peer's session never decreases distinct-group count (invariant the
// handler depends on for stability under flapping peers).
func TestQuorumDistinctGroupMonotonic(t *testing.T) {
	q := NewQuorum()
	addr := []byte{1, 2, 3, 4}

	groups := [][]byte{
		{NetIPv4, 1, 1},
		{NetIPv4, 2, 2},
		{NetIPv4, 3, 3},
		{NetIPv4, 4, 4},
	}
	winners := 0
	for i, g := range groups {
		q.Report(PeerKey(string(rune('a'+i))), NetIPv4, addr, 30303, g)
		if _, _, _, ok := q.Winner(); ok {
			winners++
		}
	}
	// Quorum must activate at ≥3 and stay active.
	if winners < 2 {
		t.Errorf("winners should stay set after quorum reached; got %d transitions", winners)
	}
}

// TestQuorumAggregatesAcrossPorts — reports for one address aggregate
// regardless of the port each reporter observed. Regression test: the
// tally used to key on (net, addr, port), so reports arriving on
// dialed sessions — each carrying our ephemeral source port — never
// aggregated, and an outbound-only (NAT'd) node could not reach
// quorum. The port is ranked separately by reporter plurality.
func TestQuorumAggregatesAcrossPorts(t *testing.T) {
	q := NewQuorum()
	addr := []byte{203, 0, 113, 42}

	// Three dialed-session reports (port zeroed by HandleYourAddr),
	// three distinct groups: quorum must be reached.
	q.Report("out-1", NetIPv4, addr, 0, []byte{NetIPv4, 1, 1})
	q.Report("out-2", NetIPv4, addr, 0, []byte{NetIPv4, 2, 2})
	q.Report("out-3", NetIPv4, addr, 0, []byte{NetIPv4, 3, 3})
	net, a, p, ok := q.Winner()
	if !ok {
		t.Fatal("outbound-only reports did not aggregate to quorum")
	}
	if net != NetIPv4 || string(a) != string(addr) {
		t.Errorf("wrong winner: (%d, %x)", net, a)
	}
	if p != 0 {
		t.Errorf("port should be 0 with no port observations, got %d", p)
	}

	// Two inbound observations agree on 32110, one says 40000: the
	// plurality port wins.
	q.Report("in-1", NetIPv4, addr, 32110, []byte{NetIPv4, 4, 4})
	q.Report("in-2", NetIPv4, addr, 32110, []byte{NetIPv4, 5, 5})
	q.Report("in-3", NetIPv4, addr, 40000, []byte{NetIPv4, 6, 6})
	if _, _, p, _ := q.Winner(); p != 32110 {
		t.Errorf("plurality port = %d, want 32110", p)
	}
}

// TestQuorumPortTieBreaksLow — equal reporter counts pick the lower
// port so the winner never flaps with map iteration order.
func TestQuorumPortTieBreaksLow(t *testing.T) {
	q := NewQuorum()
	addr := []byte{198, 51, 100, 9}
	q.Report("a", NetIPv4, addr, 40000, []byte{NetIPv4, 1, 1})
	q.Report("b", NetIPv4, addr, 32110, []byte{NetIPv4, 2, 2})
	q.Report("c", NetIPv4, addr, 0, []byte{NetIPv4, 3, 3})
	if _, _, p, ok := q.Winner(); !ok || p != 32110 {
		t.Errorf("tie-break port = %d (ok=%v), want 32110", p, ok)
	}
}

// TestQuorumOverrideShortCircuits — SetOverride always wins.
func TestQuorumOverrideShortCircuits(t *testing.T) {
	q := NewQuorum()
	// Empty tally — normally no winner.
	q.SetOverride(NetIPv4, []byte{10, 20, 30, 40}, 30303)
	net, a, p, ok := q.Winner()
	if !ok {
		t.Fatal("override should always win")
	}
	if net != NetIPv4 || p != 30303 || a[0] != 10 {
		t.Errorf("wrong override winner: (%d, %x, %d)", net, a, p)
	}

	// Clear override — tally now rules (empty, no winner).
	q.SetOverride(0, nil, 0)
	if _, _, _, ok := q.Winner(); ok {
		t.Error("Winner still ok after clearing override")
	}
}

// TestQuorumDisconnectRemovesVotes — peer reports are purged on
// disconnect, and previously-reached quorum can drop back below the
// threshold.
func TestQuorumDisconnectRemovesVotes(t *testing.T) {
	q := NewQuorum()
	addr := []byte{1, 2, 3, 4}
	q.Report("p1", NetIPv4, addr, 30303, []byte{NetIPv4, 1, 1})
	q.Report("p2", NetIPv4, addr, 30303, []byte{NetIPv4, 2, 2})
	q.Report("p3", NetIPv4, addr, 30303, []byte{NetIPv4, 3, 3})
	if _, _, _, ok := q.Winner(); !ok {
		t.Fatal("quorum not reached initially")
	}
	q.Disconnect("p3")
	if _, _, _, ok := q.Winner(); ok {
		t.Error("quorum still ok after disconnecting one of three groups")
	}
}

// TestQuorumRefreshDropsDisconnectedPeers — Refresh's
// connected-peer reconciliation drops reports from peers absent
// from the supplied connected set, even when their receivedAt is
// fresh. The "and on peer churn" half of PIP-0006 §Phase 4's
// quorum re-eval, here exercised as the periodic backstop in case
// Disconnect() didn't fire.
func TestQuorumRefreshDropsDisconnectedPeers(t *testing.T) {
	q := NewQuorum()
	addr := []byte{198, 51, 100, 7}

	q.Report("p1", NetIPv4, addr, 30303, []byte{NetIPv4, 1, 1})
	q.Report("p2", NetIPv4, addr, 30303, []byte{NetIPv4, 2, 2})
	q.Report("p3", NetIPv4, addr, 30303, []byte{NetIPv4, 3, 3})
	if _, _, _, ok := q.Winner(); !ok {
		t.Fatal("quorum not reached initially")
	}

	// p3's session vanished (handler.Run returned without firing
	// PeerDisconnected). Refresh with the truly-connected set must
	// drop the orphaned report and quorum must follow.
	connected := map[PeerKey]struct{}{"p1": {}, "p2": {}}
	dropped := q.Refresh(time.Now(), func() map[PeerKey]struct{} { return connected })
	if dropped != 1 {
		t.Errorf("Refresh dropped %d, want 1", dropped)
	}
	if _, _, _, ok := q.Winner(); ok {
		t.Error("quorum still ok after Refresh dropped a contributing peer")
	}
}

// TestQuorumRefreshNilConnectedKeepsReports — passing nil for the
// connected set is the "skip connected-set reconciliation" mode
// (used by tests that exercise only the time-eviction path). Reports
// must remain intact.
func TestQuorumRefreshNilConnectedKeepsReports(t *testing.T) {
	q := NewQuorum()
	addr := []byte{198, 51, 100, 8}
	q.Report("p1", NetIPv4, addr, 30303, []byte{NetIPv4, 1, 1})
	q.Report("p2", NetIPv4, addr, 30303, []byte{NetIPv4, 2, 2})
	q.Report("p3", NetIPv4, addr, 30303, []byte{NetIPv4, 3, 3})

	if dropped := q.Refresh(time.Now(), nil); dropped != 0 {
		t.Errorf("nil connected set dropped %d reports, want 0", dropped)
	}
	if _, _, _, ok := q.Winner(); !ok {
		t.Error("quorum lost after Refresh(nil)")
	}
}

// TestQuorumAgedReportSurvivesWhileConnected — DEFECT 1 regression.
// YourAddr is single-shot per session, so a long-lived peer's report
// ages past QuorumEvictAfter while the peer is still connected. The age
// sweep must NOT drop such a report (doing so silently collapses quorum
// on a stable topology); it may only reap the stale report of a peer
// that is genuinely gone from the connected set.
func TestQuorumAgedReportSurvivesWhileConnected(t *testing.T) {
	q := NewQuorum()
	addr := []byte{198, 51, 100, 9}

	q.Report("p1", NetIPv4, addr, 30303, []byte{NetIPv4, 1, 1})
	q.Report("p2", NetIPv4, addr, 30303, []byte{NetIPv4, 2, 2})
	q.Report("p3", NetIPv4, addr, 30303, []byte{NetIPv4, 3, 3})

	// Age every report well past the cap — the steady state on a stable
	// peer set, where no reconnect ever refreshes receivedAt.
	q.mu.Lock()
	for _, byPeer := range q.reports {
		for pk, entry := range byPeer {
			entry.receivedAt = time.Now().Add(-QuorumEvictAfter - time.Minute)
			byPeer[pk] = entry
		}
	}
	q.mu.Unlock()

	// All three peers are still connected: their aged votes must survive.
	all := map[PeerKey]struct{}{"p1": {}, "p2": {}, "p3": {}}
	q.Refresh(time.Now(), func() map[PeerKey]struct{} { return all })
	if _, _, _, ok := q.Winner(); !ok {
		t.Fatal("aged reports from still-connected peers were wrongly evicted")
	}

	// p3's session vanished without firing Disconnect. Now the age sweep
	// — driven by the reconciled connected set — reaps only that absent
	// peer's stale vote, dropping quorum below threshold.
	live := map[PeerKey]struct{}{"p1": {}, "p2": {}}
	q.Refresh(time.Now(), func() map[PeerKey]struct{} { return live })
	if _, _, _, ok := q.Winner(); ok {
		t.Error("quorum still ok after the gone peer's stale vote was reaped")
	}
}

// TestQuorumRefreshSnapshotLazyKeepsFreshVote — DEFECT 2 regression.
// The connected snapshot must be evaluated lazily, under the report
// lock, inside Refresh. A peer that completes Hello+YourAddr in the
// window between an eager snapshot and the reconciliation is present in
// the tally but absent from a stale eager snapshot, so it would be
// deleted — and its single-shot vote lost for the whole session. This
// test contrasts the two evaluation strategies over identical tallies.
func TestQuorumRefreshSnapshotLazyKeepsFreshVote(t *testing.T) {
	addr := []byte{198, 51, 100, 12}
	build := func() *Quorum {
		q := NewQuorum()
		q.Report("p1", NetIPv4, addr, 30303, []byte{NetIPv4, 1, 1})
		q.Report("p2", NetIPv4, addr, 30303, []byte{NetIPv4, 2, 2})
		// p3 is the racing peer: its YourAddr has already committed.
		q.Report("p3", NetIPv4, addr, 30303, []byte{NetIPv4, 3, 3})
		return q
	}

	// Hazard: an eager snapshot captured before p3 connected omits p3;
	// feeding it drops p3's committed vote and collapses quorum. This
	// documents exactly the failure the lazy snapshot avoids.
	qBug := build()
	stale := map[PeerKey]struct{}{"p1": {}, "p2": {}}
	qBug.Refresh(time.Now(), func() map[PeerKey]struct{} { return stale })
	if _, _, _, ok := qBug.Winner(); ok {
		t.Fatal("setup invariant: a stale snapshot missing p3 should drop its vote")
	}

	// Fixed: the snapshot is evaluated at reconciliation time, when p3's
	// Report (and, in production, the Hello that precedes it) is already
	// visible, so p3 is in the live set and its vote survives.
	qFix := build()
	qFix.Refresh(time.Now(), func() map[PeerKey]struct{} {
		return map[PeerKey]struct{}{"p1": {}, "p2": {}, "p3": {}}
	})
	if _, _, _, ok := qFix.Winner(); !ok {
		t.Fatal("fresh vote dropped despite the peer being present at reconcile time")
	}
}

// FuzzQuorumReports streams arbitrary (peerKey, net, addr, port, group)
// reports and asserts: no panic; distinct-group count is consistent
// (all Winner-true addresses have ≥3 distinct non-empty groups); no
// partial state leaks.
func FuzzQuorumReports(f *testing.F) {
	f.Add(NetIPv4, []byte{1, 2, 3, 4}, uint16(30303), "peer-1", []byte{NetIPv4, 1, 1})
	f.Add(NetIPv4, []byte{1, 2, 3, 4}, uint16(30303), "peer-2", []byte{NetIPv4, 2, 2})
	f.Add(NetIPv4, []byte{1, 2, 3, 4}, uint16(30303), "peer-3", []byte{NetIPv4, 3, 3})

	q := NewQuorum()
	f.Fuzz(func(t *testing.T, net uint8, addr []byte, port uint16, peerKey string, group []byte) {
		if len(addr) > 64 {
			addr = addr[:64]
		}
		if len(group) > 8 {
			group = group[:8]
		}
		q.Report(PeerKey(peerKey), net, addr, port, group)
		_, _, _, _ = q.Winner()
		q.Stats()
		// Sanity invariant: override takes precedence over tally.
		q.SetOverride(NetIPv4, []byte{1, 1, 1, 1}, 9999)
		if _, a, p, ok := q.Winner(); !ok || p != 9999 || len(a) != 4 {
			t.Errorf("override broken: ok=%v addr=%x port=%d", ok, a, p)
		}
		q.SetOverride(0, nil, 0)
	})
}

// TestWinnerDeterministicAcrossMultipleQuorums — when two addresses
// hold quorum simultaneously, Winner must rank deterministically:
// most distinct groups first, freshest backing report on ties. The
// old first-map-hit pick flapped with iteration order, handing ~half
// of all self-advertisements to an attacker who merely reached
// threshold alongside the honest tally; it also let a dead address
// linger as winner forever after an IP change.
func TestWinnerDeterministicAcrossMultipleQuorums(t *testing.T) {
	q := NewQuorum()
	oldAddr := []byte{198, 51, 100, 1}
	newAddr := []byte{203, 0, 113, 9}

	group := func(b byte) []byte { return []byte{NetIPv4, b, 0} }

	// Old address: quorum from 3 groups (reports land first, so they
	// are older).
	for i := 0; i < 3; i++ {
		q.Report(PeerKey(fmt.Sprintf("old-%d", i)), NetIPv4, oldAddr, 32110, group(byte(10+i)))
	}

	time.Sleep(5 * time.Millisecond)
	// New address: quorum from 3 different groups, strictly fresher.
	for i := 0; i < 3; i++ {
		q.Report(PeerKey(fmt.Sprintf("new-%d", i)), NetIPv4, newAddr, 32110, group(byte(20+i)))
	}

	// Equal group counts: freshest tally wins, on every call.
	for i := 0; i < 20; i++ {
		_, addr, _, ok := q.Winner()
		if !ok {
			t.Fatal("no winner with two quorums present")
		}
		if !bytesEqual(addr, newAddr) {
			t.Fatalf("call %d: winner = %v, want fresher %v", i, addr, newAddr)
		}
	}

	// A fourth distinct group for the old address outranks freshness.
	q.Report(PeerKey("o3"), NetIPv4, oldAddr, 32110, group(13))
	for i := 0; i < 20; i++ {
		_, addr, _, ok := q.Winner()
		if !ok {
			t.Fatal("no winner")
		}
		if !bytesEqual(addr, oldAddr) {
			t.Fatalf("call %d: winner = %v, want higher-group-count %v", i, addr, oldAddr)
		}
	}
}

// TestQuorumMappedFallback — the gateway-mapped endpoint is advertised
// while no address has quorum, yields to the quorum winner once one
// forms, and supplies that winner's missing port when the addresses
// agree.
func TestQuorumMappedFallback(t *testing.T) {
	q := NewQuorum()
	mapped := []byte{45, 236, 49, 58}
	q.SetMapped(NetIPv4, mapped, 40123)

	net, addr, port, ok := q.Winner()
	if !ok || net != NetIPv4 || string(addr) != string(mapped) || port != 40123 {
		t.Fatalf("before quorum: got (%d, %v, %d, %v), want the mapped endpoint", net, addr, port, ok)
	}

	// Quorum on the same address from outbound sessions (port 0):
	// the mapped port completes it.
	for i, g := range [][]byte{{1}, {2}, {3}} {
		q.Report(PeerKey(rune('a'+i)), NetIPv4, mapped, 0, g)
	}
	if _, _, port, _ = q.Winner(); port != 40123 {
		t.Fatalf("quorum on mapped address: port %d, want the mapped 40123", port)
	}

	// Quorum on a different address outranks the mapping, and its
	// port is not borrowed from it.
	q2 := NewQuorum()
	q2.SetMapped(NetIPv4, mapped, 40123)
	other := []byte{8, 8, 4, 4}
	for i, g := range [][]byte{{1}, {2}, {3}} {
		q2.Report(PeerKey(rune('a'+i)), NetIPv4, other, 0, g)
	}
	if _, addr, port, _ = q2.Winner(); string(addr) != string(other) || port != 0 {
		t.Fatalf("quorum elsewhere: got (%v, %d), want (%v, 0)", addr, port, other)
	}

	// Clearing withdraws the fallback.
	q.SetMapped(0, nil, 0)
	q.Disconnect("a")
	if _, _, _, ok = q.Winner(); ok {
		t.Fatal("cleared mapping with no quorum still yields a winner")
	}
}
