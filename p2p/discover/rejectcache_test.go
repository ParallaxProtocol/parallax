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

package discover

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enr"
)

func newTestRejectCache(ttl time.Duration, max int) *rejectCache {
	return &rejectCache{
		entries:  make(map[rejectKey]time.Time),
		perIP:    make(map[[16]byte]int),
		ttl:      ttl,
		max:      max,
		perIPCap: rejectCachePerIPMax,
	}
}

func mkID(b byte) enode.ID {
	var id enode.ID
	id[0] = b
	return id
}

// mkIP is the endpoint used alongside mkID in cache tests where the
// (ID, IP) pairing itself is not under test.
func mkIP(b byte) net.IP {
	return net.IP{192, 0, 2, b}
}

func TestRejectCacheAddContains(t *testing.T) {
	c := newTestRejectCache(time.Minute, 16)
	id := mkID(1)
	if c.Contains(id, mkIP(1)) {
		t.Fatalf("empty cache should not contain id")
	}
	c.Add(id, mkIP(1))
	if !c.Contains(id, mkIP(1)) {
		t.Fatalf("cache should contain id after Add")
	}
	if c.Contains(mkID(2), mkIP(1)) {
		t.Fatalf("cache should not contain unrelated id")
	}
}

func TestRejectCacheTTLExpiry(t *testing.T) {
	// 5ms TTL — short enough for a fast test, long enough to dodge scheduler jitter.
	c := newTestRejectCache(5*time.Millisecond, 16)
	id := mkID(7)
	c.Add(id, mkIP(1))
	if !c.Contains(id, mkIP(1)) {
		t.Fatalf("entry should be live immediately after Add")
	}
	time.Sleep(20 * time.Millisecond)
	if c.Contains(id, mkIP(1)) {
		t.Fatalf("entry should have expired after TTL")
	}
	// Lazy delete should have removed it from the map.
	if c.Len() != 0 {
		t.Fatalf("expected empty cache after expiry+Contains, got len=%d", c.Len())
	}
}

func TestRejectCacheReAddRefreshesTTL(t *testing.T) {
	c := newTestRejectCache(40*time.Millisecond, 16)
	id := mkID(3)
	c.Add(id, mkIP(1))
	time.Sleep(25 * time.Millisecond)
	c.Add(id, mkIP(1)) // refresh
	time.Sleep(25 * time.Millisecond)
	// Original TTL would have expired (50ms total since first Add), but the
	// refresh at 25ms means the entry is only 25ms old now.
	if !c.Contains(id, mkIP(1)) {
		t.Fatalf("re-Add should refresh TTL; entry expired prematurely")
	}
}

func TestRejectCacheCapEviction(t *testing.T) {
	const max = 8
	c := newTestRejectCache(time.Hour, max)
	// Insert max+5 distinct IDs. The cap should keep us at <= max,
	// and it must do so by dropping newcomers, never by evicting live
	// entries — an attacker with cheap failing keys could otherwise
	// flush the legitimate suppressions out of the cache.
	for i := 0; i < max+5; i++ {
		c.Add(mkID(byte(i+1)), mkIP(1))
	}
	if c.Len() > max {
		t.Fatalf("cache exceeded cap: len=%d, max=%d", c.Len(), max)
	}
	for i := 0; i < max; i++ {
		if !c.Contains(mkID(byte(i+1)), mkIP(1)) {
			t.Fatalf("live entry %d was evicted by a newcomer", i+1)
		}
	}
	if c.Contains(mkID(byte(max+5)), mkIP(1)) {
		t.Fatal("newcomer was admitted past a cache full of live entries")
	}
	// Refreshing an existing entry at cap must still work.
	c.Add(mkID(1), mkIP(1))
	if !c.Contains(mkID(1), mkIP(1)) {
		t.Fatal("TTL refresh at cap failed")
	}
}

// newTestFilterTable creates a table with an accept-all node filter so the
// verifyAndAdd / lookup-time ENR verification paths are exercised.
func newTestFilterTable(t transport) (*Table, *enode.DB) {
	db, _ := enode.OpenDB("")
	tab, _ := newTable(t, db, nil, nil, func(*enode.Node) bool { return true }, logging.Root())
	go tab.loop()
	return tab, db
}

// Regression: a node whose verified ENR is in the positive nodedb cache must
// not be dropped because of a stale reject-cache entry. Before the positive
// cache was consulted first, a single transient RequestENR failure (one
// dropped UDP packet) blacklisted a known-good node for rejectCacheTTL.
func TestVerifyAndAddPrefersNodedbOverRejectCache(t *testing.T) {
	transport := newPingRecorder()
	tab, db := newTestFilterTable(transport)
	defer db.Close()
	defer tab.close()

	n := nodeAtDistance(tab.self().ID(), 250, net.IP{203, 0, 113, 1})
	// The node has been verified before: its record is in the nodedb.
	if err := db.UpdateNode(unwrapNode(n)); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	// A transient RequestENR failure put it in the negative cache.
	tab.rejects.Add(n.ID(), n.IP())

	// The transport has no record for n, so any RequestENR round-trip would
	// fail; the add can only succeed through the nodedb fast path.
	tab.verifyAndAdd(n, 0)

	if tab.getNode(n.ID()) == nil {
		t.Fatalf("nodedb-verified node was dropped due to reject-cache entry")
	}
}

// Regression: same as above, but for the lookup-time verification path in
// lookup.query.
func TestLookupPrefersNodedbOverRejectCache(t *testing.T) {
	transport := newPingRecorder()
	tab, db := newTestFilterTable(transport)
	defer db.Close()
	defer tab.close()

	target := nodeAtDistance(tab.self().ID(), 250, net.IP{203, 0, 113, 2})
	if err := db.UpdateNode(unwrapNode(target)); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	tab.rejects.Add(target.ID(), target.IP())

	it := &lookup{
		tab:       tab,
		queryfunc: func(*node) ([]*node, error) { return []*node{target}, nil },
	}
	reply := make(chan []*node, 1)
	asked := nodeAtDistance(tab.self().ID(), 240, net.IP{203, 0, 113, 3})
	it.query(asked, reply)

	for _, n := range <-reply {
		if n.ID() == target.ID() {
			return
		}
	}
	t.Fatalf("nodedb-verified node missing from lookup reply due to reject-cache entry")
}

func TestRejectCacheCapPrefersExpiredEviction(t *testing.T) {
	const max = 4
	c := newTestRejectCache(10*time.Millisecond, max)
	// Fill cap with short-TTL entries.
	for i := 0; i < max; i++ {
		c.Add(mkID(byte(i+1)), mkIP(1))
	}
	// Wait for them all to expire.
	time.Sleep(25 * time.Millisecond)
	// Adding past cap should sweep expired entries first; no live-entry
	// eviction needed. After this, the cache should contain only the new id.
	c.Add(mkID(99), mkIP(1))
	if !c.Contains(mkID(99), mkIP(1)) {
		t.Fatalf("newly added id missing")
	}
	if c.Len() != 1 {
		t.Fatalf("expected cache to drop expired entries on cap-overflow, got len=%d", c.Len())
	}
}

// Regression: the cache is keyed by (ID, IP), so a failed verification of
// goodID advertised at an attacker's endpoint must not suppress the honest
// goodID at its real endpoint. Before the endpoint was part of the key, any
// queried neighbor could blacklist an arbitrary node ID for rejectCacheTTL
// by returning it with an unreachable address.
func TestRejectCacheKeyedByEndpoint(t *testing.T) {
	c := newTestRejectCache(time.Minute, 16)
	id := mkID(42)
	attackerIP := net.IP{198, 51, 100, 66}
	goodIP := net.IP{203, 0, 113, 7}

	c.Add(id, attackerIP)
	if !c.Contains(id, attackerIP) {
		t.Fatalf("rejected endpoint should be cached")
	}
	if c.Contains(id, goodIP) {
		t.Fatalf("rejection at attacker endpoint must not blacklist the same ID at its honest endpoint")
	}
}

// Regression: the positive nodedb cache must be bypassed when the node
// is observed at a different endpoint than the cached record carries.
// A node that changed IP keeps pinging from the new address, recording
// fresh pongs that keep the stale db record alive indefinitely — so
// without the bypass, the cached (dead) endpoint is pinned permanently
// and the node's real endpoint is never learned.
func TestVerifyAndAddRefetchesMovedNode(t *testing.T) {
	transport := newPingRecorder()
	tab, db := newTestFilterTable(transport)
	defer db.Close()
	defer tab.close()

	id := idAtDistance(tab.self().ID(), 250)
	oldIP := net.IP{203, 0, 113, 10}
	newIP := net.IP{203, 0, 113, 20}
	mk := func(ip net.IP) *node {
		var r enr.Record
		r.Set(enr.IP(ip))
		return wrapNode(enode.SignNull(&r, id))
	}

	// The stale record (old endpoint) sits in the nodedb; the node
	// itself now answers RequestENR with its fresh record.
	if err := db.UpdateNode(unwrapNode(mk(oldIP))); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	fresh := mk(newIP)
	transport.updateRecord(unwrapNode(fresh))

	// Observed pinging from the new address. The re-fetch runs on the
	// bounded async verification path, so poll for the outcome.
	tab.verifyAndAdd(mk(newIP), 0)

	got := waitForTableNode(t, tab, id)
	if !got.IP().Equal(newIP) {
		t.Fatalf("table has IP %v, want re-fetched endpoint %v (stale cached record was reused)", got.IP(), newIP)
	}
}

// waitForTableNode polls for id to appear in the table, failing the
// test after a deadline. Needed because verifyAndAdd's RequestENR path
// completes on a bounded background goroutine.
func waitForTableNode(t *testing.T, tab *Table, id enode.ID) *enode.Node {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := tab.getNode(id); n != nil {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("node missing from table")
	return nil
}

// Regression: a ping claiming a newer ENR sequence than the cached
// record must trigger a re-fetch even when the endpoint is unchanged.
func TestVerifyAndAddRefetchesOnNewerSeq(t *testing.T) {
	transport := newPingRecorder()
	tab, db := newTestFilterTable(transport)
	defer db.Close()
	defer tab.close()

	id := idAtDistance(tab.self().ID(), 250)
	ip := net.IP{203, 0, 113, 30}
	mk := func(seq uint64) *node {
		var r enr.Record
		r.Set(enr.IP(ip))
		r.SetSeq(seq)
		return wrapNode(enode.SignNull(&r, id))
	}

	if err := db.UpdateNode(unwrapNode(mk(1))); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	transport.updateRecord(unwrapNode(mk(5)))

	tab.verifyAndAdd(mk(1), 5)

	got := waitForTableNode(t, tab, id)
	if got.Seq() != 5 {
		t.Fatalf("table has seq %d, want re-fetched record seq 5", got.Seq())
	}
}

// TestRejectCachePerIPCap — node IDs are free to generate, so a single
// IP must not be able to fill the cache with (freshID, sameIP) entries
// and starve legitimate suppressions. The per-IP quota drops newcomers
// from a saturated IP while other IPs are unaffected.
func TestRejectCachePerIPCap(t *testing.T) {
	c := newTestRejectCache(time.Hour, 4096)
	c.perIPCap = 8

	for i := 0; i < c.perIPCap+10; i++ {
		c.Add(mkID(byte(i+1)), mkIP(1))
	}
	if got := c.Len(); got != c.perIPCap {
		t.Fatalf("one IP holds %d entries, want per-IP cap %d", got, c.perIPCap)
	}
	if c.Contains(mkID(byte(c.perIPCap+10)), mkIP(1)) {
		t.Fatal("newcomer admitted past a saturated per-IP quota")
	}
	// A different IP is unaffected by the first IP's saturation.
	c.Add(mkID(200), mkIP(2))
	if !c.Contains(mkID(200), mkIP(2)) {
		t.Fatal("entry from a fresh IP rejected while another IP is saturated")
	}
	// Refreshing an existing entry from the saturated IP still works.
	c.Add(mkID(1), mkIP(1))
	if !c.Contains(mkID(1), mkIP(1)) {
		t.Fatal("TTL refresh at per-IP cap failed")
	}
}

// TestRejectCachePerIPCapBucketsIPv6BySlash64 — the per-source quota
// treats a whole IPv6 /64 as one bucket: a single host routinely
// controls an entire routed /64, so per-full-address quotas would
// hand it unbounded distinct sources.
func TestRejectCachePerIPCapBucketsIPv6BySlash64(t *testing.T) {
	c := newTestRejectCache(time.Hour, 4096)
	c.perIPCap = 8

	v6 := func(prefixByte, host byte) net.IP {
		ip := net.ParseIP("2001:db8::")
		ip = append(net.IP(nil), ip...)
		ip[7] = prefixByte // vary inside byte 8 of the prefix
		ip[15] = host
		return ip
	}
	// Distinct host addresses inside one /64 share a single quota.
	for i := 0; i < c.perIPCap+5; i++ {
		c.Add(mkID(byte(i+1)), v6(1, byte(i+1)))
	}
	if got := c.Len(); got != c.perIPCap {
		t.Fatalf("one /64 holds %d entries, want per-source cap %d", got, c.perIPCap)
	}
	// A different /64 is its own bucket.
	c.Add(mkID(200), v6(2, 1))
	if !c.Contains(mkID(200), v6(2, 1)) {
		t.Fatal("entry from a different /64 rejected while another /64 is saturated")
	}
}

// TestRejectCachePerIPCapReleasesOnExpiry — expired entries release
// their per-IP quota slot (via lazy Contains deletion and the cap-
// boundary sweep), so a saturated IP can admit fresh entries again
// after its old ones expire.
func TestRejectCachePerIPCapReleasesOnExpiry(t *testing.T) {
	c := newTestRejectCache(5*time.Millisecond, 4096)
	c.perIPCap = 4

	for i := 0; i < c.perIPCap; i++ {
		c.Add(mkID(byte(i+1)), mkIP(1))
	}
	time.Sleep(20 * time.Millisecond)
	// The quota is saturated with expired entries; Add's sweep must
	// reclaim them and admit the newcomer.
	c.Add(mkID(99), mkIP(1))
	if !c.Contains(mkID(99), mkIP(1)) {
		t.Fatal("expired entries did not release the per-IP quota")
	}
}

// TestRejectCacheConcurrentAccess — Add/Contains from concurrent
// goroutines, for the race detector. The cache is reached from the
// async verify goroutines and lookup goroutines simultaneously.
func TestRejectCacheConcurrentAccess(t *testing.T) {
	c := newTestRejectCache(time.Minute, 128)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := mkID(byte(g*32 + i%32))
				ip := mkIP(byte(g + 1))
				c.Add(id, ip)
				c.Contains(id, ip)
				c.Len()
			}
		}(g)
	}
	wg.Wait()
}
