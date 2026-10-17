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

package addrman

import (
	"crypto/ecdsa"
	"net"
	"sync"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
)

// V2Candidate is a v2-native dial target emitted by V2Iter. Unlike
// NodeIter (which wraps KeyType=0x01 entries in enode.Node), the v2
// path has no persistent identity, so we expose the bare NetAddr.
// The Server's v2 dial goroutine reads from a channel of these and
// calls Server.DialV2 for each.
type V2Candidate struct {
	Addr NetAddr // routable (IP or Tor v3), port != 0
}

// IsSelfFunc reports whether addr matches the local node's own
// advertised endpoint. V2Iter calls it for each candidate before
// emit; matching entries are skipped so the v2 dialer doesn't
// burn cycles on a guarded self-dial. nil disables the check.
type IsSelfFunc func(addr NetAddr) bool

// V2Iter iterates addrman entries with KeyType=0x00 (v2-native). It
// draws candidates via Select() and skips non-v2 entries. Blocks
// between draws with exponential backoff when the table has no v2
// entries to offer, so callers can simply range-over Next().
type V2Iter struct {
	m          *AddrMan
	current    V2Candidate
	closed     chan struct{}
	closeOnce  sync.Once
	maxBackoff time.Duration
	isSelf     IsSelfFunc
	reachable  ReachableFunc
}

// ReachableFunc reports whether the local node has an outbound route
// to a BIP155 network. V2Iter skips candidates on networks it cannot
// dial, counting them against the same idle-backoff budget as any
// other skip — without that, an addrbook full of undialable entries
// (onion entries on a node with no Tor route) makes Next() return
// instantly forever and burns a core. nil treats every network as
// reachable.
type ReachableFunc func(NetID) bool

// NewV2Iter builds an iterator yielding only KeyType=0x00 entries.
// Parallels NewNodeIter. isSelf may be nil when the caller has no
// notion of self (e.g., unit tests against a bare AddrMan); when
// supplied, candidates that match are silently skipped.
// reachable may be nil, in which case every network is considered
// dialable.
func NewV2Iter(m *AddrMan, maxBackoff time.Duration, isSelf IsSelfFunc, reachable ReachableFunc) *V2Iter {
	if maxBackoff <= 0 {
		maxBackoff = 250 * time.Millisecond
	}
	return &V2Iter{
		m:          m,
		closed:     make(chan struct{}),
		maxBackoff: maxBackoff,
		isSelf:     isSelf,
		reachable:  reachable,
	}
}

// Next advances to the next v2 dial candidate. Blocks until one is
// available or Close is called.
func (it *V2Iter) Next() bool {
	backoff := 10 * time.Millisecond
	// Cap per-call Select spins. An addrman whose KeyType=0x00
	// cohort is empty (or fully IsTerrible) would otherwise turn
	// this loop into 100% CPU forever.
	const maxSkipsBeforeBackoff = 64
	skips := 0
	for {
		select {
		case <-it.closed:
			return false
		default:
		}
		addr, _, ok := it.m.Select(false, nil)
		if ok {
			info := it.m.Lookup(addr)
			if info != nil && info.KeyType == 0x00 && info.Addr.Valid() {
				// Valid() admits IP and Tor v3 candidates alike, so
				// candidates on networks this node cannot route are
				// skipped here — counting against the backoff budget,
				// because Select keeps offering them at full weight
				// (no dial means no Attempt, so LastTry never ages
				// them down) and a bare retry would spin.
				if it.reachable != nil && !it.reachable(addr.Network) {
					logging.Trace("pip6: V2Iter skip (unreachable network)", "addr", addr.String())
					skips++
					if skips >= maxSkipsBeforeBackoff {
						goto idleBackoff
					}
					continue
				}
				// Skip the local node's own endpoint. The
				// disc-protocol quorum can ingest our own
				// observed external IP into addrman; without
				// this gate the iterator re-emits it every
				// cycle and the v2 dial guard burns cycles
				// rejecting it. Cheap to test, cheap to skip.
				if it.isSelf != nil && it.isSelf(addr) {
					logging.Trace("pip6: V2Iter skip (self)", "addr", addr.String())
					skips++
					if skips >= maxSkipsBeforeBackoff {
						goto idleBackoff
					}
					continue
				}
				// Skip entries addrman already considers dead.
				// Without this gate a single stale KeyType=0x00
				// entry — persisted in addrbook.rlp from a prior
				// session or left over after a peer became
				// permanently unreachable — dominates Select
				// when it's the only KeyType=0x00 candidate,
				// producing an unbounded dial storm.
				if info.IsTerrible(time.Now()) {
					logging.Trace("pip6: V2Iter skip (terrible)",
						"addr", addr.String(),
						"attempts", info.Attempts,
						"lastSuccess", info.LastSuccess,
						"lastTry", info.LastTry)
					skips++
					if skips >= maxSkipsBeforeBackoff {
						goto idleBackoff
					}
					continue
				}
				logging.Trace("pip6: V2Iter emit",
					"addr", addr.String(),
					"keyType", info.KeyType,
					"attempts", info.Attempts,
					"lastTry", info.LastTry,
					"lastSuccess", info.LastSuccess,
					"inTried", info.InTried)
				it.current = V2Candidate{Addr: addr}
				return true
			}
			if info != nil {
				logging.Trace("pip6: V2Iter skip (wrong KeyType)",
					"addr", addr.String(),
					"keyType", info.KeyType,
					"inTried", info.InTried)
			}
			skips++
			if skips >= maxSkipsBeforeBackoff {
				goto idleBackoff
			}
			// Wrong KeyType — try again; Select will eventually
			// return a v2-native entry if one exists.
			continue
		}
	idleBackoff:
		skips = 0
		t := time.NewTimer(backoff)
		select {
		case <-it.closed:
			t.Stop()
			return false
		case <-t.C:
		}
		backoff *= 2
		if backoff > it.maxBackoff {
			backoff = it.maxBackoff
		}
	}
}

// Candidate returns the current v2 dial target. Only valid after a
// successful Next().
func (it *V2Iter) Candidate() V2Candidate { return it.current }

// Close halts the iterator. Safe to call multiple times.
func (it *V2Iter) Close() {
	it.closeOnce.Do(func() { close(it.closed) })
}

// NodeIter is an enode.Iterator view on an AddrMan. Next() calls
// AddrMan.Select() and reconstructs an *enode.Node using the stored
// NodeID+IP+Port.
//
// Entries with KeyType=0x00 (v2.0-native, no NodeID) are skipped —
// legacy RLPx dialing needs a pubkey. Once the BIP324-style handshake
// lands in Phase 2b, callers will be able to feed v2.0-native entries
// through a separate dialing path and this iterator will be
// complemented, not replaced.
//
// NodeIter yields entries indefinitely; Close() halts it. It's intended
// to sit alongside the discv4 / dnsdisc iterators in p2p/server.go's
// FairMix.
//
// Yields are paced to one per pace interval. The discv4 and dnsdisc
// iterators are paced by network round trips, and the dial scheduler
// relies on that: it reads candidates for as long as it has free dial
// slots and discards those it is already connected to or dialing. This
// iterator answers from memory, so on a network smaller than the dial
// slot count the slots never fill, and an unpaced Next would rebuild
// the same few enodes thousands of times per second.
type NodeIter struct {
	m          *AddrMan
	current    *enode.Node
	closed     chan struct{}
	closeOnce  sync.Once
	maxBackoff time.Duration
	pace       time.Duration
	lastYield  time.Time
}

// nodeIterPace is the minimum interval between NodeIter yields: the
// cadence of Bitcoin Core's ThreadOpenConnections loop, which sleeps
// 500ms between connection attempts (src/net.cpp).
const nodeIterPace = 500 * time.Millisecond

// NewNodeIter builds a NodeIter. maxBackoff caps the sleep between empty
// Select() results so an empty addrbook doesn't spin the caller — 250ms
// is a reasonable default; tests may want shorter.
func NewNodeIter(m *AddrMan, maxBackoff time.Duration) *NodeIter {
	if maxBackoff <= 0 {
		maxBackoff = 250 * time.Millisecond
	}
	return &NodeIter{
		m:          m,
		closed:     make(chan struct{}),
		maxBackoff: maxBackoff,
		pace:       nodeIterPace,
	}
}

// Next advances to the next dialable node. Blocks until one is found or
// Close() is called.
func (it *NodeIter) Next() bool {
	if !it.lastYield.IsZero() {
		if wait := it.pace - time.Since(it.lastYield); wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-it.closed:
				t.Stop()
				return false
			case <-t.C:
			}
		}
	}
	backoff := 10 * time.Millisecond
	// Cap per-call skip spins, mirroring V2Iter. On an addrbook
	// dominated by v2-native (KeyType=0x00) entries — the intended
	// 2.0 steady state — Select always returns ok but buildEnode
	// always fails, and a bare continue would peg a core forever.
	const maxSkipsBeforeBackoff = 64
	skips := 0
	for {
		select {
		case <-it.closed:
			return false
		default:
		}

		addr, _, ok := it.m.Select(false, nil)
		if ok {
			n, dialable := it.m.buildEnode(addr)
			if dialable {
				it.current = n
				it.lastYield = time.Now()
				return true
			}
			// Entry exists but can't be dialed via legacy RLPx (no
			// NodeID). Retry — Select may hand us a different entry
			// next time — but back off after a burst of consecutive
			// misses instead of spinning.
			skips++
			if skips < maxSkipsBeforeBackoff {
				continue
			}
		}

		// Empty table or skip burst — sleep with capped exponential
		// backoff.
		skips = 0
		t := time.NewTimer(backoff)
		select {
		case <-it.closed:
			t.Stop()
			return false
		case <-t.C:
		}
		backoff *= 2
		if backoff > it.maxBackoff {
			backoff = it.maxBackoff
		}
	}
}

// Node returns the current node. Only valid after a successful Next().
func (it *NodeIter) Node() *enode.Node {
	return it.current
}

// Close halts the iterator. Safe to call multiple times.
func (it *NodeIter) Close() {
	it.closeOnce.Do(func() { close(it.closed) })
}

// buildEnode reconstructs an *enode.Node from a stored NetAddr. Returns
// (node, true) only for IPv4/IPv6 entries with a 64-byte secp256k1
// NodeID — the other networks (Tor, I2P, CJDNS) are not dialable by the
// stock net.Dialer used by p2p/dial.go anyway.
func (m *AddrMan) buildEnode(addr NetAddr) (*enode.Node, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, info := m.findLocked(addr)
	if info == nil {
		return nil, false
	}
	if info.KeyType != 0x01 || len(info.NodeID) != 64 {
		return nil, false
	}
	var ip net.IP
	switch addr.Network {
	case NetIPv4:
		ip = net.IP(addr.Bytes()).To4()
	case NetIPv6:
		ip = net.IP(addr.Bytes())
	default:
		return nil, false
	}
	pub, err := unmarshalNodeID(info.NodeID)
	if err != nil {
		return nil, false
	}
	return enode.NewV4(pub, ip, int(addr.Port), int(addr.Port)), true
}

// unmarshalNodeID parses a 64-byte discv4-style NodeID into an
// ecdsa.PublicKey. Mirrors parsePubkey in p2p/enode/urlv4.go:158-167.
func unmarshalNodeID(id []byte) (*ecdsa.PublicKey, error) {
	buf := make([]byte, 65)
	buf[0] = 0x04
	copy(buf[1:], id)
	return crypto.UnmarshalPubkey(buf)
}
