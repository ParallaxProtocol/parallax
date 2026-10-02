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
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/netutil"
	"github.com/ParallaxProtocol/parallax/v2/util/mclock"
)

const (
	// This is the amount of time spent waiting in between redialing a certain node. The
	// limit is a bit higher than inboundThrottleTime to prevent failing dials in small
	// private networks.
	dialHistoryExpiration = inboundThrottleTime + 5*time.Second

	// Config for the "Looking for peers" message.
	dialStatsLogInterval = 10 * time.Second // printed at most this often
	dialStatsPeerLimit   = 3                // but not if more than this many dialed peers

	// Endpoint resolution is throttled with bounded backoff.
	initialResolveDelay = 60 * time.Second
	maxResolveDelay     = time.Hour

	// staticPoolResweepInterval bounds how long a static dial task can
	// stay stranded outside the pool when its checkDial rejection
	// clears without an event keyed to the task's ID — most notably a
	// ban or discouragement that expires silently. Every interval, all
	// out-of-pool static tasks are re-checked.
	staticPoolResweepInterval = time.Minute
)

// NodeDialer is used to connect to nodes in the network, typically by using
// an underlying net.Dialer but also using net.Pipe in tests.
type NodeDialer interface {
	Dial(context.Context, *enode.Node) (net.Conn, error)
}

type nodeResolver interface {
	Resolve(*enode.Node) *enode.Node
}

func nodeAddr(n *enode.Node) net.Addr {
	return &net.TCPAddr{IP: n.IP(), Port: n.TCP()}
}

// checkDial errors:
var (
	errSelf                  = errors.New("is self")
	errAlreadyDialing        = errors.New("already dialing")
	errAlreadyConnected      = errors.New("already connected")
	errInboundProgress       = errors.New("inbound handshake in progress")
	errRecentlyDialed        = errors.New("recently dialed")
	errNetRestrict           = errors.New("not contained in netrestrict list")
	errNoPort                = errors.New("node does not provide TCP port")
	errOutboundGroupOccupied = errors.New("outbound network group already occupied")
	errBanned                = errors.New("address banned")
	errDiscouraged           = errors.New("address discouraged")
)

// dialer creates outbound connections and submits them into Server.
// Two types of peer connections can be created:
//
//   - static dials are pre-configured connections. The dialer attempts
//     keep these nodes connected at all times.
//
//   - dynamic dials are created from node discovery results. The dialer
//     continuously reads candidate nodes from its input iterator and attempts
//     to create peer connections to nodes arriving through the iterator.
type dialScheduler struct {
	dialConfig
	setupFunc   dialSetupFunc
	wg          sync.WaitGroup
	cancel      context.CancelFunc
	ctx         context.Context
	nodesIn     chan *enode.Node
	doneCh      chan *dialTask
	addStaticCh chan *enode.Node
	remStaticCh chan *enode.Node
	addPeerCh   chan *conn
	remPeerCh   chan *conn

	// addInProgressCh / remInProgressCh signal that an inbound conn
	// is between encryption-handshake-done and addPeer (the protocol-
	// handshake window). The dialer rejects outbound dials to those
	// IDs to avoid the symmetric-handshake race that ends with one
	// side eating a DiscAlreadyConnected after wasting a handshake.
	// PIP-0006 §Phase 6 / server.go's "track in-progress inbound node
	// IDs (pre-Peer)" TODO.
	addInProgressCh chan enode.ID
	remInProgressCh chan enode.ID

	// probeCh is a test-only synchronous probe of inboundProgress
	// state. The loop handles it inline, so the result reflects the
	// state at the moment the request was processed and the read of
	// d.inboundProgress is loop-local (no race).
	probeCh chan probeCheckDialReq

	// Everything below here belongs to loop and
	// should only be accessed by code on the loop goroutine.
	dialing   map[enode.ID]*dialTask // active tasks
	peers     map[enode.ID]struct{}  // all connected peers
	dialPeers int                    // current number of dialed peers

	// inboundProgress is the run-loop's view of inbound conns
	// currently between checkpointPostHandshake and the moment they
	// either land in d.peers (success) or are dropped (failure).
	// Refcounted: a malicious peer that opens two inbound TCP sockets
	// claiming the same NodeID would otherwise underflow the count
	// when the first finishes. Bitcoin's net.cpp doesn't see this
	// because IDs are tied to TLS-handshake outcome and a given peer
	// can't easily duplicate; v2-handshake's ephemeral-key derived ID
	// is harder to duplicate but the refcount is cheap insurance.
	inboundProgress map[enode.ID]int

	// blockRelayDialed counts the subset of dialPeers that occupy
	// block-relay-only slots (Bitcoin Core's
	// MAX_BLOCK_RELAY_ONLY_CONNECTIONS, src/net.h:73). Updated at
	// peerAdded / peerRemoved time when c.is(blockRelayConn).
	blockRelayDialed int

	// dialingBlockRelay counts the subset of in-flight dials
	// (d.dialing) that were launched as block-relay-only. Combined
	// with blockRelayDialed it gives the picker the "committed"
	// BR-bucket size, so a burst of four concurrent picks doesn't
	// all classify as full-relay just because no peer has reached
	// addPeerCh yet.
	dialingBlockRelay int

	// outboundGroups counts how many currently-dialed peers occupy
	// each network group (Bitcoin Core IPv4 /16, IPv6 /32). Used by
	// checkDial to enforce one-outbound-per-group anti-eclipse
	// (mirrors src/net.cpp:2647-2688). Keyed by string(NetworkGroup).
	// Updated at peerAdded / peerRemoved time alongside dialPeers.
	outboundGroups map[string]int

	// dialingGroups counts the network groups of in-flight dials
	// (d.dialing), mirroring dialingBlockRelay: outboundGroups only
	// updates when a peer attaches, so without this a burst of
	// same-group candidates discovered in one round would all pass
	// checkDial before any of them connects — defeating the
	// one-per-group rule exactly in the startup window it exists
	// for. Bitcoin Core is immune structurally because
	// ThreadOpenConnections dials one candidate at a time. Static
	// dials are counted too: they are exempt from the check but
	// occupy groups against dynamic dials, same as attached static
	// peers in outboundGroups.
	dialingGroups map[string]int

	// The static map tracks all static dial tasks. The subset of usable static dial tasks
	// (i.e. those passing checkDial) is kept in staticPool. The scheduler prefers
	// launching random static tasks from the pool over launching dynamic dials from the
	// iterator.
	static     map[enode.ID]*dialTask
	staticPool []*dialTask

	// The dial history keeps recently dialed nodes. Members of history are not dialed.
	history          expHeap
	historyTimer     mclock.Timer
	historyTimerTime mclock.AbsTime

	// for logStats
	lastStatsLog     mclock.AbsTime
	doneSinceLastLog int
}

// dialSetupFunc hands a freshly dialed conn to the Server. The
// NetAddr is the address the dial was aimed at: under a proxy the
// conn's RemoteAddr is the proxy, so everything downstream that
// identifies a peer by address (dedup, netgroups, addrman feedback)
// needs the target instead.
type dialSetupFunc func(net.Conn, connFlag, *enode.Node, addrman.NetAddr) error

type dialConfig struct {
	self           enode.ID         // our own ID
	maxDialPeers   int              // maximum number of dialed peers
	maxActiveDials int              // maximum number of active dials
	netRestrict    *netutil.Netlist // IP netrestrict list, disabled if nil
	resolver       nodeResolver
	dialer         NodeDialer
	log            logging.Logger
	clock          mclock.Clock
	rand           *mrand.Rand

	// v2Predicate reports whether the iterator-yielded node should be
	// dialed via the v2 BIP324 path instead of v1 RLPx. v2Dial is the
	// callback invoked for such nodes; both are nil for unit tests
	// that don't want the v2 branch.
	v2Predicate func(*enode.Node) bool
	v2Dial      func(addrman.NetAddr) error
	// reachable gates automatic dials on --onlynet. nil disables.
	reachable func(addrman.NetID) bool
	// proxied reports whether dials to a network are routed through a
	// SOCKS5 proxy, so the conn can be flagged accordingly. nil
	// disables (no proxy configured).
	proxied func(addrman.NetID) bool

	// maxBlockRelay is the count of block-relay-only outbound slots
	// reserved within maxDialPeers. Bitcoin Core defaults to 2
	// (MAX_BLOCK_RELAY_ONLY_CONNECTIONS, src/net.h:73). Zero disables
	// the block-relay-only bucket entirely — all dynamic dials become
	// full-relay regardless of slot pressure. Static dials never
	// consume from this bucket.
	maxBlockRelay int

	// isBanned reports whether an IP is under an operator ban. When
	// set, checkDial refuses to dial such nodes, mirroring Bitcoin
	// Core's outbound ban gate (CConnman::OpenNetworkConnection).
	// Nil disables the check (unit tests, no ban list configured).
	isBanned func(net.IP) bool

	// isDiscouraged reports whether an IP is in the automatic
	// misbehavior discourage filter. Unlike a ban it does not block
	// static dials: Core's manual connections bypass discouragement,
	// and the filter has no clearing RPC, so honoring it on statics
	// would strand an operator-chosen peering until restart. Nil
	// disables the check.
	isDiscouraged func(net.IP) bool
}

func (cfg dialConfig) withDefaults() dialConfig {
	if cfg.maxActiveDials == 0 {
		cfg.maxActiveDials = defaultMaxPendingPeers
	}
	if cfg.log == nil {
		cfg.log = logging.Root()
	}
	if cfg.clock == nil {
		cfg.clock = mclock.System{}
	}
	if cfg.rand == nil {
		seedb := make([]byte, 8)
		crand.Read(seedb)
		seed := int64(binary.BigEndian.Uint64(seedb))
		cfg.rand = mrand.New(mrand.NewSource(seed))
	}
	return cfg
}

func newDialScheduler(config dialConfig, it enode.Iterator, setupFunc dialSetupFunc) *dialScheduler {
	d := &dialScheduler{
		dialConfig:      config.withDefaults(),
		setupFunc:       setupFunc,
		dialing:         make(map[enode.ID]*dialTask),
		outboundGroups:  make(map[string]int),
		dialingGroups:   make(map[string]int),
		static:          make(map[enode.ID]*dialTask),
		peers:           make(map[enode.ID]struct{}),
		inboundProgress: make(map[enode.ID]int),
		doneCh:          make(chan *dialTask),
		nodesIn:         make(chan *enode.Node),
		addStaticCh:     make(chan *enode.Node),
		remStaticCh:     make(chan *enode.Node),
		addPeerCh:       make(chan *conn),
		remPeerCh:       make(chan *conn),
		addInProgressCh: make(chan enode.ID),
		remInProgressCh: make(chan enode.ID),
		probeCh:         make(chan probeCheckDialReq),
	}
	d.lastStatsLog = d.clock.Now()
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.wg.Add(2)
	go d.readNodes(it)
	go d.loop(it)
	return d
}

// stop shuts down the dialer, canceling all current dial tasks.
func (d *dialScheduler) stop() {
	d.cancel()
	d.wg.Wait()
}

// addStatic adds a static dial candidate.
func (d *dialScheduler) addStatic(n *enode.Node) {
	select {
	case d.addStaticCh <- n:
	case <-d.ctx.Done():
	}
}

// removeStatic removes a static dial candidate.
func (d *dialScheduler) removeStatic(n *enode.Node) {
	select {
	case d.remStaticCh <- n:
	case <-d.ctx.Done():
	}
}

// peerAdded updates the peer set.
func (d *dialScheduler) peerAdded(c *conn) {
	select {
	case d.addPeerCh <- c:
	case <-d.ctx.Done():
	}
}

// peerRemoved updates the peer set.
func (d *dialScheduler) peerRemoved(c *conn) {
	select {
	case d.remPeerCh <- c:
	case <-d.ctx.Done():
	}
}

// inboundProgressBegin marks an inbound conn's NodeID as being mid-
// handshake. checkDial rejects outbound dials to that ID until the
// matching inboundProgressEnd. Synchronous: returns once the loop
// has applied the change, so callers (setupConn on accept goroutines)
// see a consistent inboundProgress state by the time the next dial
// candidate is considered.
func (d *dialScheduler) inboundProgressBegin(id enode.ID) {
	select {
	case d.addInProgressCh <- id:
	case <-d.ctx.Done():
	}
}

// inboundProgressEnd is the matching unregister. Always paired with
// an earlier Begin via defer in setupConn so it fires on every exit
// path (success, post-handshake-fail, proto-handshake-fail).
func (d *dialScheduler) inboundProgressEnd(id enode.ID) {
	select {
	case d.remInProgressCh <- id:
	case <-d.ctx.Done():
	}
}

// probeCheckDialReq is the message a probeCheckDial sends into the
// loop: a node to inspect plus a reply channel for the result.
type probeCheckDialReq struct {
	n   *enode.Node
	out chan error
}

// probeCheckDial runs a checkDial against d's loop-owned state and
// returns the same error a real iterator pick would see. Test-only.
// The probe runs ON the loop goroutine via probeCh so the read of
// inboundProgress can't race with any in-flight begin/end / addPeer
// updates.
func (d *dialScheduler) probeCheckDial(n *enode.Node) error {
	out := make(chan error, 1)
	select {
	case d.probeCh <- probeCheckDialReq{n: n, out: out}:
	case <-d.ctx.Done():
		return d.ctx.Err()
	}
	select {
	case err := <-out:
		return err
	case <-d.ctx.Done():
		return d.ctx.Err()
	}
}

// loop is the main loop of the dialer.
func (d *dialScheduler) loop(it enode.Iterator) {
	var (
		nodesCh      chan *enode.Node
		historyExp   = make(chan struct{}, 1)
		resweepCh    = make(chan struct{}, 1)
		resweepTimer mclock.Timer
	)

loop:
	for {
		// Launch new dials if slots are available.
		slots := d.freeDialSlots()
		slots -= d.startStaticDials(slots)
		if slots > 0 {
			nodesCh = d.nodesIn
		} else {
			nodesCh = nil
		}
		d.rearmHistoryTimer(historyExp)
		if resweepTimer == nil && d.needsStaticResweep() {
			resweepTimer = d.clock.AfterFunc(staticPoolResweepInterval, func() {
				select {
				case resweepCh <- struct{}{}:
				default:
				}
			})
		}
		d.logStats()

		select {
		case node := <-nodesCh:
			if err := d.checkDial(node, dynDialedConn); err != nil {
				d.log.Trace("Discarding dial candidate", "id", node.ID(), "ip", node.IP(), "reason", err)
			} else if d.v2Predicate != nil && d.v2Dial != nil && d.v2Predicate(node) {
				// Peer advertises v2-transport in its ENR — bypass
				// v1 RLPx entirely and hand off to the v2 dial path.
				// The handoff runs as a regular dial task so it
				// consumes a dial slot, charges dialingGroups, and is
				// drained on shutdown like any v1 dial. Without that,
				// a burst of v2-ENR candidates would fan out unbounded
				// goroutines, two same-group candidates could both
				// pass checkDial, and the dial goroutine could touch
				// the addrbook after Stop's addrbook.Save. The task
				// uses plain dynDialedConn: block-relay bucket choice
				// for v2 dials is made inside dialV2WithFlags, not by
				// the v1 scheduler's pick.
				task := newDialTask(node, dynDialedConn)
				task.v2 = true
				d.startDial(task)
			} else {
				d.startDial(newDialTask(node, d.pickDynDialFlags()))
			}

		case task := <-d.doneCh:
			id := task.dest().ID()
			if _, ok := d.dialing[id]; ok {
				if task.flags&blockRelayConn != 0 && d.dialingBlockRelay > 0 {
					d.dialingBlockRelay--
				}
				// Decrement the group recorded at startDial time, not
				// the group of the current task.dest: resolve() swaps
				// t.dest mid-flight, and a static node that moved to a
				// different /16 would otherwise strand the old group's
				// count forever (permanently blacking out dynamic
				// dials to that group) while decrementing a group that
				// was never incremented.
				if g := task.dialGroup; g != "" {
					if d.dialingGroups[g] <= 1 {
						delete(d.dialingGroups, g)
					} else {
						d.dialingGroups[g]--
					}
				}
			}
			delete(d.dialing, id)
			d.updateStaticPool(id)
			d.doneSinceLastLog++

		case c := <-d.addPeerCh:
			// Feeler / addrfetch probes are short-lived and must not
			// consume an outbound slot or a network-group slot
			// (Bitcoin Core excludes ConnectionType::FEELER from
			// outbound counts). They still land in d.peers below so
			// checkDial's already-connected guard covers them.
			if (c.is(dynDialedConn) || c.is(staticDialedConn)) && !c.is(feelerConn) {
				d.dialPeers++
				if c.is(blockRelayConn) {
					d.blockRelayDialed++
				}
				if g := outboundGroupKey(c); g != "" {
					d.outboundGroups[g]++
				}
			}
			id := c.node.ID()
			d.peers[id] = struct{}{}
			// Remove from static pool because the node is now connected.
			task := d.static[id]
			if task != nil && task.staticPoolIndex >= 0 {
				d.removeFromStaticPool(task.staticPoolIndex)
			}
			// TODO: cancel dials to connected peers

		case c := <-d.remPeerCh:
			// Mirror the feeler exclusion from addPeerCh so the
			// counters stay balanced.
			if (c.is(dynDialedConn) || c.is(staticDialedConn)) && !c.is(feelerConn) {
				d.dialPeers--
				if c.is(blockRelayConn) && d.blockRelayDialed > 0 {
					d.blockRelayDialed--
				}
				if g := outboundGroupKey(c); g != "" {
					if d.outboundGroups[g] <= 1 {
						delete(d.outboundGroups, g)
					} else {
						d.outboundGroups[g]--
					}
				}
			}
			delete(d.peers, c.node.ID())
			d.updateStaticPool(c.node.ID())

		case id := <-d.addInProgressCh:
			d.inboundProgress[id]++

		case id := <-d.remInProgressCh:
			if n := d.inboundProgress[id]; n > 1 {
				d.inboundProgress[id] = n - 1
			} else {
				delete(d.inboundProgress, id)
			}
			// A static task for this ID may have been rejected with
			// errInboundProgress while the handshake was pending. If
			// the inbound conn failed (it never became a peer, so no
			// remPeerCh event will ever fire for it), this is the
			// only signal that the ID is dialable again.
			d.updateStaticPool(id)

		case req := <-d.probeCh:
			req.out <- d.checkDial(req.n, dynDialedConn)

		case node := <-d.addStaticCh:
			id := node.ID()
			_, exists := d.static[id]
			d.log.Trace("Adding static node", "id", id, "ip", node.IP(), "added", !exists)
			if exists {
				continue loop
			}
			task := newDialTask(node, staticDialedConn)
			d.static[id] = task
			if d.checkDial(node, staticDialedConn) == nil {
				d.addToStaticPool(task)
			}

		case node := <-d.remStaticCh:
			id := node.ID()
			task := d.static[id]
			d.log.Trace("Removing static node", "id", id, "ok", task != nil)
			if task != nil {
				delete(d.static, id)
				if task.staticPoolIndex >= 0 {
					d.removeFromStaticPool(task.staticPoolIndex)
				}
			}

		case <-historyExp:
			d.expireHistory()

		case <-resweepCh:
			resweepTimer = nil
			for id := range d.static {
				d.updateStaticPool(id)
			}

		case <-d.ctx.Done():
			it.Close()
			break loop
		}
	}

	if resweepTimer != nil {
		resweepTimer.Stop()
	}
	d.stopHistoryTimer(historyExp)
	for range d.dialing {
		<-d.doneCh
	}
	d.wg.Done()
}

// readNodes runs in its own goroutine and delivers nodes from
// the input iterator to the nodesIn channel.
func (d *dialScheduler) readNodes(it enode.Iterator) {
	defer d.wg.Done()

	for it.Next() {
		select {
		case d.nodesIn <- it.Node():
		case <-d.ctx.Done():
		}
	}
}

// logStats prints dialer statistics to the log. The message is suppressed when enough
// peers are connected because users should only see it while their client is starting up
// or comes back online.
func (d *dialScheduler) logStats() {
	now := d.clock.Now()
	if d.lastStatsLog.Add(dialStatsLogInterval) > now {
		return
	}
	if d.dialPeers < dialStatsPeerLimit && d.dialPeers < d.maxDialPeers {
		d.log.Info("Looking for peers", "peercount", len(d.peers), "tried", d.doneSinceLastLog, "static", len(d.static))
	}
	d.doneSinceLastLog = 0
	d.lastStatsLog = now
}

// rearmHistoryTimer configures d.historyTimer to fire when the
// next item in d.history expires.
func (d *dialScheduler) rearmHistoryTimer(ch chan struct{}) {
	if len(d.history) == 0 || d.historyTimerTime == d.history.nextExpiry() {
		return
	}
	d.stopHistoryTimer(ch)
	d.historyTimerTime = d.history.nextExpiry()
	timeout := time.Duration(d.historyTimerTime - d.clock.Now())
	d.historyTimer = d.clock.AfterFunc(timeout, func() { ch <- struct{}{} })
}

// stopHistoryTimer stops the timer and drains the channel it sends on.
func (d *dialScheduler) stopHistoryTimer(ch chan struct{}) {
	if d.historyTimer != nil && !d.historyTimer.Stop() {
		<-ch
	}
}

// expireHistory removes expired items from d.history.
func (d *dialScheduler) expireHistory() {
	d.historyTimer.Stop()
	d.historyTimer = nil
	d.historyTimerTime = 0
	d.history.expire(d.clock.Now(), func(hkey string) {
		var id enode.ID
		copy(id[:], hkey)
		d.updateStaticPool(id)
	})
}

// freeDialSlots returns the number of free dial slots. The result can be negative
// when peers are connected while their task is still running.
func (d *dialScheduler) freeDialSlots() int {
	slots := (d.maxDialPeers - d.dialPeers) * 2
	if slots > d.maxActiveDials {
		slots = d.maxActiveDials
	}
	free := slots - len(d.dialing)
	return free
}

// checkDial returns an error if node n should not be dialed with the
// given conn flags.
func (d *dialScheduler) checkDial(n *enode.Node, flags connFlag) error {
	if n.ID() == d.self {
		return errSelf
	}
	if n.IP() != nil && n.TCP() == 0 {
		// This check can trigger if a non-TCP node is found
		// by discovery. If there is no IP, the node is a static
		// node and the actual endpoint will be resolved later in dialTask.
		return errNoPort
	}
	if _, ok := d.dialing[n.ID()]; ok {
		return errAlreadyDialing
	}
	if _, ok := d.peers[n.ID()]; ok {
		return errAlreadyConnected
	}
	// Reject if an inbound conn for the same NodeID is still mid-
	// handshake. Closes the symmetric-dial race that would otherwise
	// have us spend a full encryption + protocol handshake just to
	// hit DiscAlreadyConnected at addPeerChecks. PIP-0006 review A6.
	if d.inboundProgress[n.ID()] > 0 {
		return errInboundProgress
	}
	if d.netRestrict != nil && !d.netRestrict.Contains(n.IP()) {
		return errNetRestrict
	}
	// --onlynet gates automatic dials only; static (operator-chosen)
	// endpoints are exempt, as in Core.
	if flags&staticDialedConn == 0 && d.reachable != nil && n.IP() != nil {
		na, ok := netAddrFromTCP(&net.TCPAddr{IP: n.IP(), Port: n.TCP()})
		if ok && !d.reachable(na.Network) {
			return errUnreachableNetwork
		}
	}
	// Never dial a banned address (Bitcoin Core
	// CConnman::OpenNetworkConnection). Applies to every scheduler
	// dial including static ones — an operator ban must not be
	// worked around by an addnode entry.
	if d.isBanned != nil && n.IP() != nil && d.isBanned(n.IP()) {
		return errBanned
	}
	// Discouragement is softer than an operator ban: it is stamped
	// automatically on misbehavior and only clears on restart or
	// filter rotation. Static dials ignore it, as Core's manual
	// connections do — the operator explicitly chose the endpoint,
	// and a shared-IP neighbor's misbehavior must not strand it.
	if flags&staticDialedConn == 0 && d.isDiscouraged != nil && n.IP() != nil && d.isDiscouraged(n.IP()) {
		return errDiscouraged
	}
	if d.history.contains(string(n.ID().Bytes())) {
		return errRecentlyDialed
	}
	// Anti-eclipse: refuse to add a second outbound peer in the
	// same /16 (IPv4) or /32 (IPv6) network group. Mirrors Bitcoin
	// Core's outbound_ipv46_peer_netgroups guard in
	// src/net.cpp:2685. Static dials are exempt, as Core's manual
	// connections are: the operator chose those endpoints, group
	// concentration among them carries no eclipse signal, and
	// applying the rule would permanently strand static nodes in
	// clustered deployments (every docker-bridge peer shares
	// 172.17.0.0/16). Only iterator-sourced dynamic dials are
	// group-limited.
	if flags&staticDialedConn == 0 {
		if g := nodeNetworkGroupKey(n); g != "" {
			// Attached peers AND in-flight dials both occupy the
			// group: a successful dial passes through peerAdded
			// (outboundGroups) before its task reaches doneCh
			// (dialingGroups), so the combined check never sees a
			// gap between the two.
			if d.outboundGroups[g] > 0 || d.dialingGroups[g] > 0 {
				return errOutboundGroupOccupied
			}
		}
	}
	return nil
}

// pickDynDialFlags chooses the connFlag set for a fresh dynamic
// outbound dial. Returns plain dynDialedConn for full-relay slots
// (the default) or dynDialedConn|blockRelayConn when the block-
// relay-only bucket has room and full-relay is at target capacity.
//
// Bitcoin Core's order in ThreadOpenConnections (src/net.cpp:2715-
// 2765) prioritizes full-relay first, then block-relay, then
// feeler / extra-block-relay. We mirror the FR-then-BR step;
// feeler / anchor live on a separate goroutine (phase 4 follow-up
// commits) so they never reach this picker.
//
// "Committed" counts include in-flight dials (d.dialing /
// d.dialingBlockRelay) so a burst of concurrent picks doesn't all
// land in the same bucket before any peer reaches addPeerCh.
//
// Static dials never reach this function — staticDialedConn dials
// take a fixed flag set in addStatic / startStaticDials.
func (d *dialScheduler) pickDynDialFlags() connFlag {
	if d.maxBlockRelay <= 0 {
		return dynDialedConn
	}
	committedBR := d.blockRelayDialed + d.dialingBlockRelay
	if committedBR >= d.maxBlockRelay {
		return dynDialedConn
	}
	fullRelayTarget := d.maxDialPeers - d.maxBlockRelay
	if fullRelayTarget < 0 {
		fullRelayTarget = 0
	}
	committedFR := (d.dialPeers - d.blockRelayDialed) + (len(d.dialing) - d.dialingBlockRelay)
	if committedFR < fullRelayTarget {
		return dynDialedConn
	}
	return dynDialedConn | blockRelayConn
}

// outboundGroupKey returns the network-group key used to bucket
// outbound peers for diversity accounting. Returns the empty
// string when the conn isn't an outbound dial (inbound peers
// don't count), the remote address can't be parsed, or the
// address is exempt from group-diversity (loopback / link-local).
//
// Falls back to the conn's enode if the kernel-level fd doesn't
// expose a TCP RemoteAddr (synthetic test conns). Never panics on
// nil fd.
func outboundGroupKey(c *conn) string {
	if !c.is(dynDialedConn) && !c.is(staticDialedConn) {
		return ""
	}
	// The dialed target outranks the socket address: proxied conns'
	// RemoteAddr is the SOCKS5 proxy, onion targets have no IP.
	if t := c.dialTarget(); t.Network != 0 {
		return groupKeyForNetAddr(t)
	}
	if c.fd != nil {
		if pra, ok := c.fd.RemoteAddr().(*net.TCPAddr); ok {
			return ipNetworkGroupKey(pra.IP)
		}
	}
	if c.node != nil {
		if ip := c.node.IP(); ip != nil {
			return ipNetworkGroupKey(ip)
		}
	}
	return ""
}

// ipNetworkGroupKey applies the loopback / link-local exemption
// shared by outboundGroupKey and nodeNetworkGroupKey.
func ipNetworkGroupKey(ip net.IP) string {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return ""
	}
	return string(NetworkGroupForIP(ip))
}

// nodeNetworkGroupKey computes the same key from an enode.Node so
// checkDial can compare a candidate against the live set without
// having a *conn yet. Returns the empty string only for loopback and
// link-local addresses — private RFC1918 ranges are NOT exempt and
// group normally (Bitcoin group-limits them too; test deployments on
// one LAN share a single group and rely on the static-dial
// exemption instead).
//
// Mirrors Bitcoin Core's m_is_local exemption (eviction.cpp:115).
func nodeNetworkGroupKey(n *enode.Node) string {
	ip := n.IP()
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return ""
	}
	return string(NetworkGroupForIP(ip))
}

// startStaticDials starts n static dial tasks.
func (d *dialScheduler) startStaticDials(n int) (started int) {
	for started = 0; started < n && len(d.staticPool) > 0; started++ {
		idx := d.rand.Intn(len(d.staticPool))
		task := d.staticPool[idx]
		d.startDial(task)
		d.removeFromStaticPool(idx)
	}
	return started
}

// needsStaticResweep reports whether any static task is stranded: out
// of the pool while neither dialing nor connected. Such a task is
// waiting on a checkDial rejection to clear, and some rejections
// (ban expiry) produce no event — the periodic resweep is their only
// way back in.
func (d *dialScheduler) needsStaticResweep() bool {
	for id, task := range d.static {
		if task.staticPoolIndex >= 0 {
			continue
		}
		if _, ok := d.dialing[id]; ok {
			continue
		}
		if _, ok := d.peers[id]; ok {
			continue
		}
		return true
	}
	return false
}

// updateStaticPool attempts to move the given static dial back into staticPool.
func (d *dialScheduler) updateStaticPool(id enode.ID) {
	task, ok := d.static[id]
	if ok && task.staticPoolIndex < 0 && d.checkDial(task.dest(), task.flags) == nil {
		d.addToStaticPool(task)
	}
}

func (d *dialScheduler) addToStaticPool(task *dialTask) {
	if task.staticPoolIndex >= 0 {
		panic("attempt to add task to staticPool twice")
	}
	d.staticPool = append(d.staticPool, task)
	task.staticPoolIndex = len(d.staticPool) - 1
}

// removeFromStaticPool removes the task at idx from staticPool. It does that by moving the
// current last element of the pool to idx and then shortening the pool by one.
func (d *dialScheduler) removeFromStaticPool(idx int) {
	task := d.staticPool[idx]
	end := len(d.staticPool) - 1
	d.staticPool[idx] = d.staticPool[end]
	d.staticPool[idx].staticPoolIndex = idx
	d.staticPool[end] = nil
	d.staticPool = d.staticPool[:end]
	task.staticPoolIndex = -1
}

// startDial runs the given dial task in a separate goroutine.
func (d *dialScheduler) startDial(task *dialTask) {
	node := task.dest()
	d.log.Trace("Starting p2p dial", "id", node.ID(), "ip", node.IP(), "flag", task.flags)
	hkey := string(node.ID().Bytes())
	d.history.add(hkey, d.clock.Now().Add(dialHistoryExpiration))
	d.dialing[node.ID()] = task
	if task.flags&blockRelayConn != 0 {
		d.dialingBlockRelay++
	}
	// Record the group charged for this dial on the task itself so
	// the doneCh decrement targets the same key even if resolve()
	// replaces task.dest with an endpoint in a different group.
	task.dialGroup = nodeNetworkGroupKey(node)
	if task.dialGroup != "" {
		d.dialingGroups[task.dialGroup]++
	}
	go func() {
		task.run(d)
		d.doneCh <- task
	}()
}

// A dialTask generated for each node that is dialed.
type dialTask struct {
	staticPoolIndex int
	flags           connFlag

	// dialGroup is the network-group key charged to dialingGroups
	// when the task launched. Written by startDial before the task
	// goroutine starts and read by the doneCh handler after it
	// finishes, so it needs no synchronization. Kept separate from
	// dest because resolve() may replace dest with an endpoint in a
	// different group mid-flight.
	dialGroup string

	// v2 routes the task through the scheduler's v2Dial callback
	// (BIP324 transport) instead of the v1 RLPx dial. v2 tasks never
	// resolve or redial: the v2 path has its own cooldown and
	// failure accounting.
	v2 bool

	// These fields are private to the task and should not be
	// accessed by dialScheduler while the task is running.
	destPtr      atomic.Pointer[enode.Node]
	lastResolved mclock.AbsTime
	resolveDelay time.Duration
}

func newDialTask(dest *enode.Node, flags connFlag) *dialTask {
	t := &dialTask{flags: flags, staticPoolIndex: -1}
	t.destPtr.Store(dest)
	return t
}

type dialError struct {
	error
}

func (t *dialTask) dest() *enode.Node {
	return t.destPtr.Load()
}

func (t *dialTask) run(d *dialScheduler) {
	if t.v2 {
		node := t.dest()
		na, ok := netAddrFromTCP(&net.TCPAddr{IP: node.IP(), Port: node.TCP()})
		if !ok {
			return
		}
		if err := d.v2Dial(na); err != nil {
			d.log.Trace("v2 dial (from v1 scheduler) failed", "addr", na, "err", err)
		}
		return
	}
	if t.needResolve() && !t.resolve(d) {
		return
	}

	err := t.dial(d, t.dest())
	if err != nil {
		// For static nodes, resolve one more time if dialing fails.
		if _, ok := err.(*dialError); ok && t.flags&staticDialedConn != 0 {
			if t.resolve(d) {
				t.dial(d, t.dest())
			}
		}
	}
}

func (t *dialTask) needResolve() bool {
	return t.flags&staticDialedConn != 0 && t.dest().IP() == nil
}

// resolve attempts to find the current endpoint for the destination
// using discovery.
//
// Resolve operations are throttled with backoff to avoid flooding the
// discovery network with useless queries for nodes that don't exist.
// The backoff delay resets when the node is found.
func (t *dialTask) resolve(d *dialScheduler) bool {
	if d.resolver == nil {
		return false
	}
	if t.resolveDelay == 0 {
		t.resolveDelay = initialResolveDelay
	}
	if t.lastResolved > 0 && time.Duration(d.clock.Now()-t.lastResolved) < t.resolveDelay {
		return false
	}
	node := t.dest()
	resolved := d.resolver.Resolve(node)
	t.lastResolved = d.clock.Now()
	if resolved == nil {
		t.resolveDelay *= 2
		if t.resolveDelay > maxResolveDelay {
			t.resolveDelay = maxResolveDelay
		}
		d.log.Debug("Resolving node failed", "id", node.ID(), "newdelay", t.resolveDelay)
		return false
	}
	// The node was found.
	t.resolveDelay = initialResolveDelay
	t.destPtr.Store(resolved)
	d.log.Debug("Resolved node", "id", resolved.ID(), "addr", &net.TCPAddr{IP: resolved.IP(), Port: resolved.TCP()})
	return true
}

// dial performs the actual connection attempt.
func (t *dialTask) dial(d *dialScheduler, dest *enode.Node) error {
	fd, err := d.dialer.Dial(d.ctx, dest)
	if err != nil {
		d.log.Trace("Dial error", "id", dest.ID(), "addr", nodeAddr(dest), "conn", t.flags, "err", cleanupDialErr(err))
		return &dialError{err}
	}
	mfd := newMeteredConn(fd, false, &net.TCPAddr{IP: dest.IP(), Port: dest.TCP()})
	// Legacy dials run through the same proxy-aware connector as v2
	// ones, so they must carry the same identity: the dial target and,
	// when routed through a proxy, the proxied flag. Without them a
	// proxied v1 peer is identified by the proxy's address — every
	// such peer looks like the same endpoint to the dedup, netgroup
	// and addrman paths.
	flags := t.flags
	target, ok := netAddrFromTCP(&net.TCPAddr{IP: dest.IP(), Port: dest.TCP()})
	if !ok {
		target = addrman.NetAddr{}
	} else if d.proxied != nil && d.proxied(target.Network) {
		flags |= proxiedConn
	}
	return d.setupFunc(mfd, flags, dest, target)
}

func (t *dialTask) String() string {
	node := t.dest()
	id := node.ID()
	return fmt.Sprintf("%v %x %v:%d", t.flags, id[:8], node.IP(), node.TCP())
}

func cleanupDialErr(err error) error {
	if netErr, ok := err.(*net.OpError); ok && netErr.Op == "dial" {
		return netErr.Err
	}
	return err
}
