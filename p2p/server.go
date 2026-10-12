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

// Package p2p implements the Parallax p2p network protocols.
package p2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/banman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/discover"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enr"
	"github.com/ParallaxProtocol/parallax/v2/p2p/nat"
	"github.com/ParallaxProtocol/parallax/v2/p2p/netutil"
	"github.com/ParallaxProtocol/parallax/v2/p2p/rlpx/bip324handshake"
	"github.com/ParallaxProtocol/parallax/v2/p2p/torcontrol"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/support/event"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/mclock"
)

const (
	defaultDialTimeout = 15 * time.Second

	// This is the fairness knob for the discovery mixer. When looking for peers, we'll
	// wait this long for a single source of candidates before moving on and trying other
	// sources.
	discmixTimeout = 5 * time.Second

	// Connectivity defaults.
	defaultMaxPendingPeers = 50
	defaultDialRatio       = 3

	// defaultMaxBlockRelayPeers is the default number of outbound
	// slots reserved for block-relay-only peers. Bitcoin Core's
	// MAX_BLOCK_RELAY_ONLY_CONNECTIONS (src/net.h:73). Operators can
	// override via Config.MaxBlockRelayPeers.
	defaultMaxBlockRelayPeers = 2

	// defaultMinLegacyPeers is the number of peer slots withheld from
	// tcp_gossip-sourced candidates while in v2.x. Bounds the blast
	// radius of a v2.0-specific bug by preventing 100% concentration
	// on the new code path. Removed in v3.0 alongside the legacy
	// transports. PIP-0006 §Phase 5.
	defaultMinLegacyPeers = 2

	// This time limits inbound connection attempts per source IP.
	inboundThrottleTime = 30 * time.Second

	// maxInboundConnAttemptsPerIP caps how many distinct inbound TCP
	// attempts from the same source IP are tolerated within
	// inboundThrottleTime. Set above 1 so legitimate co-located
	// scenarios work (e.g. an operator running parallax-disc-crawl
	// on the same host as their parallaxd, which puts the crawler
	// and the daemon behind the same public-NAT IP from any remote
	// peer's POV). Still strict enough to make per-IP flooding
	// expensive — an attacker has to scale across IPs as before, with
	// only a 4x relaxation per IP.
	maxInboundConnAttemptsPerIP = 4

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	frameWriteTimeout = 20 * time.Second
)

var errServerStopped = errors.New("server stopped")

// Config holds Server options.
type Config struct {
	// This field must be set to a valid secp256k1 private key.
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	MaxPeers int

	// MinLegacyPeers is the number of peer slots withheld from
	// tcp_gossip-sourced candidates so the node retains at least
	// this many peers from non-tcp_gossip sources (legacy_udp,
	// dns_seed, manual, self_advertised) when such peers are
	// reachable. Defaults to defaultMinLegacyPeers when zero. Set
	// to a negative value to disable the floor entirely.
	//
	// The floor constrains outbound dials only: inbound peers
	// cannot be attributed to an addrman source (their ephemeral
	// source port never matches the stored listen-port entry), so
	// they are conservatively never counted against the cap.
	//
	// Rationale: during v2.x, prevents a v2.0 node from ending up
	// with all peers running the same new code — bounds the blast
	// radius of a v2.0-specific bug. Not a defense against any
	// adversary; robustness for early-rollout population
	// concentration. Removed in v3.0 alongside the legacy
	// transports. PIP-0006 §Phase 5.
	MinLegacyPeers int `toml:",omitempty"`

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	MaxPendingPeers int `toml:",omitempty"`

	// DialRatio controls the ratio of inbound to dialed connections.
	// Example: a DialRatio of 2 allows 1/2 of connections to be dialed.
	// Setting DialRatio to zero defaults it to 3.
	DialRatio int `toml:",omitempty"`

	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	NoDiscovery bool

	// Name sets the node name of this server.
	// Use util.MakeName to create a name that follows existing conventions.
	Name string `toml:"-"`

	// BootstrapNodes are the NodeID-carrying bootstrap peers used to
	// seed connectivity with the rest of the network. Consumed by
	// discv4's routing table (v1.x-compat peers) and ingested into
	// addrman with KeyType=0x01 via IngestNode.
	BootstrapNodes []*enode.Node

	// BootstrapNodesV2 are the v2-native bootstrap peers — IP or Tor
	// v3 addresses (PIP-0007) used by the BIP324-style handshake. No
	// NodeID / enode URL is required to reach them — the handshake
	// authenticates against whoever answered at that address.
	// Ingested into addrman with source=dns_seed and KeyType=0x00 at
	// Start, filtered to the networks the node has a route to
	// (Core's fixed-seed reachability skip).
	BootstrapNodesV2 []addrman.NetAddr

	// DNSSeeds are hostnames the node resolves at DNSSeedDefaultInterval
	// (24h, Bitcoin parity) to bootstrap addrman with v2.0-native peers
	// on DNSSeedDefaultPort. Empty disables the resolver loop entirely.
	// Populated from netparams.MainnetDNSSeeds (or testnet equivalent)
	// gated by --dnsseed / --nodiscover.
	DNSSeeds []string `toml:",omitempty"`

	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	StaticNodes []*enode.Node

	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	TrustedNodes []*enode.Node

	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	Protocols []Protocol `toml:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	ListenAddr string

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	NAT nat.Interface `toml:",omitempty"`

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	Dialer NodeDialer `toml:"-"`

	// ProxyAddr, when set, routes every outbound connection through
	// the given SOCKS5 proxy ("ip:port"), including .onion targets —
	// Bitcoin Core's -proxy. PIP-0007.
	ProxyAddr string `toml:",omitempty"`

	// OnionProxyAddr overrides the proxy used for .onion targets —
	// Bitcoin Core's -onion. Empty inherits ProxyAddr; the sentinel
	// "0" disables onion outbound even when ProxyAddr is set.
	OnionProxyAddr string `toml:",omitempty"`

	// OnlyNet restricts outbound connections to the named networks
	// ("ipv4", "ipv6", "onion") — Bitcoin Core's -onlynet. Empty
	// allows every network the node has a route to. Inbound and
	// operator-initiated dials are not restricted, as in Core.
	OnlyNet []string `toml:",omitempty"`

	// ProxyNoRandomize disables per-connection SOCKS5 credential
	// randomization (Tor stream isolation) — the inverse of Bitcoin
	// Core's -proxyrandomize, inverted so the zero value keeps
	// isolation on.
	ProxyNoRandomize bool `toml:",omitempty"`

	// ListenOnion creates a Tor v3 onion service for the P2P listener
	// via the Tor control port — Bitcoin Core's -listenonion. Only
	// effective when the node listens (ListenAddr != ""). PIP-0007 §3.
	ListenOnion bool `toml:",omitempty"`

	// TorControlAddr is the Tor control port. Empty defaults to
	// 127.0.0.1:9051 (Core's -torcontrol).
	TorControlAddr string `toml:",omitempty"`

	// TorPassword authenticates to the control port via
	// HASHEDPASSWORD (Core's -torpassword). Cookie auth is preferred
	// and automatic when the password is empty.
	TorPassword string `toml:"-"`

	// OnionKeyPath persists the onion service's ed25519 key across
	// restarts (Core's onion_v3_private_key). Defaults to
	// <datadir>/onion_v3_private_key via the node layer; empty keeps
	// the onion identity ephemeral.
	OnionKeyPath string `toml:",omitempty"`

	// OnionVirtualPort is the port the onion service exposes. Zero
	// defaults to the network default port (32110) regardless of the
	// local listen port — Core always advertises the default port to
	// avoid decloaking nodes running on non-standard ones.
	OnionVirtualPort uint16 `toml:",omitempty"`

	// OnOnionService / OnOnionLost notify the wiring layer (the disc
	// backend) when the onion service comes up or goes away. Called
	// after the Server's own state is updated. Optional.
	OnOnionService func(addrman.NetAddr) `toml:"-"`
	OnOnionLost    func()                `toml:"-"`

	// OnNATMapping notifies the wiring layer (the disc backend) of the
	// external TCP endpoint a UPnP/NAT-PMP gateway forwards to our
	// listener, whenever its address or mapped port changes. Called
	// with the zero NetAddr when the endpoint becomes unknown (the
	// mapping lapsed). Not called for --nat extip, which the wiring
	// layer handles as an operator override. Optional.
	OnNATMapping func(addrman.NetAddr) `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool

	// NodeFilter is an optional function for filtering discovery nodes.
	// If set, nodes that don't pass this filter are evicted from the
	// discovery routing table during revalidation.
	NodeFilter func(*enode.Node) bool `toml:"-"`

	// LegacyDiscoveryMode is the single operator knob controlling
	// this node's compatibility with the v1.x transport stack. It
	// drives three subsystems in lockstep because they all reflect
	// the same v1.x identity model (persistent secp256k1, enode/ENR,
	// legacy RLPx, UDP discovery):
	//
	//   "auto" (default) — discv4 UDP responder-only (answers inbound
	//                      PING/FINDNODE but doesn't drive dialing);
	//                      both legacy and v2 handshakes accepted;
	//                      addrman is the primary dial source.
	//   "on"             — discv4 fully active as a dial candidate
	//                      source; both handshakes accepted. Matches
	//                      pre-PIP-0006 operator expectations.
	//   "off"            — no UDP socket; listener rejects legacy
	//                      RLPx; dialer refuses KeyType=0x01
	//                      (legacy-enode) addrman entries. Every
	//                      peer session uses the v2 handshake. The
	//                      enode URL emitted on startup is
	//                      diagnostic-only.
	//
	// Empty / invalid values fall back to "auto" with a warning.
	// The v2 handshake code path and addrman are always present —
	// this flag only controls whether the legacy v1.x surface is
	// exposed alongside them.
	LegacyDiscoveryMode string `toml:",omitempty"`

	// MaxBlockRelayPeers is the count of outbound peers reserved for
	// block-relay-only slots (Bitcoin Core's
	// MAX_BLOCK_RELAY_ONLY_CONNECTIONS, src/net.h:73 = 2). Block-
	// relay-only peers do not relay transactions or addresses;
	// they're anti-eclipse insurance over and above full-relay.
	// Counted against the existing outbound budget (DialRatio), so
	// raising this lowers the full-relay slot count by the same
	// amount. Zero applies the default of 2; a negative value
	// disables the block-relay-only bucket entirely so every outbound
	// dial becomes full-relay (same zero-means-default convention as
	// MinLegacyPeers; see maxBlockRelayDial).
	MaxBlockRelayPeers int `toml:",omitempty"`

	// BanList is the BanMan instance the inbound-accept path consults
	// to reject banned and (under saturation) discouraged source IPs.
	// Operator-controlled persistence lives in p2p/banman; the Server
	// only reads. nil disables ban / discourage gating — useful in
	// ephemeral tests. The node layer constructs and assigns this
	// before Server.Start using BanListPath; tests can preset.
	BanList *banman.BanMan `toml:"-"`

	// BanListPath is where banlist.json persists across restarts.
	// Defaults to <datadir>/banlist.json via the node layer. Empty
	// keeps the BanMan in-memory only (fine for ephemeral tests).
	// Honored only when BanList is nil at Start time.
	BanListPath string `toml:",omitempty"`

	// AnchorsPath is the location of anchors.dat. On clean shutdown
	// the (IP, listen-port) of currently-connected block-relay-only
	// outbound peers are persisted there (capped at
	// MaxBlockRelayAnchors); on next startup those peers are
	// redialed as block-relay-only and the file is deleted. Mirrors
	// Bitcoin Core's m_anchors / anchors.dat (src/net.cpp:57).
	// Empty disables anchor persistence — useful for ephemeral
	// tests and for nodes that don't run any block-relay-only
	// peers (MaxBlockRelayPeers=0).
	AnchorsPath string `toml:",omitempty"`

	// AddrBookPath is where the addrbook persists across restarts.
	// Defaults to <datadir>/addrbook.rlp via the node layer. If
	// empty, the addrman still runs in-memory but nothing is
	// persisted on shutdown — useful for ephemeral tests.
	AddrBookPath string `toml:",omitempty"`

	// AddrManager, when non-nil, is an already-initialized address
	// manager supplied by the caller. Server skips internal Load and
	// just adopts this instance — useful when the caller (node.Node)
	// needs the addrman available before Server.Start so it can wire
	// the parallax-disc/1 subprotocol backend against it. Save-on-stop
	// still happens if AddrBookPath is also set.
	AddrManager *addrman.AddrMan `toml:"-"`

	// Logger is a custom logger to use with the p2p.Server.
	Logger logging.Logger `toml:",omitempty"`

	clock mclock.Clock
}

// Server manages all peer connections.
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	newTransport func(net.Conn, *ecdsa.PublicKey) transport
	newPeerHook  func(*Peer)
	listenFunc   func(network, addr string) (net.Listener, error)

	lock    sync.Mutex // protects running
	running bool

	listener     net.Listener
	ourHandshake *protoHandshake
	loopWG       sync.WaitGroup // loop, listenLoop
	peerFeed     event.Feed
	log          logging.Logger

	// netpol / connector are resolved from the proxy configuration at
	// Start. The policy is held behind an atomic pointer because the
	// torcontrol auto-proxy replaces it at runtime (copy-on-write in
	// setAutoOnionProxy) while dial paths and ingest gates read it
	// unsynchronized. connector is a test seam like newTransport:
	// preset it before Start to intercept every outbound stream.
	// PIP-0007.
	netpol    atomic.Pointer[netPolicy]
	connector Connector

	// torControl maintains the onion service when ListenOnion is set.
	// onionSelf is the service's address while established — consulted
	// by the self-dial guard, inbound classification, and the disc
	// backend's self-advertisement hooks.
	torControl *torcontrol.Controller
	// pendingAnchors holds anchors whose network was unreachable at
	// replay time. anchors.dat is deleted unconditionally on read
	// (crash safety), so without this an onion anchor would be lost
	// whenever a restart raced its Tor route coming up; the
	// reachability hook replays them instead.
	pendingAnchorsMu sync.Mutex
	pendingAnchors   []addrman.NetAddr

	onionSelfMu  sync.Mutex
	onionSelf    addrman.NetAddr
	onionSelfSet bool

	// natIP / natTCPPort are the gateway's external address and the
	// external port it maps to our TCP listener, as last reported by
	// the NAT mechanism; zero while unknown. Combined into the
	// OnNATMapping endpoint by setNATEndpoint.
	natMu      sync.Mutex
	natIP      net.IP
	natTCPPort uint16
	natLast    addrman.NetAddr

	nodedb    *enode.DB
	localnode *enode.LocalNode
	ntab      *discover.UDPv4
	discmix   *enode.FairMix
	dialsched *dialScheduler

	// helloNonce is a 64-bit random value generated once per Server
	// lifetime and embedded in every parallax-disc/1 Hello we send.
	// Receiving our own nonce back identifies a self-connect (the
	// protocol-level analog of Bitcoin Core's nLocalHostNonce, src/
	// net.cpp PushNodeVersion). Read-only after setupLocalNode; safe
	// for concurrent reads from peer goroutines without locking.
	helloNonce uint64

	// peerListenLookup is the disc-protocol's per-peer Hello cache
	// projected as "given this peer ID, what listen port did they
	// disclose?". Used by peerListenAddr to dedup inbound peers
	// (whose RemoteAddr port is ephemeral) against outbound dials.
	// Set once at node setup before Start; nil during tests that
	// don't wire the disc backend.
	peerListenLookup PeerListenPortLookup

	// addrbook is the PIP-0006 address manager. Populated only when
	// Config.ExperimentalAddrMan is true. Feeds the dialer as an
	// additional FairMix source and receives discv4/bootnode entries
	// via teeIter wrappers. Exposed via AddrBook() so upstream code
	// can register subprotocols against it without pulling p2p into
	// an import cycle with p2p/protocols/*.
	addrbook     *addrman.AddrMan
	addrbookIter *addrman.NodeIter
	v2Iter       *addrman.V2Iter

	// v2DialRecent is a per-(ip:port) cooldown keyed by tcp addr
	// string. Gates DialV2 so every caller — runV2Dialer, the v2-ENR
	// branch in the dial scheduler, admin RPC — shares a single
	// throttle. Serialized by v2DialRecentMu.
	v2DialRecentMu sync.Mutex
	v2DialRecent   map[string]time.Time

	// quitCtx is cancelled together with quit. It bounds operations
	// that take a context — most importantly the v2/feeler TCP dials,
	// whose 15s connect timeout would otherwise stall Stop's
	// loopWG.Wait for its full remainder (Bitcoin Core interrupts its
	// connect loop the same way via interruptNet).
	quitCtx    context.Context
	quitCancel context.CancelFunc

	// Channels into the run loop.
	quit                    chan struct{}
	addtrusted              chan *enode.Node
	removetrusted           chan *enode.Node
	peerOp                  chan peerOpFunc
	peerOpDone              chan struct{}
	delpeer                 chan peerDrop
	checkpointPostHandshake chan *conn
	checkpointAddPeer       chan *conn

	// State of run loop and listenLoop.
	inboundHistory expHeap
}

type peerOpFunc func(map[enode.ID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer
}

// enrV2Transport is the ENR entry a node sets to signal that its
// listening TCP endpoint accepts the BIP324-style v2 handshake.
// Peers that see this on an enode's ENR dial v2 from the start and
// skip the v1 RLPx path, avoiding the "connect v1, tear down, redial
// v2" promotion dance. No payload — presence is the signal.
type enrV2Transport struct {
	Rest []rlp.RawValue `rlp:"tail"`
}

func (enrV2Transport) ENRKey() string { return "pipv2" }

// hasV2TransportENR reports whether n's ENR advertises v2-transport
// support.
func hasV2TransportENR(n *enode.Node) bool {
	if n == nil {
		return false
	}
	var e enrV2Transport
	return n.Load(&e) == nil
}

type connFlag int32

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn
	// v2DialedConn marks a connection initiated via Server.DialV2.
	// pickHandshakeVariant reads this bit to route outbound v2
	// dials — the legacy dial path never sets it, so existing
	// code paths keep their original semantics after the Phase 2b
	// changes.
	v2DialedConn
	// blockRelayConn marks an outbound peer occupying a block-relay-
	// only slot in the dial scheduler. Block-relay-only peers do not
	// relay transactions or addresses (Bitcoin Core's
	// MAX_BLOCK_RELAY_ONLY_CONNECTIONS, src/net.h:73). The bit
	// propagates to *Peer.blockRelayOnly at attach time so the prl
	// and disc protocol handlers can suppress tx and address gossip.
	blockRelayConn
	// feelerConn marks a short-lived probe connection (feeler or
	// addrfetch) that exists only to verify reachability or warm the
	// addrbook, then disconnects. Bitcoin Core's ConnectionType::
	// FEELER / ADDR_FETCH. Feelers are excluded from the dial
	// scheduler's slot and network-group accounting and never record
	// an addrman failure on their deliberate disconnect (they already
	// marked the address Good at attach).
	feelerConn
	// onionConn marks a peer whose effective network is Tor: an
	// outbound dial to a .onion target, or an inbound connection
	// arriving from loopback while our onion service is active
	// (Core's CNode::ConnectedThroughNetwork heuristic, PIP-0007
	// §3.2). Onion peers' YourAddr observations are excluded from
	// the self-address quorum, and the disc greeting advertises the
	// onion self-address to them.
	onionConn
	// proxiedConn marks an outbound connection that was routed
	// through a SOCKS5 proxy. The conn's RemoteAddr is the proxy,
	// not the peer, so it must never be used as an observation of
	// the peer's address (YourAddr reporting, dedup).
	proxiedConn
)

// conn wraps a network connection with information gathered
// during the two handshakes.
type conn struct {
	fd net.Conn
	transport
	node  *enode.Node
	flags connFlag
	cont  chan error // The run loop uses cont to signal errors to SetupConn.
	caps  []Cap      // valid after the protocol handshake
	name  string     // valid after the protocol handshake

	// dialedTarget is the address an outbound dial was aimed at (nil
	// for inbound conns). Group-diversity accounting, addrman
	// feedback, dedup and peer-targeting RPCs prefer it over
	// fd.RemoteAddr, which for proxied conns is the SOCKS5 proxy
	// rather than the peer. Atomic because it is written at conn
	// setup and read from peer, dial and RPC goroutines. PIP-0007.
	dialedTarget atomic.Pointer[addrman.NetAddr]

	// evicted records that this connection already triggered a
	// successful inbound eviction at an earlier checkpoint. The
	// admission checks run twice per connection (post-handshake and
	// add-peer); without this guard a single admission could evict
	// two victims. Only touched from the run loop.
	evicted bool
}

type transport interface {
	// The two handshakes.
	doEncHandshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because MsgPipe doesn't use it.
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.node.ID() != enode.ID{}) {
		s += " " + c.node.ID().String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if f&blockRelayConn != 0 {
		s += "-blockrelay"
	}
	if f&feelerConn != 0 {
		s += "-feeler"
	}
	if f&onionConn != 0 {
		s += "-onion"
	}
	if f&proxiedConn != 0 {
		s += "-proxied"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

// dialTarget returns the outbound dial target, zero when the conn is
// inbound or legacy-dialed and no target has been adopted.
func (c *conn) dialTarget() addrman.NetAddr {
	if p := c.dialedTarget.Load(); p != nil {
		return *p
	}
	return addrman.NetAddr{}
}

// setDialTarget records the conn's dial target.
func (c *conn) setDialTarget(a addrman.NetAddr) {
	if a.Network != 0 {
		c.dialedTarget.Store(&a)
	}
}

func (c *conn) is(f connFlag) bool {
	flags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
	return flags&f != 0
}

func (c *conn) set(f connFlag, val bool) {
	for {
		oldFlags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
		flags := oldFlags
		if val {
			flags |= f
		} else {
			flags &= ^f
		}
		if atomic.CompareAndSwapInt32((*int32)(&c.flags), int32(oldFlags), int32(flags)) {
			return
		}
	}
}

// LocalNode returns the local node record.
func (srv *Server) LocalNode() *enode.LocalNode {
	return srv.localnode
}

// HelloNonce returns the per-startup random nonce embedded in every
// outgoing parallax-disc/1 Hello. Bitcoin Core analog: nLocalHostNonce
// (src/net.cpp PushNodeVersion). Stable for the Server's lifetime;
// safe for concurrent reads.
func (srv *Server) HelloNonce() uint64 {
	return srv.helloNonce
}

// PeerListenPortLookup is the minimal surface peerListenAddr needs
// to consult an external per-peer listen-port store. The
// parallax-disc/1 AddrmanBackend records a peer's claimed listen
// port from their Hello message and implements this interface so
// the Server can resolve inbound peers' true listen address (their
// kernel RemoteAddr port is ephemeral, not their listen port).
//
// Returning ok=false means the peer hasn't disclosed a port (yet)
// or doesn't speak the disc protocol — peerListenAddr in turn
// reports unknown for that peer, which behaves correctly in the
// dedup paths (no false positives).
type PeerListenPortLookup interface {
	PeerListenPort(id enode.ID) (uint16, bool)
}

// SetPeerListenPortLookup wires the disc backend (or any other
// per-peer listen-port store) into the Server. Called once at node
// setup before Start; subsequent calls overwrite. Concurrent reads
// from peer goroutines see the latest value via plain field access
// — node setup runs before any peer goroutine, so the
// happens-before is established by Start's startup barrier.
func (srv *Server) SetPeerListenPortLookup(l PeerListenPortLookup) {
	srv.peerListenLookup = l
}

// initHelloNonce draws a 64-bit value from crypto/rand. Called once
// from setupLocalNode before any peer can be accepted.
func (srv *Server) initHelloNonce() error {
	var buf [8]byte
	if _, err := crand.Read(buf[:]); err != nil {
		return fmt.Errorf("hello nonce init: %w", err)
	}
	srv.helloNonce = binary.BigEndian.Uint64(buf[:])
	return nil
}

// Peers returns all connected peers.
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	})
	return ps
}

// PeerCount returns the number of connected peers.
func (srv *Server) PeerCount() int {
	var count int
	srv.doPeerOp(func(ps map[enode.ID]*Peer) {
		count = len(ps)
	})
	return count
}

// AddPeer adds the given node to the static node set. When there is room in the peer set,
// the server will connect to the node. If the connection fails for any reason, the server
// will attempt to reconnect the peer.
func (srv *Server) AddPeer(node *enode.Node) {
	srv.dialsched.addStatic(node)
}

// RemovePeer removes a node from the static node set. It also disconnects from the given
// node if it is currently connected as a peer.
//
// This method blocks until all protocols have exited and the peer is removed. Do not use
// RemovePeer in protocol implementations, call Disconnect on the Peer instead.
func (srv *Server) RemovePeer(node *enode.Node) {
	var (
		ch  chan *PeerEvent
		sub event.Subscription
	)
	// Disconnect the peer on the main loop.
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		srv.dialsched.removeStatic(node)
		if peer := peers[node.ID()]; peer != nil {
			ch = make(chan *PeerEvent, 1)
			sub = srv.peerFeed.Subscribe(ch)
			peer.Disconnect(DiscRequested)
		}
	})
	// Wait for the peer connection to end.
	if ch != nil {
		defer sub.Unsubscribe()
		for ev := range ch {
			if ev.Peer == node.ID() && ev.Type == PeerEventTypeDrop {
				return
			}
		}
	}
}

// AddTrustedPeer adds the given node to a reserved trusted list which allows the
// node to always connect, even if the slot are full.
func (srv *Server) AddTrustedPeer(node *enode.Node) {
	select {
	case srv.addtrusted <- node:
	case <-srv.quit:
	}
}

// RemoveTrustedPeer removes the given node from the trusted peer set.
func (srv *Server) RemoveTrustedPeer(node *enode.Node) {
	select {
	case srv.removetrusted <- node:
	case <-srv.quit:
	}
}

// SubscribeEvents subscribes the given channel to peer events
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// Self returns the local node's endpoint information.
func (srv *Server) Self() *enode.Node {
	srv.lock.Lock()
	ln := srv.localnode
	srv.lock.Unlock()

	if ln == nil {
		return enode.NewV4(&srv.PrivateKey.PublicKey, net.ParseIP("0.0.0.0"), 0, 0)
	}
	return ln.Node()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	srv.lock.Lock()
	if !srv.running {
		srv.lock.Unlock()
		return
	}
	srv.running = false
	// Captured here, stopped after the lock is released: the
	// controller's shutdown is prompt and deterministic, but nothing
	// that waits on another goroutine belongs under srv.lock.
	torControl := srv.torControl
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	if srv.addrbookIter != nil {
		srv.addrbookIter.Close()
	}
	if srv.v2Iter != nil {
		srv.v2Iter.Close()
	}
	close(srv.quit)
	if srv.quitCancel != nil {
		srv.quitCancel()
	}
	srv.lock.Unlock()
	if torControl != nil {
		// Tor drops the ephemeral onion service with the control
		// connection; nothing else to unwind.
		torControl.Stop()
	}
	srv.loopWG.Wait()

	// Persist addrbook on shutdown. Done after loopWG so no inflight
	// Good/Attempt/Add calls race the Save. Failures are logged, not
	// propagated — a save error on shutdown must not crash the node.
	if srv.addrbook != nil && srv.AddrBookPath != "" {
		if err := srv.addrbook.Save(srv.AddrBookPath); err != nil {
			srv.log.Warn("addrbook save failed on shutdown", "path", srv.AddrBookPath, "err", err)
		} else {
			srv.log.Info("addrbook saved", "path", srv.AddrBookPath, "entries", srv.addrbook.Size(nil, nil))
		}
	}
	// Block-relay-only anchors are persisted by the run loop's
	// spindown (see persistAnchors call in run), while the peer set
	// is still intact. Doing it here — after loopWG.Wait — would
	// always observe an empty peer set. Bitcoin Core m_anchors /
	// anchors.dat (src/net.cpp:57).
}

// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = logging.Root()
	}
	if srv.clock == nil {
		srv.clock = mclock.System{}
	}
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}

	// static fields
	if srv.PrivateKey == nil {
		return errors.New("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.legacyDiscoveryMode() == legacyDiscoveryOff {
		// --legacy-discovery=off implies v2-only: legacy RLPx is
		// refused at the listener, dialer refuses KeyType=0x01
		// entries, and the enode URL emitted on startup becomes a
		// diagnostic artifact rather than a dialable identifier.
		// The secp256k1 private key is still loaded because
		// LocalNode uses it to derive a stable placeholder for
		// logs and metrics; no peer handshake consumes it in this
		// mode.
		srv.log.Info("--legacy-discovery=off: legacy RLPx refused, enode URL diagnostic-only")
	}
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}
	if srv.listenFunc == nil {
		srv.listenFunc = net.Listen
	}
	// Resolve proxy configuration before anything opens a socket:
	// setupLocalNode/setupListening consult the policy to mute NAT
	// and UDP for onion-only nodes, and the dial paths route every
	// outbound stream through the connector. PIP-0007.
	pol, err := newNetPolicy(&srv.Config)
	if err != nil {
		return err
	}
	srv.netpol.Store(pol)
	if srv.connector == nil {
		srv.connector = &netConnector{policy: srv.policy, timeout: defaultDialTimeout}
	}
	// Onion-only nodes must not chatter on the LAN: UPnP/NAT-PMP
	// discovery reveals the node and maps a port no clearnet peer
	// will ever dial. PIP-0007 §1.4.
	if pol.clearnetHidden() && srv.NAT != nil {
		// Only the discovery mechanisms are muted: UPnP/NAT-PMP probe
		// the LAN and map a port, which is what would expose a node
		// that means to stay hidden. A --nat extip: value performs no
		// network activity at all — it is an operator statement about
		// the node's address, and the disc layer keeps advertising it
		// through the quorum override, so discarding it here would
		// leave the two halves disagreeing.
		if _, static := srv.NAT.(nat.ExtIP); !static {
			srv.log.Info("NAT traversal disabled: clearnet is proxied or unreachable")
			srv.NAT = nil
		}
	}
	// One-line reachability summary so operators can confirm their
	// proxy flags resolved as intended (PIP-0007 §4).
	srv.log.Info("network reachability",
		"ipv4", pol.isReachable(addrman.NetIPv4),
		"ipv6", pol.isReachable(addrman.NetIPv6),
		"onion", pol.isReachable(addrman.NetTorV3),
		"proxied", pol.proxied(),
		"listenonion", srv.ListenOnion && srv.ListenAddr != "")
	srv.quit = make(chan struct{})
	srv.quitCtx, srv.quitCancel = context.WithCancel(context.Background())
	srv.delpeer = make(chan peerDrop)
	srv.checkpointPostHandshake = make(chan *conn)
	srv.checkpointAddPeer = make(chan *conn)
	srv.addtrusted = make(chan *enode.Node)
	srv.removetrusted = make(chan *enode.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})

	if err := srv.setupLocalNode(); err != nil {
		return err
	}
	if srv.ListenAddr != "" {
		if err := srv.setupListening(); err != nil {
			return err
		}
	}
	srv.applyLegacyDiscoveryMode()
	if err := srv.setupAddrMan(); err != nil {
		return err
	}
	if err := srv.setupDiscovery(); err != nil {
		return err
	}
	srv.setupDialScheduler()
	srv.replayAnchors()

	// Started last: the controller's callbacks (auto-proxy, service
	// establishment) run on its own goroutine and touch the addrbook,
	// the deferred-anchor list and the dial paths, so every one of
	// those must be fully initialized before it can fire.
	if srv.ListenOnion && srv.listener != nil {
		srv.startTorControl()
	}

	// Periodic ban-list sweep + dump (Bitcoin's 15-minute
	// DUMP_BANS_INTERVAL): keeps expired entries out of the map and
	// banlist.json in the steady state, not just after mutations.
	if srv.BanList != nil {
		srv.loopWG.Add(1)
		go func() {
			defer srv.loopWG.Done()
			srv.BanList.RunSweeper(srv.quit)
		}()
	}

	srv.loopWG.Add(1)
	go srv.run()
	return nil
}

// setupAddrMan initializes the address manager. Always runs — the
// addrman is the v2 design and is not operator-optional anymore.
//
// Flow:
//
//   - If Config.AddrManager is supplied (the node layer's typical path,
//     wired before Start so parallax-disc/1 can register), adopt it.
//   - Otherwise construct an empty addrman, Load addrbook.rlp if
//     Config.AddrBookPath is non-empty (skipping persistence when it's
//     empty — useful for ephemeral tests), and ingest BootstrapNodes
//     with source=dns_seed.
func (srv *Server) setupAddrMan() error {
	var m *addrman.AddrMan
	if srv.AddrManager != nil {
		m = srv.AddrManager
	} else {
		var err error
		m, err = addrman.New()
		if err != nil {
			return fmt.Errorf("addrman: new: %w", err)
		}
		if srv.AddrBookPath != "" {
			if err := m.Load(srv.AddrBookPath); err != nil {
				if errors.Is(err, addrman.ErrFutureSchema) {
					srv.log.Warn("addrbook schema is from a newer binary; proceeding with empty addrbook", "path", srv.AddrBookPath, "err", err)
				} else {
					srv.log.Warn("failed to load addrbook; proceeding empty", "path", srv.AddrBookPath, "err", err)
				}
			}
		}
		now := time.Now()
		for _, n := range srv.BootstrapNodes {
			addrman.IngestNode(m, n, addrman.SourceDNSSeed, now)
		}
	}
	// V2 bootstrap ingest runs here (not the node layer) so the
	// resolved proxy policy can filter it: a bootnode on a network we
	// have no route to is skipped, mirroring Core's fixed-seed
	// reachability skip. Add dedupes, so re-running on a warm
	// addrbook is harmless.
	now := time.Now()
	for _, addr := range srv.BootstrapNodesV2 {
		if !srv.NetworkReachable(addr.Network) {
			srv.log.Debug("skipping bootstrap node on unreachable network", "addr", addr)
			continue
		}
		addrman.IngestV2NetAddr(m, addr, addrman.SourceDNSSeed, now)
	}
	srv.addrbook = m
	srv.log.Info("addrman enabled", "path", srv.AddrBookPath, "entries", m.Size(nil, nil))

	// Periodic metrics refresh and legacy_udp dominance log. Cheap —
	// Size() is O(1) and sourceCounts is a small map. Tied to quit so
	// Stop() tears it down cleanly.
	srv.loopWG.Add(1)
	go func() {
		defer srv.loopWG.Done()
		metricsTick := time.NewTicker(5 * time.Second)
		defer metricsTick.Stop()
		dominanceTick := time.NewTicker(15 * time.Minute)
		defer dominanceTick.Stop()
		for {
			select {
			case <-srv.quit:
				return
			case <-metricsTick.C:
				srv.addrbook.RefreshMetrics()
			case <-dominanceTick.C:
				srv.warnOnLegacyUDPDominance()
			}
		}
	}()

	// DNS-seed resolver loop. Plain A/AAAA at DNSSeedDefaultInterval,
	// each IP paired with DNSSeedDefaultPort and ingested into addrman
	// with source=dns_seed. Empty Config.DNSSeeds disables it (matches
	// --nodiscover semantics).
	if len(srv.DNSSeeds) > 0 {
		switch {
		case srv.policy().nameProxy() != nil:
			// --proxy: never touch the system resolver. Connect to
			// each seed hostname through the proxy instead and let
			// the disc greeting's GetPeers warm the addrbook —
			// Core's HaveNameProxy() → AddAddrFetch(seed) branch in
			// ThreadDNSAddressSeed. PIP-0007 §1.4.
			seedCtx, seedCancel := context.WithCancel(context.Background())
			srv.loopWG.Add(2)
			go func() {
				defer srv.loopWG.Done()
				<-srv.quit
				seedCancel()
			}()
			go func() {
				defer srv.loopWG.Done()
				srv.proxiedSeedLoop(seedCtx, srv.DNSSeeds, DNSSeedDefaultPort, DNSSeedDefaultInterval)
			}()
			srv.log.Info("DNS seeds via proxy addr-fetch (no local resolution)", "hosts", srv.DNSSeeds)
		case srv.policy().clearnetHidden():
			// Onion-only without --proxy: seed hostnames would leak
			// through the system resolver and their A/AAAA results
			// are undialable anyway.
			srv.log.Info("DNS seeds disabled: no clearnet network is reachable")
		default:
			seedCtx, seedCancel := context.WithCancel(context.Background())
			srv.loopWG.Add(2)
			go func() {
				defer srv.loopWG.Done()
				<-srv.quit
				seedCancel()
			}()
			go func() {
				defer srv.loopWG.Done()
				dnsSeedLoop(
					seedCtx,
					net.DefaultResolver,
					srv.DNSSeeds,
					srv.addrbook,
					DNSSeedDefaultPort,
					DNSSeedDefaultInterval,
					srv.log,
				)
			}()
			srv.log.Info("DNS-seed resolver enabled", "hosts", srv.DNSSeeds, "interval", DNSSeedDefaultInterval, "port", DNSSeedDefaultPort)
		}
	}
	return nil
}

// warnOnLegacyUDPDominance logs at warn level if legacy_udp entries
// account for more than 50% of the addrbook. PIP-0006 Phase 5 flags
// this as a signal of poor v2.0 network share — the operator should
// investigate whether they've partitioned onto v1.x peers only.
func (srv *Server) warnOnLegacyUDPDominance() {
	if srv.addrbook == nil {
		return
	}
	total := srv.addrbook.Size(nil, nil)
	if total < 20 {
		// Too few entries for the ratio to be meaningful.
		return
	}
	counts := srv.addrbook.CountsBySource()
	legacy := counts[addrman.SourceLegacyUDP]
	if legacy*2 > total {
		srv.log.Warn("addrbook dominated by legacy_udp entries — v2.0 network share may be low",
			"legacy_udp", legacy, "total", total)
	}
}

func (srv *Server) setupLocalNode() error {
	// Generate the per-startup self-connect nonce. Drawn from
	// crypto/rand so adversaries can't predict it; uint64 space is
	// large enough that collision probability across the network is
	// negligible (birthday bound ~2^32 distinct nodes before any
	// pair shares a nonce, and even then only matters if those two
	// nodes happen to dial each other).
	if err := srv.initHelloNonce(); err != nil {
		return err
	}

	// Create the devp2p handshake.
	pubkey := crypto.FromECDSAPub(&srv.PrivateKey.PublicKey)
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: pubkey[1:]}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
	sort.Sort(capsByNameAndVersion(srv.ourHandshake.Caps))

	// Create the local node.
	db, err := enode.OpenDB(srv.Config.NodeDatabase)
	if err != nil {
		return err
	}
	srv.nodedb = db
	srv.localnode = enode.NewLocalNode(db, srv.PrivateKey)
	srv.localnode.SetFallbackIP(net.IP{127, 0, 0, 1})
	// Advertise v2-transport acceptance in our ENR. Peers that
	// resolve our enode (via enrtree or discv4) will see this and
	// dial v2 directly instead of v1-then-promote.
	srv.localnode.Set(enrV2Transport{})
	// TODO: check conflicts
	for _, p := range srv.Protocols {
		for _, e := range p.Attributes {
			srv.localnode.Set(e)
		}
	}
	switch srv.NAT.(type) {
	case nil:
		srv.log.Debug("NAT disabled, no port mapping will be performed")
	case nat.ExtIP:
		// ExtIP doesn't block, set the IP right away.
		ip, _ := srv.NAT.ExternalIP()
		srv.log.Info("Using static external IP for NAT", "ip", ip)
		srv.localnode.SetStaticIP(ip)
	default:
		// Ask the router about the IP. This takes a while and blocks startup,
		// do it in the background.
		srv.log.Info("NAT enabled, discovering external IP in background", "mechanism", srv.NAT)
		srv.loopWG.Add(1)
		go func() {
			defer srv.loopWG.Done()
			srv.natExternalIPLoop()
		}()
	}
	return nil
}

// natIPRefreshInterval is how often the gateway is re-asked for its
// external address. Residential WAN addresses change (PPPoE reconnects,
// DHCP lease turnover), and an advertisement of the old one sends every
// peer to a dead endpoint until the quorum catches up.
const natIPRefreshInterval = 5 * time.Minute

// natExternalIPLoop asks the NAT gateway for its external address at
// startup and every natIPRefreshInterval, publishing changes to the
// local node record and the OnNATMapping hook. A failed query keeps the
// last known address: gateways drop the odd SOAP request, and a mapping
// that genuinely lapsed is withdrawn through the port mapping instead.
func (srv *Server) natExternalIPLoop() {
	var (
		last   net.IP
		warned bool
	)
	tick := time.NewTicker(natIPRefreshInterval)
	defer tick.Stop()
	for {
		if ip, err := srv.NAT.ExternalIP(); err == nil {
			if !ip.Equal(last) {
				srv.log.Info("NAT external IP discovered", "ip", ip)
				srv.localnode.SetStaticIP(ip)
				srv.setNATEndpoint(ip, 0)
				last = ip
			}
		} else if !warned {
			srv.log.Warn("NAT external IP discovery failed", "err", err)
			warned = true
		} else {
			srv.log.Debug("NAT external IP discovery failed", "err", err)
		}
		select {
		case <-srv.quit:
			return
		case <-tick.C:
		}
	}
}

// setNATEndpoint records a NAT update — the gateway's external IP
// (port 0) or the external port mapped to the TCP listener (ip nil;
// port 0 when the mapping lapsed) — and passes the combined endpoint
// to OnNATMapping when it changes. The endpoint is the zero NetAddr
// until both halves are known.
func (srv *Server) setNATEndpoint(ip net.IP, port uint16) {
	srv.natMu.Lock()
	if ip != nil {
		srv.natIP = ip
	} else {
		srv.natTCPPort = port
	}
	var ep addrman.NetAddr
	if srv.natIP != nil && srv.natTCPPort != 0 {
		if a, ok := netip.AddrFromSlice(srv.natIP); ok {
			ep, _ = addrman.FromAddrPort(netip.AddrPortFrom(a.Unmap(), srv.natTCPPort))
		}
	}
	if ep == srv.natLast {
		srv.natMu.Unlock()
		return
	}
	srv.natLast = ep
	// Called under natMu so concurrent updates reach the hook in the
	// order they were recorded; the hook must not call back into the
	// Server's NAT state.
	if srv.OnNATMapping != nil {
		srv.OnNATMapping(ep)
	}
	srv.natMu.Unlock()
}

func (srv *Server) setupDiscovery() error {
	srv.discmix = enode.NewFairMix(discmixTimeout)

	// Add protocol-specific discovery sources. Tee each into addrman
	// (when present) with source=dns_seed so the enrtree-delivered
	// enodes become addrman entries — otherwise addrman sees only
	// the static MainnetBootnodes ingest and has no view of the rest
	// of the network, which leaves stale KeyType=0x00 entries
	// dominating V2Iter with nothing to balance them out.
	// Onion-only nodes skip the enrtree consumers entirely: their
	// candidates are clearnet IPs resolved over system DNS — both a
	// leak and useless under the policy. PIP-0007 §1.4.
	if !srv.policy().clearnetHidden() {
		added := make(map[string]bool)
		for _, proto := range srv.Protocols {
			if proto.DialCandidates != nil && !added[proto.Name] {
				src := proto.DialCandidates
				if srv.addrbook != nil {
					src = addrman.NewTeeIter(src, srv.addrbook, addrman.SourceDNSSeed)
				}
				srv.discmix.AddSource(src)
				added[proto.Name] = true
			}
		}
	} else {
		for _, proto := range srv.Protocols {
			if proto.DialCandidates != nil {
				srv.log.Info("enrtree discovery disabled: clearnet is proxied or unreachable")
				break
			}
		}
	}

	// Don't listen on UDP endpoint if DHT is disabled. An onion-only
	// node opens no UDP socket at all, regardless of
	// --legacy-discovery: Tor carries no UDP, and answering discv4
	// probes on clearnet would deanonymize the node. PIP-0007 §1.4.
	if srv.NoDiscovery || srv.policy().clearnetHidden() {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	realaddr := conn.LocalAddr().(*net.UDPAddr)
	srv.log.Debug("UDP listener up", "addr", realaddr)
	if srv.NAT != nil {
		if !realaddr.IP.IsLoopback() {
			srv.log.Info("Setting up NAT port mapping for UDP discovery", "port", realaddr.Port)
			srv.loopWG.Add(1)
			go func() {
				nat.Map(srv.NAT, srv.quit, "udp", realaddr.Port, realaddr.Port, "parallax discovery", func(extport uint16) {
					if extport == 0 {
						// A failed renewal leaves the ENR's UDP port as
						// it was; discv4 has no withdrawal to make.
						return
					}
					// The router may have remapped our requested port to a
					// different external one (IGDv2 AddAnyPortMapping or our
					// random-port retry path). Update the local node so the
					// ENR advertises the actually-reachable UDP port.
					if int(extport) != realaddr.Port {
						srv.log.Info("NAT remapped UDP discovery port",
							"intport", realaddr.Port, "extport", extport)
					}
					srv.localnode.SetFallbackUDP(int(extport))
				})
				srv.loopWG.Done()
			}()
		} else {
			srv.log.Debug("Skipping NAT mapping for loopback UDP address", "addr", realaddr)
		}
	}
	srv.localnode.SetFallbackUDP(realaddr.Port)

	// Discovery V4
	// discv4 seeds its routing table with BootstrapNodes (NodeID-
	// carrying entries). BootstrapNodesV2 (ip:port only) are not
	// usable here — discv4 is NodeID-keyed — and reach the v2
	// handshake path through addrman ingest in setupAddrMan.
	cfg := discover.Config{
		PrivateKey:  srv.PrivateKey,
		NetRestrict: srv.NetRestrict,
		Bootnodes:   srv.BootstrapNodes,
		Log:         srv.log,
		NodeFilter:  srv.NodeFilter,
	}
	ntab, err := discover.ListenV4(conn, srv.localnode, cfg)
	if err != nil {
		return err
	}
	srv.ntab = ntab
	// PIP-0006 Phase 5: legacy discovery mode gates whether
	// discv4 drives the dial path. Modes:
	//   on    — discv4 is a full dial source (v1.x compat).
	//   auto  — discv4 responds but is NOT plumbed to the
	//           dialer; addrman is the source of truth.
	//   off   — this branch isn't reached because NoDiscovery
	//           is already true (see setLegacyDiscoveryDefaults).
	//
	// discv4's own periodic table refresh still runs in auto
	// mode so inbound PING/FINDNODE continues to work and the
	// routing table stays warm — we only skip using RandomNodes
	// as a dial candidate iterator.
	mode := srv.legacyDiscoveryMode()
	if mode == legacyDiscoveryOn {
		src := ntab.RandomNodes()
		if srv.addrbook != nil {
			// Tee discv4 discoveries into addrman with
			// source=legacy_udp. Original node passes
			// through to the dialer unchanged.
			src = addrman.NewTeeIter(src, srv.addrbook, addrman.SourceLegacyUDP)
		}
		srv.discmix.AddSource(src)
	}
	return nil
}

func (srv *Server) setupDialScheduler() {
	config := dialConfig{
		self:           srv.localnode.ID(),
		maxDialPeers:   srv.maxDialedConns(),
		maxActiveDials: srv.MaxPendingPeers,
		log:            srv.Logger,
		netRestrict:    srv.NetRestrict,
		dialer:         srv.Dialer,
		clock:          srv.clock,
		v2Predicate:    hasV2TransportENR,
		v2Dial:         srv.DialV2,
		reachable:      srv.NetworkReachable,
		proxied:        srv.networkProxied,
		maxBlockRelay:  srv.maxBlockRelayDial(),
	}
	if srv.BanList != nil {
		bl := srv.BanList
		config.isBanned = bl.IsBanned
		config.isDiscouraged = bl.IsDiscouraged
	}
	if srv.ntab != nil {
		config.resolver = srv.ntab
	}
	if config.dialer == nil {
		// Route v1 scheduler dials through the connector so proxy
		// policy covers legacy enode dials too. PIP-0007 §1.1.
		config.dialer = connectorDialer{c: srv.dialConnector()}
	}
	// When addrman is enabled, add its NodeIter as an additional FairMix
	// source. discmix hands the dialer candidates round-robin across
	// sources, so this lets addrman feed dials without displacing
	// discv4 during the transition window.
	if srv.addrbook != nil {
		srv.addrbookIter = addrman.NewNodeIter(srv.addrbook, 250*time.Millisecond)
		srv.discmix.AddSource(srv.addrbookIter)
		// v2 dialer is always spawned — v2 handshake is not
		// operator-optional. V2Iter yields KeyType=0x00 entries;
		// when the addrbook has none (e.g., a freshly-installed
		// v1.x-only network), the goroutine idles on its internal
		// backoff.
		srv.v2Iter = addrman.NewV2Iter(srv.addrbook, 250*time.Millisecond, srv.isSelfNetAddr, srv.NetworkReachable)
		srv.loopWG.Add(1)
		go srv.runV2Dialer()

		// Background feeler. Periodically tests one addrman entry
		// for reachability without occupying an outbound slot —
		// Bitcoin Core's anti-eclipse / addrman-freshness feeler
		// (src/net.cpp:2796-2810). Refreshes LastSuccess on hits,
		// records failures otherwise.
		srv.loopWG.Add(1)
		go srv.runFeeler()

		// Cold-start addrfetch. One-shot bootstrap-only dial when
		// the addrman is below addrFetchThreshold so a fresh
		// install can populate addrbook from a few peers' GetPeers
		// responses (Bitcoin Core ConnectionType::ADDR_FETCH,
		// src/net.cpp:2422). No-op once the addrman has filled up.
		if len(srv.BootstrapNodesV2) > 0 {
			srv.loopWG.Add(1)
			go srv.runAddrFetch()
		}
	}
	srv.dialsched = newDialScheduler(config, srv.discmix, srv.setupConnTarget)
	for _, n := range srv.StaticNodes {
		srv.dialsched.addStatic(n)
	}
}

// legacyDiscoveryMode parses Config.LegacyDiscoveryMode into a
// stable enum. Unknown / empty values map to auto.
type legacyDiscoveryMode int

const (
	legacyDiscoveryAuto legacyDiscoveryMode = iota
	legacyDiscoveryOn
	legacyDiscoveryOff
)

func (srv *Server) legacyDiscoveryMode() legacyDiscoveryMode {
	switch srv.LegacyDiscoveryMode {
	case "on":
		return legacyDiscoveryOn
	case "off":
		return legacyDiscoveryOff
	case "", "auto":
		return legacyDiscoveryAuto
	}
	srv.log.Warn("unknown --legacy-discovery value; defaulting to auto", "value", srv.LegacyDiscoveryMode)
	return legacyDiscoveryAuto
}

// applyLegacyDiscoveryMode rewrites NoDiscovery for mode=off. Must be
// called before setupDiscovery. mode=auto/on leave NoDiscovery alone —
// auto still listens to answer inbound, it just doesn't drive the
// dial path (see setupDiscovery).
func (srv *Server) applyLegacyDiscoveryMode() {
	if srv.legacyDiscoveryMode() == legacyDiscoveryOff {
		srv.NoDiscovery = true
	}
}

// runV2Dialer drains v2-native addrman entries and launches a Server
// DialV2 for each. Rate-limited to one outstanding dial at a time so
// a large addrbook doesn't burst-dial the network.
func (srv *Server) runV2Dialer() {
	defer srv.loopWG.Done()

	// No local cooldown: DialV2 itself gates per-addr timing via
	// v2DialCooldownCheckAndMark. If the cooldown rejects a draw we
	// back off briefly to stop the iterator from looping hot.
	const cooldownRejectPause = 1 * time.Second

	// Poll interval while the outbound-slot budget is spent. Slots
	// free up on peer disconnect, which this loop can't observe
	// directly, so it re-checks on a coarse timer.
	const budgetFullPause = 5 * time.Second

	if srv.maxDialedConns() == 0 {
		// Dialing disabled (NoDial / MaxPeers=0).
		return
	}
	var prev time.Time
	for srv.v2Iter.Next() {
		select {
		case <-srv.quit:
			return
		default:
		}
		// Outbound-slot budget. The dial scheduler enforces
		// maxDialPeers on its own dials; this loop bypasses the
		// scheduler, so without a ceiling here a v2-native network
		// fills every MaxPeers slot with outbound peers — DialRatio
		// stops meaning anything and inbound capacity starves (late
		// inbound connections then bounce off the hard MaxPeers
		// check instead of triggering eviction). The budget is
		// shared with the scheduler by counting the live dialed
		// peer set rather than loop-local state.
		if srv.dialedOutboundCount() >= srv.maxDialedConns() {
			select {
			case <-srv.quit:
				return
			case <-time.After(budgetFullPause):
			}
			continue
		}
		cand := srv.v2Iter.Candidate()
		// Skip networks the policy has no route to. Entries on such
		// networks can sit in the addrbook legitimately — persisted
		// from a session that had a Tor route, or ingested before a
		// restart changed the flags — and Core's ThreadOpenConnections
		// skips them at selection time the same way.
		if !srv.NetworkReachable(cand.Addr.Network) {
			continue
		}
		now := time.Now()
		var sincePrev time.Duration
		if !prev.IsZero() {
			sincePrev = now.Sub(prev)
		}
		srv.log.Trace("pip6: runV2Dialer iter", "addr", cand.Addr.String(), "sincePrev", sincePrev)
		prev = now
		// Fill full-relay slots first; the block-relay-only bucket
		// fills once the full-relay target (total outbound budget
		// minus the reserved block-relay slots) is met. Bitcoin
		// Core's ThreadOpenConnections opens OUTBOUND_FULL_RELAY up
		// to m_max_outbound_full_relay before any BLOCK_RELAY
		// connection, and the scheduler path (pickDynDialFlags)
		// orders the same way — a fresh v2-native node must not
		// spend its earliest outbound sessions on peers that relay
		// neither transactions nor addresses.
		dial := srv.DialV2
		if v2DialWantsBlockRelay(srv.dialedOutboundCount(), srv.blockRelayOutboundCount(),
			srv.maxDialedConns(), srv.maxBlockRelayDial()) {
			dial = srv.DialV2BlockRelay
		}
		if err := dial(cand.Addr); err != nil {
			srv.log.Trace("v2 dial failed", "addr", cand.Addr, "err", err)
			if errors.Is(err, errV2DialCooldown) {
				select {
				case <-srv.quit:
					return
				case <-time.After(cooldownRejectPause):
				}
			}
		}
	}
}

// v2DialWantsBlockRelay reports whether the next addrman-driven v2
// dial should fill a block-relay-only slot instead of a full-relay
// one. Full-relay first, block-relay after — the same order as the
// scheduler's pickDynDialFlags and Bitcoin Core's
// ThreadOpenConnections. Pure function for unit testing; the live
// counts come from the peer set at pick time.
func v2DialWantsBlockRelay(dialedOutbound, blockRelayOutbound, maxDialed, maxBlockRelay int) bool {
	if maxBlockRelay <= 0 || blockRelayOutbound >= maxBlockRelay {
		return false
	}
	fullRelayTarget := maxDialed - maxBlockRelay
	if fullRelayTarget < 0 {
		fullRelayTarget = 0
	}
	return dialedOutbound-blockRelayOutbound >= fullRelayTarget
}

// DialV2 opens a v2-handshake TCP connection to the supplied address
// and hands the resulting peer to the normal run-loop checkpoints.
// Called by the v2 dial goroutine and by admin_dialV2 for operator
// testing.
//
// Skips the dial if any existing peer is already connected on the
// same (IP, TCP port). v2 sessions derive node.ID from ephemeral
// keys, so the Server's node.ID-keyed peer map can't dedupe on its
// own — short-circuit here before the TCP connection spends kernel
// resources on a duplicate handshake.
func (srv *Server) DialV2(addr addrman.NetAddr) error {
	_, err := srv.dialV2WithFlags(addr, 0)
	return err
}

// DialV2Manual is DialV2 for operator-initiated dials (admin_dialV2
// and admin_addPeer's ip:port form). The resulting conn is tagged
// staticDialedConn instead of dynDialedConn: the operator explicitly
// chose the endpoint, so it gets the same treatment as a v1 static
// dial — exempt from the discourage filter (a shared-IP neighbor's
// misbehavior must not strand an explicit dial until restart; Core's
// manual connections skip discouragement the same way), from the
// network-group diversity rule, and from the dynamic dial budget.
// The operator ban check still applies, the same documented
// divergence from Core as the v1 static path: setban is an explicit
// operator statement that outranks a dial request.
func (srv *Server) DialV2Manual(addr addrman.NetAddr) error {
	_, err := srv.dialV2WithFlags(addr, staticDialedConn)
	return err
}

// DialV2BlockRelay opens a v2-handshake TCP connection like DialV2
// but tags the resulting conn with the block-relay-only flag. Used
// at startup to replay anchors.dat — anchor peers are persisted
// outbound block-relay-only peers, so they should reattach in the
// same role.
func (srv *Server) DialV2BlockRelay(addr addrman.NetAddr) error {
	_, err := srv.dialV2WithFlags(addr, blockRelayConn)
	return err
}

// DialV2Feeler opens a v2-handshake TCP connection like DialV2 but
// tags the resulting conn as a feeler. Feeler conns are excluded
// from the dial scheduler's slot and network-group budget and never
// record an addrman failure on their deliberate short-lived
// disconnect. Used by the feeler and addrfetch loops.
//
// Returns the underlying conn so callers can tear the probe down by
// closing it after the feeler lifetime — the one teardown that works
// on every network: a proxied onion peer has no observable (IP,
// listen-port) an address-keyed disconnect could match.
func (srv *Server) DialV2Feeler(addr addrman.NetAddr) (net.Conn, error) {
	return srv.dialV2WithFlags(addr, feelerConn)
}

// dialV2WithFlags is the shared implementation. extra is OR'd into
// the standard (dynDialedConn|v2DialedConn) flag set so the caller
// can request block-relay-only or other future variants without
// duplicating the cooldown / self-endpoint / dedup checks.
func (srv *Server) dialV2WithFlags(addr addrman.NetAddr, extra connFlag) (net.Conn, error) {
	if len(addr.Bytes()) == 0 || addr.Port == 0 {
		return nil, errors.New("v2 dial: invalid address")
	}
	// tcp is the IP:port projection, nil for onion targets. The
	// IP-keyed guards below (netrestrict, banlist, self-endpoint,
	// dedup, netgroup) apply to it; their onion-side behavior is
	// annotated case by case.
	tcp := tcpFromNetAddr(addr)
	// NetRestrict: the operator's allowlist confines every dial,
	// exactly as checkDial enforces it on the scheduler path and
	// checkInboundConn on accept. Without this, a node locked to a
	// private range still dials arbitrary public IPs from addrman
	// and DNS seeds. The list is CIDR-based, so setting it implies
	// IP-only outbound: non-IP networks are refused outright
	// (PIP-0007 §4, netrestrict semantics).
	if srv.NetRestrict != nil && (tcp == nil || !srv.NetRestrict.Contains(tcp.IP)) {
		return nil, fmt.Errorf("v2 dial %s: %w", addr, errV2DialRestricted)
	}
	// Never make an automatic outbound connection to a banned or
	// discouraged address. Bitcoin Core gates outbound candidate
	// selection the same way (CConnman::OpenNetworkConnection,
	// src/net.cpp: IsBanned || IsDiscouraged). Without this the
	// inbound-only accept-time gate is trivially bypassed: a banned
	// peer stays in the addrbook and the dial scheduler reconnects
	// to it as an outbound peer within one cooldown.
	//
	// Manual dials (staticDialedConn) skip the discourage half:
	// discouragement is stamped automatically and has no clearing
	// RPC, so honoring it on an operator-chosen endpoint would
	// strand the dial until restart — same exemption as the v1
	// static path in checkDial. The ban check stays: setban is an
	// explicit operator statement.
	// Never make an automatic outbound connection to a banned or
	// discouraged target. IP targets check ban + discourage; onion
	// targets check the exact-host ban list (there is no discourage
	// tier for onion — the filter is IP-keyed and inbound onion
	// streams can't be attributed to an onion address anyway).
	if srv.BanList != nil {
		banned := false
		switch {
		case tcp != nil:
			banned = srv.BanList.IsBanned(tcp.IP) ||
				(!extraHas(extra, staticDialedConn) && srv.BanList.IsDiscouraged(tcp.IP))
		case addr.Network == addrman.NetTorV3:
			banned = srv.BanList.IsBannedHost(addr.OnionHostname())
		}
		if banned {
			srv.addrmanAttemptAddr(addr, false)
			return nil, fmt.Errorf("v2 dial %s: %w", addr, errV2DialBanned)
		}
	}
	// --onlynet restricts automatic outbound connections only;
	// operator-initiated dials (admin_addPeer / admin_dialV2, tagged
	// staticDialedConn) reach any network the node has a route to,
	// as in Core. Checked after the ban gate so a banned address
	// reports banned whatever the policy says about its network.
	if !extraHas(extra, staticDialedConn) && !srv.NetworkReachable(addr.Network) {
		return nil, fmt.Errorf("v2 dial %s: %w", addr, errUnreachableNetwork)
	}
	if !srv.v2DialCooldownCheckAndMark(addr) {
		return nil, fmt.Errorf("v2 dial %s: %w", addr, errV2DialCooldown)
	}
	// Self and duplicate detection are (IP, listen-port)-keyed. An
	// onion target can be neither matched against our own endpoint
	// (we have no onion identity until phase 3 creates the service)
	// nor deduped against connected peers (a proxied peer's remote
	// addr is the proxy); both checks pass onion targets through, and
	// the cooldown above is what bounds re-dials meanwhile.
	if srv.isSelfNetAddr(addr) {
		srv.log.Debug("v2 dial skipped (self endpoint)", "addr", addr.String())
		return nil, fmt.Errorf("v2 dial %s: %w", addr, errV2DialSelf)
	}
	// Duplicate suppression, two complementary matchers: the listen
	// addr comparison (IP targets only — onion peers expose no listen
	// addr) and the dial-target comparison, which covers every
	// network. Either match refreshes LastTry without
	// counting a failure: addrman's Select chance weighting drops
	// ~100x for 10 min once LastTry is recent, so the iterator stops
	// burning cycles re-picking an endpoint we already peer with.
	if (tcp != nil && srv.alreadyConnectedTo(tcp)) || srv.connectedToDialTarget(addr) {
		srv.addrmanAttemptAddr(addr, false)
		return nil, fmt.Errorf("v2 dial %s: already connected", addr)
	}
	srv.log.Trace("pip6: DialV2 enter", "addr", addr.String(), "peers", len(srv.Peers()), "extra", extra)
	// Network-group diversity for outbound dials. Refuse a second
	// outbound peer in the same /16 (IPv4) or /32 (IPv6) group so an
	// attacker can't fill our outbound slots from one network.
	// Mirrors Bitcoin Core's outbound_ipv46_peer_netgroups guard
	// (src/net.cpp ThreadOpenConnections): full-relay, block-relay-
	// only and anchor connections are all subject to the rule — the
	// block-relay slots exist for eclipse resistance, so letting them
	// cluster in one group would defeat their purpose. Only feeler
	// probes are exempt; they are transient and never hold a slot.
	// The v1/v2 dial scheduler enforces the same rule in checkDial;
	// this covers runV2Dialer and the anchor replay, which dial
	// without going through the scheduler.
	// The group key comes from the dial target — onion targets group
	// by the top-4-bits rule, and proxied IP targets keep their real
	// group rather than the proxy's.
	if v2DialSubjectToGroupLimit(extra) {
		if g := groupKeyForNetAddr(addr); g != "" && srv.outboundGroupOccupied(g) {
			srv.addrmanAttemptAddr(addr, false)
			return nil, fmt.Errorf("v2 dial %s: %w", addr, errV2DialGroupOccupied)
		}
	}
	// Dial under quitCtx so Stop interrupts an in-flight connect
	// (e.g. a feeler probing a SYN-blackholed address) instead of
	// waiting out the remainder of the 15s timeout in loopWG.Wait.
	ctx := srv.quitCtx
	if ctx == nil {
		ctx = context.Background()
	}
	fd, err := srv.dialConnector().Connect(ctx, addr)
	if err != nil {
		// Routing problems on our side (no route to the network, the
		// proxy leg failed) carry no evidence about the destination
		// and must not push it toward IsTerrible.
		srv.addrmanAttemptAddr(addr, dialCountsAsFailure(err))
		return nil, fmt.Errorf("v2 dial %s: %w", addr, err)
	}
	// Flags: dynDialedConn so the run loop slots it correctly, plus
	// v2DialedConn so pickHandshakeVariant picks the v2 transport.
	// extra carries blockRelayConn for anchor replays / block-relay
	// bucket fills, feelerConn for probes, or staticDialedConn for
	// manual dials — which replaces dynDialedConn rather than
	// combining with it, so downstream accounting sees exactly one
	// dial class.
	flags := dynDialedConn | v2DialedConn | extra
	if extraHas(extra, staticDialedConn) {
		flags &^= dynDialedConn
	}
	// Network classification (PIP-0007 §3.2): the dial target's
	// network is authoritative for outbound peers, and a proxied
	// conn's RemoteAddr is the proxy — downstream address logic
	// (YourAddr reporting, dedup) must not treat it as the peer's.
	if addr.Network == addrman.NetTorV3 {
		flags |= onionConn
	}
	if srv.policy().proxyFor(addr.Network) != nil {
		flags |= proxiedConn
	}
	if err := srv.setupConnTarget(fd, flags, nil, addr); err != nil {
		// v2 handshake / protocol negotiation failed before a Peer
		// object was constructed, so the delpeer path never runs
		// and addrman never learns the entry is unreachable. Record
		// it here so IsTerrible can eventually evict it — except for
		// feelers, where the failure is often our own admission
		// rejection rather than a reachability problem, and counting
		// it would penalize an address we have no evidence against.
		//
		// A DiscReason-typed error means the TCP connect and enough
		// of the handshake succeeded for a protocol-level rejection —
		// our own admission checks (saturation, duplicate, self) or
		// the remote's. Either way the address is provably reachable:
		// refresh LastTry so Select stops re-picking it for a while,
		// but don't count a failure toward IsTerrible.
		if !extraHas(extra, feelerConn) {
			var reason DiscReason
			if errors.As(err, &reason) {
				srv.addrmanAttemptAddr(addr, false)
			} else {
				srv.addrmanAttemptAddr(addr, true)
			}
		}
		return nil, err
	}
	return fd, nil
}

// extraHas reports whether the extra flag set includes f.
func extraHas(extra, f connFlag) bool { return extra&f != 0 }

// v2DialSubjectToGroupLimit reports whether a v2 dial carrying the
// given extra flags is subject to the outbound network-group
// diversity rule. Feeler probes are exempt (transient, never hold a
// slot) and so are manual dials (staticDialedConn: the operator chose
// the endpoint, matching checkDial's static exemption and Core's
// manual connections) — full-relay, block-relay-only and anchor dials
// are all group-limited, as in Core's ThreadOpenConnections. Kept as
// a named predicate so the exemption set is pinned by a unit test: an
// earlier version exempted everything with a non-zero extra, quietly
// letting block-relay and anchor fills cluster in one /16.
func v2DialSubjectToGroupLimit(extra connFlag) bool {
	return !extraHas(extra, feelerConn) && !extraHas(extra, staticDialedConn)
}

// outboundGroupOccupied reports whether any current non-feeler
// outbound peer falls in the given network-group key. Used by the
// v2 dial path to enforce outbound /16 (IPv4) / /32 (IPv6) diversity
// for addrman-driven dials that bypass the dial scheduler. Inbound
// peers are ignored (we don't choose their source network) and
// feeler probes are transient.
func (srv *Server) outboundGroupOccupied(group string) bool {
	occupied := false
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		occupied = outboundGroupOccupiedIn(peers, group)
	})
	return occupied
}

// outboundGroupOccupiedIn is the pure core of outboundGroupOccupied,
// split out so it can be unit-tested without a running run loop.
func outboundGroupOccupiedIn(peers map[enode.ID]*Peer, group string) bool {
	for _, p := range peers {
		if p.rw.is(inboundConn) || p.rw.is(feelerConn) {
			continue
		}
		// Prefer the dialed target: a proxied peer's RemoteAddr is
		// the SOCKS5 proxy, and an onion peer has no IP at all.
		if t := p.rw.dialTarget(); t.Network != 0 {
			if groupKeyForNetAddr(t) == group {
				return true
			}
			continue
		}
		ra, ok := p.RemoteAddr().(*net.TCPAddr)
		if !ok {
			continue
		}
		if ipNetworkGroupKey(ra.IP) == group {
			return true
		}
	}
	return false
}

// dialedOutboundCount returns the number of live dialed outbound
// peers — dynamic and static alike, block-relay-only included, feeler
// probes excluded. This is the count the v2 dial loop holds against
// maxDialedConns. Statics count because the v1 scheduler's
// maxDialPeers accounting counts them too (dial.go peerAdded:
// dialPeers++ for dyn and static): two dialers filling one outbound
// budget must agree on what consumes it, or the effective total
// depends on which path fills first.
func (srv *Server) dialedOutboundCount() int {
	n := 0
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		n = dialedOutboundCountIn(peers)
	})
	return n
}

// dialedOutboundCountIn is the pure core of dialedOutboundCount,
// split out for unit testing.
func dialedOutboundCountIn(peers map[enode.ID]*Peer) int {
	n := 0
	for _, p := range peers {
		if (p.rw.is(dynDialedConn) || p.rw.is(staticDialedConn)) && !p.rw.is(feelerConn) {
			n++
		}
	}
	return n
}

// nonFeelerLen counts peers excluding live feeler probes. Core
// excludes feelers from connection counts in both directions, so a
// probe's short lifetime must not cause hard-rejects of real peers
// arriving at saturation.
func nonFeelerLen(peers map[enode.ID]*Peer) int {
	n := 0
	for _, p := range peers {
		if !p.rw.is(feelerConn) {
			n++
		}
	}
	return n
}

// blockRelayOutboundCount returns the number of current outbound
// block-relay-only peers. Used by runV2Dialer to decide whether the
// next addrman-driven dial should fill a block-relay-only slot. This
// reads the authoritative live peer set rather than the dial
// scheduler's loop-owned counter, so it stays correct across both
// the scheduler and the separate v2 dial loop.
func (srv *Server) blockRelayOutboundCount() int {
	n := 0
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		n = blockRelayOutboundCountIn(peers)
	})
	return n
}

// blockRelayOutboundCountIn is the pure core of
// blockRelayOutboundCount, split out for unit testing.
func blockRelayOutboundCountIn(peers map[enode.ID]*Peer) int {
	n := 0
	for _, p := range peers {
		if !p.rw.is(inboundConn) && p.rw.is(blockRelayConn) {
			n++
		}
	}
	return n
}

// addrmanAttempt records a dial attempt in addrman. countFailure=true
// bumps the failure counter so IsTerrible can eventually evict
// unreachable entries; pass false to update only LastTry (throttles
// re-selection without signalling unreachability — used when we
// short-circuit a dial because we're already peered with the
// endpoint via a different transport).
func (srv *Server) addrmanAttemptAddr(addr addrman.NetAddr, countFailure bool) {
	if srv.addrbook == nil {
		return
	}
	srv.addrbook.Attempt(addr, countFailure, time.Now())
}

// v2DialCooldown is the minimum interval between successive v2 dial
// attempts to the same (IP, port). Select's chanceFactor ramp
// guarantees addrman returns a candidate regardless of LastTry, so
// chance-based throttling isn't a rate-limit when the KeyType=0
// cohort is small; this is the authoritative gate.
const v2DialCooldown = 30 * time.Second

// errV2DialCooldown is the sentinel returned by DialV2 when the
// per-addr cooldown rejects an attempt. Callers check with
// errors.Is to back off instead of treating the rejection as a
// real failure.
var errV2DialCooldown = errors.New("v2 dial cooldown")

// errV2DialSelf is the sentinel returned by DialV2 when the dial
// target matches this node's own advertised (IP, TCP) endpoint.
// v2 sessions derive node.ID from ephemeral X25519 keys, so the
// node.ID-keyed self-check in postHandshakeChecks cannot fire for
// v2 peers — without this guard, a node behind a hairpinning NAT
// dials its own external IP and accepts the looped-back TCP
// connection as a peer.
var errV2DialSelf = errors.New("v2 dial self")

// errV2DialBanned is the sentinel returned by DialV2 when the dial
// target's IP is banned or discouraged. Callers back off rather
// than counting it as a connection failure.
var errV2DialBanned = errors.New("v2 dial banned")

// errV2DialRestricted is the sentinel returned by DialV2 when the
// dial target falls outside the operator's --netrestrict allowlist.
// Callers back off; the address is off-limits by policy, not
// unreachable.
var errV2DialRestricted = errors.New("v2 dial outside netrestrict")

// errV2DialGroupOccupied is the sentinel returned by DialV2 when a
// full-relay outbound peer already occupies the target's network
// group. Callers back off; not a reachability failure.
var errV2DialGroupOccupied = errors.New("v2 dial network group occupied")

// v2DialCooldownCheckAndMark returns true and records addr's dial
// timestamp if the cooldown has elapsed; returns false otherwise.
// Serialized so concurrent callers (runV2Dialer, dial-scheduler v2
// branch, admin RPC) agree on the decision.
func (srv *Server) v2DialCooldownCheckAndMark(addr addrman.NetAddr) bool {
	key := addr.String()
	now := time.Now()
	srv.v2DialRecentMu.Lock()
	defer srv.v2DialRecentMu.Unlock()
	if srv.v2DialRecent == nil {
		srv.v2DialRecent = make(map[string]time.Time)
	}
	if last, ok := srv.v2DialRecent[key]; ok && now.Sub(last) < v2DialCooldown {
		return false
	}
	srv.v2DialRecent[key] = now
	// Opportunistic purge — cheap because the map is small.
	for k, t := range srv.v2DialRecent {
		if now.Sub(t) >= v2DialCooldown {
			delete(srv.v2DialRecent, k)
		}
	}
	return true
}

// IsSelfEndpoint reports whether addr matches this node's own
// advertised (IP, TCP) endpoint. Exported so external wiring (the
// disc-protocol AddrmanBackend, the addrman V2Iter) can consult
// the same source of truth as the dial / handshake guards. Used
// to short-circuit v2 dials that would hairpin through the NAT
// and arrive back at our own listener, and as a defense-in-depth
// check in postHandshakeChecks for v2 connections that bypass the
// dial guard.
//
// A dial counts as self when ANY of these hold:
//
//   - the address (IP, port) matches localnode's advertised TCP
//     endpoint (the ordinary case once setupListening publishes
//     the port);
//   - the address is loopback (127.0.0.0/8, ::1) and the port
//     matches our listen port (a localhost dial to our own
//     listener);
//   - the address is loopback and our listen port is not yet
//     published — during the brief Start()-window before
//     setupListening assigns the TCP port to localnode, any
//     loopback dial is treated as self because no legitimate
//     caller (admin RPC, anchor replay, feeler, runV2Dialer)
//     ever wants to dial loopback at this stage.
//
// The loopback-only fallback in the port-0 branch closes the
// startup-window gap without false-positiving real external
// peers: a dial to a remote host's IP cannot match loopback.
func (srv *Server) IsSelfEndpoint(addr *net.TCPAddr) bool {
	if addr == nil || srv.localnode == nil {
		return false
	}
	n := srv.localnode.Node()
	selfPort := n.TCP()
	if selfPort == 0 {
		// No advertised TCP port. Two distinct cases:
		//   - We are configured not to listen (ListenAddr == ""):
		//     there is no listener a loopback dial could hairpin
		//     into, so dialing 127.0.0.1 reaches a co-hosted node,
		//     not ourselves. Not self. Without this, a non-listening
		//     node could never dial a co-hosted peer over loopback
		//     for the whole process lifetime.
		//   - We intend to listen but haven't bound yet (startup
		//     window): a loopback dial could hairpin once the
		//     listener comes up, so treat it as self out of caution.
		if srv.ListenAddr == "" {
			return false
		}
		return addr.IP.IsLoopback()
	}
	if addr.Port != selfPort {
		return false
	}
	// Same port: self if the IP matches the advertised one OR is
	// loopback (127.0.0.1 -> own listener regardless of advertised IP).
	return addr.IP.Equal(n.IP()) || addr.IP.IsLoopback()
}

// isSelfNetAddr adapts the self-endpoint checks to addrman.NetAddr
// candidates (the V2Iter self-gate and the shared v2 dial path): the
// (IP, listen-port) match for IP targets, our own onion service for
// Tor targets. A self-dial that still slips through (e.g. the service
// established after the check) is caught by the Hello nonce
// self-connect check like any other v2 session.
func (srv *Server) isSelfNetAddr(addr addrman.NetAddr) bool {
	if tcp := tcpFromNetAddr(addr); tcp != nil {
		return srv.IsSelfEndpoint(tcp)
	}
	return srv.isSelfOnion(addr)
}

// peerListenAddr returns the peer's effective (IP, listen-port) for
// dedup. For outbound peers, RemoteAddr is the dial target — its port
// IS the peer's listen port. For inbound peers, RemoteAddr's port is
// the ephemeral source they connected from; substitute the listen
// port the peer disclosed via parallax-disc/1 Hello when available.
// Returns ok=false in two cases:
//   - non-TCP RemoteAddr (test pipes, tunneled transports);
//   - inbound peer with no disclosed listen port yet (pre-Hello window
//     or v1 peer that doesn't speak the extension).
//
// Callers using this for dedup must treat ok=false as "no signal" —
// it's not safe to assume the peer's listen address.
func (srv *Server) peerListenAddr(p *Peer) (*net.TCPAddr, bool) {
	if !p.rw.is(inboundConn) {
		// Outbound: the dial target is the peer's listen endpoint.
		// Prefer the conn's recorded target — a proxied conn's
		// RemoteAddr is the SOCKS5 proxy, which made every proxied
		// peer look like the same endpoint (and cross-dial dedup
		// then tore down healthy peers as duplicates). Onion targets
		// have no ip:port form and yield ok=false — an onion peer
		// cannot be address-deduped.
		if t := p.rw.dialTarget(); t.Network != 0 {
			if tcp := tcpFromNetAddr(t); tcp != nil {
				return tcp, true
			}
			return nil, false
		}
		if p.rw.is(proxiedConn) {
			// Dialed through a proxy with no recorded target (a
			// hostname seed fetch): RemoteAddr is the proxy, so the
			// peer's listen address is simply unknown. Reporting the
			// proxy would make every such session look like the same
			// endpoint.
			return nil, false
		}
		pra, ok := p.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return nil, false
		}
		return pra, true
	}
	pra, ok := p.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, false
	}
	if srv.peerListenLookup == nil {
		return nil, false
	}
	port, ok := srv.peerListenLookup.PeerListenPort(p.ID())
	if !ok || port == 0 {
		return nil, false
	}
	return &net.TCPAddr{IP: pra.IP, Port: int(port)}, true
}

// PeerListenAddr is the exported wrapper around peerListenAddr.
// Used by the parallax-disc/1 AddrmanBackend's cross-dial dedup
// hook so the disc package doesn't need to duplicate the
// outbound/inbound branching logic.
func (srv *Server) PeerListenAddr(p *Peer) (*net.TCPAddr, bool) {
	return srv.peerListenAddr(p)
}

// connectedToDialTarget reports whether any live peer's recorded dial
// target equals addr. This is the dedup that works on every network,
// including onion targets, which expose no listen address to compare.
// Feelers are excluded — a probe must not suppress real dials.
func (srv *Server) connectedToDialTarget(addr addrman.NetAddr) bool {
	found := false
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		for _, p := range peers {
			if p.rw.is(feelerConn) {
				continue
			}
			if t := p.rw.dialTarget(); t.Network != 0 && t.Equal(addr) {
				found = true
				return
			}
		}
	})
	return found
}

// alreadyConnectedTo reports whether any current peer's effective
// listen-addr matches addr's (IP, port). Used by DialV2 to dedupe v2
// dial targets that can't be caught by node.ID-keyed matching.
//
// Inbound peers contribute to this check only after disclosing their
// listen port via Hello; in the brief window between TCP-up and Hello
// receipt, an outbound dial to the same logical peer can race through.
// The post-Hello cross-dial dedup hook in AddrmanBackend.HandleHello
// resolves the resulting duplicate by dropping the inbound side.
func (srv *Server) alreadyConnectedTo(addr *net.TCPAddr) bool {
	for _, p := range srv.Peers() {
		// Feelers are transient probes; one must never suppress a
		// real dial to the same address (the cold-start addr-fetch
		// probes exactly the bootstrap addresses the dialer needs).
		if p.rw.is(feelerConn) {
			continue
		}
		la, ok := srv.peerListenAddr(p)
		if !ok {
			continue
		}
		if la.Port == addr.Port && la.IP.Equal(addr.IP) {
			return true
		}
	}
	return false
}

// FindCrossDialDup looks for an existing peer (other than newPeer)
// whose effective listen-addr matches (newPeer.IP, listenPort).
// Returns nil if none. Called by AddrmanBackend.HandleHello after
// a peer discloses its listen port: if a duplicate exists, one of
// the two connections must be torn down to avoid double-counting
// the logical neighbor. Tie-break logic lives at the call site.
func (srv *Server) FindCrossDialDup(newPeer *Peer, listenPort uint16) *Peer {
	return srv.findCrossDialDupIn(srv.Peers(), newPeer, listenPort)
}

// findCrossDialDupIn is the testable core: same logic but operates
// over a caller-supplied peer slice instead of pulling the current
// set through the run loop. Tests synthesize fake peers and drive
// it directly without standing up Start().
//
// Trust model (security): the listen port is only verified for an
// OUTBOUND newPeer — there we dialed the endpoint ourselves, so
// RemoteAddr() is its real (IP, port) and we ignore the self-claimed
// Hello port. For an INBOUND newPeer the Hello port is unverified: a
// peer sharing a source IP (CGNAT/shared host/NAT) could pre-claim a
// victim's listen port to make an honest connection look like a
// duplicate. To keep the dedup from being weaponized while preserving
// the legitimate symmetric-dial case it exists for, a match requires a
// trusted anchor on at least one side: we never dedup two connections
// whose linkage rests solely on unverified inbound Hello ports. Because
// the tie-break (selectCrossDialLoser) always drops the inbound side of
// a mixed pair, this guarantees an existing honest connection is never
// torn down on the strength of another inbound peer's port claim.
func (srv *Server) findCrossDialDupIn(peers []*Peer, newPeer *Peer, listenPort uint16) *Peer {
	if newPeer == nil || listenPort == 0 {
		return nil
	}
	newInbound := newPeer.rw.is(inboundConn)
	var target *net.TCPAddr
	if !newInbound {
		// Trusted target: for an outbound newPeer use the dial
		// target — its port, not the self-claimed Hello port, so an
		// outbound peer can't inject a victim's port via Hello; and
		// its address from the conn's recorded target rather than
		// RemoteAddr, which for a proxied conn is the SOCKS5 proxy
		// and made every proxied peer dedup against every other. An
		// onion target has no ip:port form; onion peers are exempt
		// from address dedup.
		if t := newPeer.rw.dialTarget(); t.Network != 0 {
			target = tcpFromNetAddr(t)
		} else if pra, ok := newPeer.RemoteAddr().(*net.TCPAddr); ok {
			target = pra
		}
	} else {
		pra, ok := newPeer.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return nil
		}
		target = &net.TCPAddr{IP: pra.IP, Port: int(listenPort)}
	}
	if target == nil {
		return nil
	}
	for _, p := range peers {
		if p == newPeer {
			continue
		}
		// Refuse to dedup when both sides are inbound: the match would
		// rest entirely on unverified Hello ports, and the loser could
		// be an honest connection an attacker framed by pre-claiming its
		// port. Legitimate cross-dial duplicates always involve an
		// outbound leg (our dial to the peer, or the peer's dial to us),
		// which is preserved below.
		if newInbound && p.rw.is(inboundConn) {
			continue
		}
		la, ok := srv.peerListenAddr(p)
		if !ok {
			continue
		}
		if la.Port == target.Port && la.IP.Equal(target.IP) {
			return p
		}
	}
	return nil
}

// logStartup emits the node's starting address as plain ip:port
// rather than a full enode URL. The URL form hard-couples to the v1.x
// identity model, which misleads operators running in v2-only mode
// (where the persistent secp256k1 key doesn't participate in any
// handshake). For v1.x-compatible modes the enode URL is still worth
// having — we emit it at debug level as a secondary line.
func (srv *Server) logStartup() {
	n := srv.localnode.Node()
	srv.log.Info("Started P2P networking",
		"address", formatAddr(n.IP(), n.TCP()),
		"mode", srv.startupModeString())
	if srv.legacyHandshakeMode() != legacyHandshakeOff {
		srv.log.Debug("Legacy enode URL", "self", n.URLv4())
	}
}

// formatAddr renders an ip/port pair as "ip:port", bracketing IPv6
// to keep the colon separator unambiguous.
func formatAddr(ip net.IP, port int) string {
	return (&net.TCPAddr{IP: ip, Port: port}).String()
}

// startupModeString describes the handshake/discovery posture for the
// startup banner.
func (srv *Server) startupModeString() string {
	switch srv.legacyDiscoveryMode() {
	case legacyDiscoveryOff:
		return "v2-only"
	case legacyDiscoveryOn:
		return "legacy+v2 (discv4-full)"
	}
	return "legacy+v2 (discv4-responder)"
}

// watchLocalAddrChanges polls the LocalNode's advertised IP/port and
// logs a follow-up line when they change — typically when NAT/UPnP
// resolves the public IP or the ENR is refreshed by a peer observation.
// The poll cadence matches the LocalNode's internal refresh rate
// closely enough; precise hooks would require a subscription API on
// LocalNode that doesn't exist yet.
func (srv *Server) watchLocalAddrChanges() {
	prevIP := srv.localnode.Node().IP()
	prevPort := srv.localnode.Node().TCP()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-srv.quit:
			return
		case <-tick.C:
			n := srv.localnode.Node()
			ip, port := n.IP(), n.TCP()
			if !ip.Equal(prevIP) || port != prevPort {
				srv.log.Info("P2P external address updated", "address", formatAddr(ip, port))
				prevIP, prevPort = ip, port
			}
		}
	}
}

// LegacyHandshakeRefused reports whether this Server is in v2-only
// mode (--legacy-discovery=off). Exposed for RPC handlers that want
// to branch on the transport posture — e.g., admin_addPeer rejects
// enode:// targets in this mode because the legacy handshake is
// refused both inbound and outbound.
func (srv *Server) LegacyHandshakeRefused() bool {
	return srv.legacyHandshakeMode() == legacyHandshakeOff
}

// DisconnectByAddr finds the first connected peer whose RemoteAddr
// matches the given TCP address and disconnects it. Returns true if
// a matching peer was found. Used by admin_removePeer in v2 mode
// because v2 peer identities are session-ephemeral and can't be used
// as stable lookup keys.
func (srv *Server) DisconnectByAddr(addr *net.TCPAddr) bool {
	na, ok := netAddrFromTCP(addr)
	if !ok {
		return false
	}
	return srv.DisconnectByNetAddr(na)
}

// DisconnectByNetAddr disconnects the first peer matching addr on any
// network, and reports whether one was found. A peer matches on its
// dial target when it has one — the only handle on an onion peer, and
// the correct one for a proxied peer, whose RemoteAddr is the SOCKS5
// proxy and would otherwise match every peer sharing that proxy — and
// otherwise on its socket address.
func (srv *Server) DisconnectByNetAddr(addr addrman.NetAddr) bool {
	if len(addr.Bytes()) == 0 {
		return false
	}
	want := tcpFromNetAddr(addr)
	for _, p := range srv.Peers() {
		if t := p.rw.dialTarget(); t.Network != 0 {
			if t.Equal(addr) {
				p.Disconnect(DiscRequested)
				return true
			}
			continue
		}
		if want == nil || p.rw.is(proxiedConn) {
			continue
		}
		ra, ok := p.RemoteAddr().(*net.TCPAddr)
		if !ok {
			continue
		}
		if ra.Port == want.Port && ra.IP.Equal(want.IP) {
			p.Disconnect(DiscRequested)
			return true
		}
	}
	return false
}

// DisconnectMatching disconnects every peer whose address satisfies
// match, and returns how many were dropped. Peers are matched by dial
// target when they have one, else by socket address; proxied peers
// without a target are skipped, since their socket address is the
// proxy's. Used by setban to enforce a fresh ban immediately.
func (srv *Server) DisconnectMatching(match func(addrman.NetAddr) bool) int {
	if match == nil {
		return 0
	}
	dropped := 0
	for _, p := range srv.Peers() {
		var cand addrman.NetAddr
		if t := p.rw.dialTarget(); t.Network != 0 {
			cand = t
		} else if !p.rw.is(proxiedConn) {
			if ra, ok := p.RemoteAddr().(*net.TCPAddr); ok {
				if na, ok := netAddrFromTCP(ra); ok {
					cand = na
				}
			}
		}
		if cand.Network == 0 || !match(cand) {
			continue
		}
		p.Disconnect(DiscRequested)
		dropped++
	}
	return dropped
}

// AddrBook returns the server's address manager, or nil when
// ExperimentalAddrMan is not enabled. Upstream packages register the
// parallax-disc/1 subprotocol against this book — doing the
// registration here would create an import cycle with
// p2p/protocols/disc.
func (srv *Server) AddrBook() *addrman.AddrMan { return srv.addrbook }

// addrmanGood marks the peer's address as verified in the addrman and
// refreshes the entry's identity with what the session proved
// first-hand. No-op when ExperimentalAddrMan is off. Called from the
// run-loop right after an outbound peer joins the peers map — the
// caller's !p.Inbound() guard is load-bearing for the identity update
// below.
func (srv *Server) addrmanGood(p *Peer) {
	if srv.addrbook == nil {
		return
	}
	addr, ok := peerAdvertisedAddr(p)
	if !ok {
		return
	}
	srv.log.Trace("pip6: addrmanGood",
		"addr", addr.String(),
		"isV2", p.UsingV2Handshake(),
		"id", p.ID())
	srv.addrbook.Good(addr, time.Now())
	srv.upgradeAddrIdentity(p, addr)
}

// upgradeAddrIdentity overwrites the addrman entry's KeyType/NodeID
// with what an outbound session proved first-hand — Bitcoin Core's
// rule that direct connections overwrite while gossip only adds
// (SetServices on an outbound peer's VERSION message,
// src/net_processing.cpp:3606-3612, vs gossiped services OR-ed in
// src/addrman.cpp:574; our gossip half already matches — addSingle
// only sets identity on create). Without this, an entry gossiped with
// a stale secp256k1 identity outlives the node's re-key or v2-only
// switch forever: Good() keeps refreshing the entry on every v2
// success while its identity never changes, so the network keeps
// relaying a NodeID nobody can complete a legacy handshake against.
//
// Rules (outbound sessions only — inbound peers' advertised endpoints
// are self-claimed, so they are not ground truth for the address):
//
//   - v2 session: set KeyType 0x00, clear NodeID. We dialed the
//     address and completed the BIP324 handshake, so the endpoint is
//     v2-dialable, and 0x00 is strictly more dialable in a network
//     where the v2 handshake is always on.
//   - legacy session: refresh NodeID only when the entry is already
//     KeyType 0x01 (heals a stale key after a re-key — the RLPx
//     handshake verified the key we dialed). Never downgrade
//     0x00 → 0x01: v1-success does not imply v2-failure, and 0x01
//     would hide a legitimate dual-stack peer from V2Iter.
func (srv *Server) upgradeAddrIdentity(p *Peer, addr addrman.NetAddr) {
	if p.UsingV2Handshake() {
		if srv.addrbook.UpgradeIdentity(addr, 0x00, nil) {
			srv.log.Debug("Addrman entry confirmed v2", "addr", addr.String())
		}
		return
	}
	info := srv.addrbook.Lookup(addr)
	if info == nil || info.KeyType != 0x01 {
		return
	}
	nodeID, err := addrman.PubkeyBytes(p.Node())
	if err != nil {
		return
	}
	if srv.addrbook.UpgradeIdentity(addr, 0x01, nodeID) {
		srv.log.Debug("Addrman entry legacy key refreshed", "addr", addr.String())
	}
}

// peerAdvertisedAddr returns the addrman.NetAddr form of a Peer's
// advertised listening endpoint — (IP, TCP) from p.Node() rather than
// the TCP socket's RemoteAddr. Inbound v1 peers' RemoteAddr carries
// the ephemeral source port, which doesn't match the addrman entry
// keyed by the peer's listening port; p.Node() is rebuilt in
// SetupConn for inbound v1 to hold the handshake-advertised port.
// Outbound v1 peers have c.node = dialDest, which already carries
// the correct listening port.
func peerAdvertisedAddr(p *Peer) (addrman.NetAddr, bool) {
	// An outbound dial target is the advertised endpoint we used —
	// authoritative for proxied and onion peers, whose socket and
	// node record carry the proxy's address at best.
	if t := p.rw.dialTarget(); t.Network != 0 {
		return t, true
	}
	n := p.Node()
	if n == nil {
		return addrman.NetAddr{}, false
	}
	ip := n.IP()
	port := n.TCP()
	if ip == nil || port == 0 {
		return peerRemoteAddr(p)
	}
	if v4 := ip.To4(); v4 != nil {
		a, err := addrman.NewNetAddr(addrman.NetIPv4, v4, uint16(port))
		if err != nil {
			return addrman.NetAddr{}, false
		}
		return a, true
	}
	if v6 := ip.To16(); v6 != nil {
		a, err := addrman.NewNetAddr(addrman.NetIPv6, v6, uint16(port))
		if err != nil {
			return addrman.NetAddr{}, false
		}
		return a, true
	}
	return addrman.NetAddr{}, false
}

// replayAnchors reads the persisted block-relay-only anchor list
// (anchors.dat) and re-dials each entry as block-relay-only. The
// file is deleted immediately after a successful read so a crash
// during startup doesn't replay the same anchors twice (matches
// Bitcoin Core src/net.cpp:2715-2716 post-read delete).
//
// Each replay dial runs in its own goroutine so a slow DNS / dial
// doesn't block server startup. Failures are logged but never
// propagated — anchors are best-effort hints.
func (srv *Server) replayAnchors() {
	if srv.AnchorsPath == "" || srv.NoDial {
		return
	}
	// An operator who disabled the block-relay bucket
	// (MaxBlockRelayPeers < 0) must not get block-relay peers
	// resurrected from a stale anchors.dat — and persistAnchors
	// would then re-write them on shutdown, carrying the bypass
	// across restarts indefinitely. Still delete the file (anchors
	// are ephemeral hints either way).
	if srv.maxBlockRelayDial() <= 0 {
		if err := removeAnchors(srv.AnchorsPath); err != nil {
			srv.log.Warn("anchors: remove with block-relay disabled failed", "path", srv.AnchorsPath, "err", err)
		}
		return
	}
	addrs, err := loadAnchors(srv.AnchorsPath)
	if err != nil {
		// Delete the unreadable file: anchors are ephemeral hints,
		// and keeping a corrupt one around just repeats this warning
		// on every startup forever. Core deletes anchors.dat after
		// reading it regardless of parse outcome.
		srv.log.Warn("anchors: load failed; deleting file", "path", srv.AnchorsPath, "err", err)
		if rerr := removeAnchors(srv.AnchorsPath); rerr != nil {
			srv.log.Warn("anchors: remove unreadable file failed", "path", srv.AnchorsPath, "err", rerr)
		}
		return
	}
	// Delete the file unconditionally, even on a clean read, so a
	// crash mid-startup doesn't double-dial. Bitcoin parity.
	if err := removeAnchors(srv.AnchorsPath); err != nil {
		srv.log.Warn("anchors: remove after load failed", "path", srv.AnchorsPath, "err", err)
	}
	if len(addrs) == 0 {
		return
	}
	srv.log.Info("anchors: replaying block-relay-only peers", "count", len(addrs))
	for _, a := range addrs {
		// An anchor on a network the current policy can't reach (an
		// onion anchor after a restart without a Tor route) is
		// skipped, not an error — the file is already deleted either
		// way.
		if !srv.NetworkReachable(a.Network) {
			// Deferred, not dropped: the route may still come up (the
			// torcontrol auto-proxy resolves after Start).
			srv.log.Debug("anchors: deferring anchor on unreachable network", "addr", a)
			srv.pendingAnchorsMu.Lock()
			srv.pendingAnchors = append(srv.pendingAnchors, a)
			srv.pendingAnchorsMu.Unlock()
			continue
		}
		srv.loopWG.Add(1)
		go func() {
			defer srv.loopWG.Done()
			if err := srv.DialV2BlockRelay(a); err != nil {
				srv.log.Trace("anchor dial failed", "addr", a, "err", err)
			}
		}()
	}
}

// persistAnchors snapshots the (IP, listen-port) of the given
// block-relay-only outbound peers (capped at MaxBlockRelayAnchors)
// to anchors.dat. Must be called with the live peer set BEFORE the
// run loop tears peers down — by Stop's time the map is already
// empty and every peer disconnected. Best-effort: errors are
// logged, never propagated.
func (srv *Server) persistAnchors(peers map[enode.ID]*Peer) {
	if srv.AnchorsPath == "" {
		return
	}
	addrs := make([]addrman.NetAddr, 0, MaxBlockRelayAnchors)
	for _, p := range peers {
		if !p.BlockRelayOnly() {
			continue
		}
		// The dialed target is the authoritative anchor address:
		// block-relay peers are always outbound, and for proxied or
		// onion peers peerListenAddr would report the SOCKS5 proxy.
		var na addrman.NetAddr
		if t := p.rw.dialTarget(); t.Network != 0 {
			na = t
		} else if la, ok := srv.peerListenAddr(p); ok {
			if converted, ok := netAddrFromTCP(la); ok {
				na = converted
			}
		}
		if na.Network == 0 {
			continue
		}
		addrs = append(addrs, na)
		if len(addrs) >= MaxBlockRelayAnchors {
			break
		}
	}
	if err := saveAnchors(srv.AnchorsPath, addrs); err != nil {
		srv.log.Warn("anchors: save failed on shutdown", "path", srv.AnchorsPath, "err", err)
		return
	}
	srv.log.Info("anchors: saved", "path", srv.AnchorsPath, "count", len(addrs))
}

// addrmanAttempt records a failed connection attempt in the addrman.
// No-op when ExperimentalAddrMan is off.
func (srv *Server) addrmanAttempt(p *Peer) {
	if srv.addrbook == nil {
		return
	}
	addr, ok := peerRemoteAddr(p)
	if !ok {
		return
	}
	srv.addrbook.Attempt(addr, true, time.Now())
}

// addrmanConnected refreshes the addrman entry's LastSeen for a peer
// whose full outbound session just ended — Core's FinalizeNode →
// AddrMan::Connected discipline (only at disconnect, never per
// keep-alive, to avoid leaking currently-connected topology).
// No-op when ExperimentalAddrMan is off.
func (srv *Server) addrmanConnected(p *Peer) {
	if srv.addrbook == nil {
		return
	}
	addr, ok := peerRemoteAddr(p)
	if !ok {
		return
	}
	srv.addrbook.Connected(addr, time.Now())
}

// peerRemoteAddr extracts the addrman.NetAddr form of a Peer's
// RemoteAddr. Returns ok=false for non-TCP or unresolvable connections
// (test pipes, Unix sockets, etc.).
func peerRemoteAddr(p *Peer) (addrman.NetAddr, bool) {
	// The dialed target outranks the socket address: a proxied conn's
	// RemoteAddr is the SOCKS5 proxy, and addrman feedback recorded
	// against the proxy is lost — the real entry then accrues
	// attempts without successes and decays toward IsTerrible.
	if t := p.rw.dialTarget(); t.Network != 0 {
		return t, true
	}
	ra := p.RemoteAddr()
	if ra == nil {
		return addrman.NetAddr{}, false
	}
	tcp, ok := ra.(*net.TCPAddr)
	if !ok {
		return addrman.NetAddr{}, false
	}
	if v4 := tcp.IP.To4(); v4 != nil {
		a, err := addrman.NewNetAddr(addrman.NetIPv4, v4, uint16(tcp.Port))
		if err != nil {
			return addrman.NetAddr{}, false
		}
		return a, true
	}
	if v6 := tcp.IP.To16(); v6 != nil {
		a, err := addrman.NewNetAddr(addrman.NetIPv6, v6, uint16(tcp.Port))
		if err != nil {
			return addrman.NetAddr{}, false
		}
		return a, true
	}
	return addrman.NetAddr{}, false
}

func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}

// minLegacyPeers returns the configured floor of non-tcp_gossip
// peer slots, with the v2.x default applied when MinLegacyPeers is
// zero. A negative value disables the floor.
func (srv *Server) minLegacyPeers() int {
	if srv.MinLegacyPeers < 0 {
		return 0
	}
	if srv.MinLegacyPeers == 0 {
		return defaultMinLegacyPeers
	}
	return srv.MinLegacyPeers
}

// connSourceTag returns the addrman source tag for c's remote
// endpoint, or 0 if no addrman entry exists or the addrbook is
// disabled. Looks up by RemoteAddr; for v1 inbound peers this is the
// ephemeral source port and won't match the addrman entry keyed by
// listen port — those connections fall through unclassified, which
// is the conservative choice (the floor only fires on classifiable
// tcp_gossip peers).
func (srv *Server) connSourceTag(c *conn) addrman.Source {
	if srv.addrbook == nil {
		return 0
	}
	tcp, ok := c.fd.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	var na addrman.NetAddr
	var err error
	if v4 := tcp.IP.To4(); v4 != nil {
		na, err = addrman.NewNetAddr(addrman.NetIPv4, v4, uint16(tcp.Port))
	} else if v6 := tcp.IP.To16(); v6 != nil {
		na, err = addrman.NewNetAddr(addrman.NetIPv6, v6, uint16(tcp.Port))
	} else {
		return 0
	}
	if err != nil {
		return 0
	}
	info := srv.addrbook.Lookup(na)
	if info == nil {
		return 0
	}
	return info.SourceTag
}

// hasNonTCPGossipAlternatives reports whether the addrbook holds
// any entry from a source other than tcp_gossip. Used to short-
// circuit the legacy-floor reject when no non-tcp_gossip candidate
// could ever fill the reserved slots.
func (srv *Server) hasNonTCPGossipAlternatives() bool {
	if srv.addrbook == nil {
		return false
	}
	for src, n := range srv.addrbook.CountsBySource() {
		if src != addrman.SourceTCPGossip && n > 0 {
			return true
		}
	}
	return false
}

func (srv *Server) maxDialedConns() (limit int) {
	if srv.NoDial || srv.MaxPeers == 0 {
		return 0
	}
	if srv.DialRatio == 0 {
		limit = srv.MaxPeers / defaultDialRatio
	} else {
		limit = srv.MaxPeers / srv.DialRatio
	}
	if limit == 0 {
		limit = 1
	}
	return limit
}

// maxBlockRelayDial returns the count of outbound slots reserved
// for block-relay-only peers. Capped at maxDialedConns()/2 so a
// pathological config can't push every outbound dial into the
// block-relay bucket and starve full-relay traffic.
func (srv *Server) maxBlockRelayDial() int {
	if srv.NoDial || srv.MaxPeers == 0 {
		return 0
	}
	want := srv.MaxBlockRelayPeers
	if want == 0 {
		want = defaultMaxBlockRelayPeers
	}
	if want < 0 {
		return 0
	}
	if cap := srv.maxDialedConns() / 2; want > cap {
		want = cap
	}
	return want
}

func (srv *Server) setupListening() error {
	// Launch the listener.
	listener, err := srv.listenFunc("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	srv.listener = listener
	srv.ListenAddr = listener.Addr().String()

	// Update the local node record and map the TCP listening port if NAT is configured.
	if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
		srv.localnode.Set(enr.TCP(tcp.Port))
		if !tcp.IP.IsLoopback() && srv.NAT != nil {
			srv.log.Info("Setting up NAT port mapping for TCP p2p", "port", tcp.Port)
			srv.loopWG.Add(1)
			go func() {
				nat.Map(srv.NAT, srv.quit, "tcp", tcp.Port, tcp.Port, "parallax p2p", func(extport uint16) {
					// Feed the v2 self-advertisement first: it carries
					// the mapping's loss (extport 0) as well as its port.
					srv.setNATEndpoint(nil, extport)
					if extport == 0 {
						return
					}
					// The router may have remapped our requested port to a
					// different external one. Update the ENR's TCP entry so
					// remote peers dial the reachable port.
					if int(extport) != tcp.Port {
						srv.log.Info("NAT remapped TCP p2p port",
							"intport", tcp.Port, "extport", extport)
					}
					srv.localnode.Set(enr.TCP(int(extport)))
				})
				srv.loopWG.Done()
			}()
		} else if srv.NAT == nil {
			srv.log.Debug("NAT not configured, skipping TCP port mapping")
		}
	}

	srv.loopWG.Add(1)
	go srv.listenLoop()
	return nil
}

// doPeerOp runs fn on the main loop.
func (srv *Server) doPeerOp(fn peerOpFunc) {
	select {
	case srv.peerOp <- fn:
		<-srv.peerOpDone
	case <-srv.quit:
	}
}

// run is the main loop of the server.
func (srv *Server) run() {
	srv.logStartup()
	go srv.watchLocalAddrChanges()
	defer srv.loopWG.Done()
	defer srv.nodedb.Close()
	defer srv.discmix.Close()
	defer srv.dialsched.stop()

	var (
		peers        = make(map[enode.ID]*Peer)
		inboundCount = 0
		// tcpGossipPeers counts currently-connected peers whose
		// addrman entry was tagged source=tcp_gossip when first
		// learned. Drives the MinLegacyPeers floor in
		// postHandshakeChecks so we don't end up with all peers on
		// the new code path during early v2.x. PIP-0006 §Phase 5.
		tcpGossipPeers = 0
		trusted        = make(map[enode.ID]bool, len(srv.TrustedNodes))
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup or added via AddTrustedPeer RPC.
	for _, n := range srv.TrustedNodes {
		trusted[n.ID()] = true
	}

running:
	for {
		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running

		case n := <-srv.addtrusted:
			// This channel is used by AddTrustedPeer to add a node
			// to the trusted node set.
			srv.log.Trace("Adding trusted node", "node", n)
			trusted[n.ID()] = true
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, true)
			}

		case n := <-srv.removetrusted:
			// This channel is used by RemoveTrustedPeer to remove a node
			// from the trusted node set.
			srv.log.Trace("Removing trusted node", "node", n)
			delete(trusted, n.ID())
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, false)
			}

		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			op(peers)
			srv.peerOpDone <- struct{}{}

		case c := <-srv.checkpointPostHandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			if trusted[c.node.ID()] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			c.cont <- srv.postHandshakeChecks(peers, inboundCount, tcpGossipPeers, c)

		case c := <-srv.checkpointAddPeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			err := srv.addPeerChecks(peers, inboundCount, tcpGossipPeers, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := srv.launchPeer(c)
				peers[c.node.ID()] = p
				srv.log.Debug("Adding p2p peer", "peercount", len(peers), "id", p.ID(), "conn", c.flags, "addr", p.RemoteAddr(), "name", p.Name())
				srv.dialsched.peerAdded(c)
				if p.Inbound() {
					inboundCount++
				}
				if srv.connSourceTag(c) == addrman.SourceTCPGossip {
					tcpGossipPeers++
					p.tcpGossipSourced = true
				}
				// addrman.Good: mark this peer's address as verified.
				// Outbound sessions only — we dialed the address, so
				// we proved it reachable (CConnman calls
				// CAddrMan::Good only for outbound connections). An
				// inbound peer's advertised address is just its
				// unverified Hello ListenPort; letting it promote
				// itself into the tried table would hand eclipse
				// attackers exactly the shortcut the table exists to
				// prevent.
				if !p.Inbound() {
					srv.addrmanGood(p)
				}
			}
			c.cont <- err

		case pd := <-srv.delpeer:
			// A peer disconnected.
			d := util.PrettyDuration(mclock.Now() - pd.created)
			delete(peers, pd.ID())
			srv.log.Debug("Removing p2p peer", "peercount", len(peers), "id", pd.ID(), "duration", d, "req", pd.requested, "err", pd.err)
			srv.dialsched.peerRemoved(pd.rw)
			if pd.Inbound() {
				inboundCount--
			}
			if pd.tcpGossipSourced && tcpGossipPeers > 0 {
				tcpGossipPeers--
			}
			// addrman.Attempt: log the dial failure so IsTerrible
			// eventually evicts unreachable entries. Only count
			// failures on outbound-dial sessions — inbound
			// disconnects tell us nothing about our view of the
			// peer's reachability. Feeler conns are excluded: they
			// already marked the address Good at attach, and their
			// deliberate short-lived disconnect is not a reachability
			// failure — counting it would penalize the very address
			// the feeler just verified.
			if pd.err != nil && !pd.Inbound() && !pd.rw.is(feelerConn) {
				srv.addrmanAttempt(pd.Peer)
			}
			// addrman.Connected: refresh the entry's LastSeen at
			// disconnect time for full outbound sessions, mirroring
			// Core's FinalizeNode (net_processing.cpp:1738). Without
			// it a peer we stay connected to for weeks is never
			// re-stamped and ages across the 30-day IsTerrible
			// horizon despite being demonstrably alive. Outbound
			// non-feeler only: inbound advertised endpoints are
			// unverified, and feelers deliberately disconnect
			// moments after Good already stamped them.
			if !pd.Inbound() && !pd.rw.is(feelerConn) {
				srv.addrmanConnected(pd.Peer)
			}
			// Discourage hook: if the peer was flagged for
			// misbehavior during the session, add its source IP to
			// the ephemeral discourage filter. The filter is
			// consulted by postHandshakeChecks to reject the same
			// source if it tries to reconnect into a saturated
			// inbound pool. Bitcoin Core src/net_processing.cpp
			// MaybeDiscourageAndDisconnect — which never discourages
			// NoBan (trusted), manual (static), or local peers:
			// those exemptions matter here because the filter has no
			// clearing RPC, so one bad message from a trusted or
			// static peer would otherwise sever the peering until
			// restart, and on a multi-node host one misbehaving
			// loopback peer would sever every local peering sharing
			// the address.
			if srv.BanList != nil {
				if ip, ok := discourageTarget(pd.Peer); ok {
					srv.BanList.Discourage(ip)
					srv.log.Debug("discouraging misbehaving peer",
						"id", pd.ID(),
						"addr", ip,
						"reason", pd.DiscourageReason())
				}
			}
		}
	}

	srv.log.Trace("P2P networking is spinning down")

	// Snapshot block-relay-only anchors while the peer set is still
	// intact. This must happen before the disconnect loop below —
	// once peers are torn down the set is empty and anchors.dat
	// would be written empty (and thereby deleted). The run loop
	// owns `peers`, so reading it here is race-free.
	srv.persistAnchors(peers)

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	// Disconnect all peers.
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)")
		delete(peers, p.ID())
	}
}

// v2ConnDuplicate reports whether c represents a peer the node is
// already connected to. v2 sessions derive their node ID from
// ephemeral keys, so the ID-keyed peer map cannot catch duplicates and
// the address has to.
//
// The address compared is the one we dialed whenever the conn records
// one: a proxied conn's socket RemoteAddr is the SOCKS5 proxy, so
// comparing socket addresses would make the second proxied peer a
// duplicate of the first and cap the node at one peer per proxy. A
// proxied conn with no recorded target (a hostname seed fetch) cannot
// be identified at all and is never treated as a duplicate.
//
// Feeler probes are skipped: they are transient and must never block a
// real connection. On a cold start the addr-fetch probes exactly the
// bootstrap addresses the dialer then needs, which with a single
// bootnode is the only address it has.
func v2ConnDuplicate(peers map[enode.ID]*Peer, c *conn) bool {
	target := c.dialTarget()
	remote, hasRemote := c.fd.RemoteAddr().(*net.TCPAddr)
	if target.Network == 0 && (!hasRemote || c.is(proxiedConn)) {
		return false
	}
	for _, p := range peers {
		if p.rw.is(feelerConn) {
			continue
		}
		pt := p.rw.dialTarget()
		if target.Network != 0 {
			if pt.Network != 0 && pt.Equal(target) {
				return true
			}
			continue
		}
		if pt.Network != 0 || p.rw.is(proxiedConn) {
			continue
		}
		if pra, ok := p.RemoteAddr().(*net.TCPAddr); ok &&
			pra.Port == remote.Port && pra.IP.Equal(remote.IP) {
			return true
		}
	}
	return false
}

func (srv *Server) postHandshakeChecks(peers map[enode.ID]*Peer, inboundCount, tcpGossipPeers int, c *conn) error {
	// Duplicate and self connections are rejected before any
	// capacity handling: they must never trigger eviction (there is
	// nothing to make room for) and the rejection must fire
	// regardless of saturation state.
	if peers[c.node.ID()] != nil {
		return DiscAlreadyConnected
	}
	if c.node.ID() == srv.localnode.ID() {
		return DiscSelf
	}
	// Re-check the ban list after the handshake. The accept-loop
	// check (checkInboundConn) runs before the handshake starts; a
	// setban issued while handshakes are in flight only disconnects
	// peers already registered, so without this re-check a connection
	// that passed accept before the ban and completed the handshake
	// after it would be admitted and survive for the ban's whole
	// lifetime. Bitcoin's window is near zero because CNode registers
	// at accept; ours closes here. Applies to both directions —
	// outbound dials are pre-checked too, but static/admin dials can
	// race a ban the same way. Trusted peers bypass, matching the
	// NoBan permission.
	if srv.BanList != nil && !c.is(trustedConn) {
		if remote, ok := c.fd.RemoteAddr().(*net.TCPAddr); ok && srv.BanList.IsBanned(remote.IP) {
			return DiscUselessPeer
		}
	}
	// Discouraged-at-saturation rejection (Bitcoin Core
	// src/net.cpp:1808, nInbound + 1 >= nMaxInbound). At inbound
	// saturation we'd normally evict to make room. If the
	// candidate's IP is in our discourage filter (an in-memory
	// record of recent misbehavior), hard-reject before evicting —
	// there's no point displacing a well-behaved peer to admit one
	// we already know is misbehaving. Trusted peers bypass.
	if srv.BanList != nil && !c.is(trustedConn) && c.is(inboundConn) && inboundCount+1 >= srv.maxInboundConns() {
		if remote, ok := c.fd.RemoteAddr().(*net.TCPAddr); ok && srv.BanList.IsDiscouraged(remote.IP) {
			return DiscTooManyPeers
		}
	}
	// MinLegacyPeers floor (PIP-0006 §Phase 5): hard-cap tcp_gossip
	// peers at MaxPeers - MinLegacyPeers so a v2.0-specific bug
	// can't take down 100% of our peers. Applies on both directions
	// once the peer's source is classifiable. Trusted peers bypass.
	// Skipped when the addrbook holds no non-tcp_gossip alternatives —
	// no point reserving slots that nothing can fill.
	// Static dials bypass like trusted: the operator chose the
	// endpoint, and the floor exists to guard against a v2.0 gossip
	// bug, not against explicit peering. Feelers bypass too — they
	// probe addrman entries (mostly tcp_gossip-tagged) and never hold
	// a slot, so rejecting them at the floor would silently stop
	// tried-table maintenance.
	if floor := srv.minLegacyPeers(); floor > 0 && !c.is(trustedConn) && !c.is(staticDialedConn) && !c.is(feelerConn) {
		cap := srv.MaxPeers - floor
		if cap < 0 {
			cap = 0
		}
		if tcpGossipPeers >= cap && srv.connSourceTag(c) == addrman.SourceTCPGossip && srv.hasNonTCPGossipAlternatives() {
			return DiscTooManyPeers
		}
	}
	// Capacity checks. Inbound saturation is handled first: instead
	// of hard-rejecting, run the Bitcoin-Core-style eviction
	// algorithm to free a slot by dropping the lowest-quality
	// existing inbound peer. If eviction succeeds, accept the new
	// peer optimistically — the run loop processes the loser's
	// delpeer asynchronously, so inboundCount (and the total)
	// transiently exceed their caps by the number of in-flight
	// admissions, each of which is paired with one fresh victim.
	//
	// The inbound check must precede the MaxPeers check: in the
	// steady state (outbound slots full) inbound-full implies
	// total-full, and a total-first ordering would shadow eviction
	// entirely. The MaxPeers hard-reject still applies to outbound
	// conns and to inbound conns arriving while inbound has spare
	// capacity but the total is exhausted by outbound overshoot.
	if !c.is(trustedConn) {
		if c.is(inboundConn) && inboundCount >= srv.maxInboundConns() {
			// A connection that already paid for its slot with an
			// eviction at the post-handshake checkpoint is not
			// charged again at the add-peer checkpoint.
			if !c.evicted {
				if !srv.evictInbound(peers) {
					return DiscTooManyPeers
				}
				c.evicted = true
			}
		} else if nonFeelerLen(peers) >= srv.MaxPeers && !c.is(feelerConn) {
			// Feelers are exempt from the MaxPeers ceiling: Core
			// makes feeler connections regardless of its limits
			// (they're never counted toward outbound totals). A
			// feeler exists to verify reachability and feed the
			// tried table; the periodic feeler runs one at a time,
			// though the startup addrfetch sweep dials every
			// configured bootnode concurrently, so the transient
			// overshoot is bounded by the bootnode count plus one.
			// Every feeler self-disconnects after its lifetime.
			// Rejecting them at saturation would silently stop
			// tried-table maintenance exactly when the node is
			// busiest.
			return DiscTooManyPeers
		}
	}
	// Block-relay bucket cap, enforced at the checkpoint where all
	// dial paths serialize on the run loop. The scheduler and
	// runV2Dialer each check the bucket against the live peer set
	// before dialing, but neither sees the other's in-flight dials,
	// so two racing picks can both target the last slot — and
	// without this check the overshoot would persist until a
	// natural disconnect, since nothing evicts the excess.
	if c.is(blockRelayConn) && !c.is(feelerConn) {
		if blockRelayOutboundCountIn(peers) >= srv.maxBlockRelayDial() {
			return DiscTooManyPeers
		}
	}
	// Outbound network-group diversity, same backstop rationale: the
	// v1 scheduler, runV2Dialer, and the anchor replay each check the
	// one-outbound-per-group rule before dialing, but none sees the
	// others' in-flight dials, so a cross-path race can land two
	// outbound peers in one /16 — and the excess would persist until
	// a natural disconnect, quietly weakening the anti-eclipse
	// property the rule exists for. Static and trusted dials are
	// exempt from the check (the operator chose the endpoint) but
	// still occupy groups against dynamic dials, matching checkDial.
	// Feelers never hold a slot; loopback/link-local key to "".
	if c.is(dynDialedConn) && !c.is(feelerConn) && !c.is(staticDialedConn) && !c.is(trustedConn) {
		if g := outboundGroupKey(c); g != "" && outboundGroupOccupiedIn(peers, g) {
			return DiscTooManyPeers
		}
	}
	// Dynamic outbound budget backstop: the v1 scheduler and
	// runV2Dialer each count live dialed peers before dialing but not
	// each other's in-flight handshakes (and the scheduler
	// deliberately over-dials up to 2x its remaining slots to absorb
	// failures), so racing successes can overshoot maxDialedConns and
	// squeeze inbound capacity until a natural disconnect. Bitcoin
	// Core cannot overshoot — ThreadOpenConnections is serial.
	// Static and trusted dials don't consume the dynamic budget.
	// Skipped under NoDial: the automatic dialers this polices don't
	// run, and the only dyn-flagged dials left are operator-initiated
	// (admin.dialV2), which must not be budget-capped.
	if !srv.NoDial && c.is(dynDialedConn) && !c.is(feelerConn) && !c.is(trustedConn) && !c.is(staticDialedConn) {
		if dialedOutboundCountIn(peers) >= srv.maxDialedConns() {
			return DiscTooManyPeers
		}
	}
	// Phase 2b dedup: v2 sessions derive node.ID from ephemeral
	// X25519 keys, so reconnecting to the same remote yields a
	// fresh-looking ID that the map above can't flag. Fall back to
	// (IP, TCP port) matching — if a peer on the same address is
	// already connected, treat this as a duplicate.
	//
	// Also catch v2 self-connections that the node.ID check above
	// can't see: the kernel-level remote of an outbound dial is
	// the dial target, so if it matches our own advertised endpoint
	// the connection is a hairpin. DialV2 already rejects this at
	// the dial site; the check here covers the narrow window where
	// localnode's IP updates between the dial and this checkpoint,
	// and any future code path that bypasses DialV2.
	if _, isV2 := c.transport.(*v2Transport); isV2 {
		if target := c.dialTarget(); target.Network != 0 {
			if srv.isSelfNetAddr(target) {
				return DiscSelf
			}
		} else if remote, ok := c.fd.RemoteAddr().(*net.TCPAddr); ok && !c.is(proxiedConn) {
			if srv.IsSelfEndpoint(remote) {
				return DiscSelf
			}
		}
		if v2ConnDuplicate(peers, c) {
			return DiscAlreadyConnected
		}
	}
	return nil
}

func (srv *Server) addPeerChecks(peers map[enode.ID]*Peer, inboundCount, tcpGossipPeers int, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the post-handshake checks because the
	// peer set might have changed since those checks were performed.
	return srv.postHandshakeChecks(peers, inboundCount, tcpGossipPeers, c)
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	srv.log.Debug("TCP listener up", "addr", srv.listener.Addr())

	// The slots channel limits accepts of new connections.
	tokens := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	// Wait for slots to be returned on exit. This ensures all connection goroutines
	// are down before listenLoop returns.
	defer srv.loopWG.Done()
	defer func() {
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
	}()

	for {
		// Wait for a free slot before accepting.
		<-slots

		var (
			fd      net.Conn
			err     error
			lastLog time.Time
		)
		for {
			fd, err = srv.listener.Accept()
			if netutil.IsTemporaryError(err) {
				if time.Since(lastLog) > 1*time.Second {
					srv.log.Debug("Temporary read error", "err", err)
					lastLog = time.Now()
				}
				time.Sleep(time.Millisecond * 200)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				slots <- struct{}{}
				return
			}
			break
		}

		remoteIP := netutil.AddrIP(fd.RemoteAddr())
		if err := srv.checkInboundConn(remoteIP); err != nil {
			srv.log.Debug("Rejected inbound connection", "addr", fd.RemoteAddr(), "err", err)
			fd.Close()
			slots <- struct{}{}
			continue
		}
		if remoteIP != nil {
			var addr *net.TCPAddr
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok {
				addr = tcp
			}
			fd = newMeteredConn(fd, true, addr)
			srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		}
		go func() {
			// PIP-0006 Phase 2b: peek the first byte to classify the
			// inbound connection as legacy ECIES or v2 AEAD. The
			// peekedConn wrapper replays the byte for the legacy
			// path and consumes it for the v2 path. peeked-variant
			// is read by pickHandshakeVariant in SetupConn.
			wrapped := srv.dispatchInbound(fd)
			if wrapped != nil {
				srv.SetupConn(wrapped, inboundConn, nil)
			}
			slots <- struct{}{}
		}()
	}
}

// dispatchInbound inspects the first byte of fd to classify the
// handshake variant. Returns nil after closing fd if the peek failed
// or the byte doesn't match a supported variant under the current
// configuration.
//
// Rules (v2 handshake is always available in this build):
//   - Peek the first byte.
//   - 0xA0 → v2 handshake (magic consumed by the peek).
//   - Legacy RLPx magic → accepted only when legacyHandshakeMode == on.
//   - Anything else → reject.
func (srv *Server) dispatchInbound(fd net.Conn) net.Conn {
	// Give the peek a short deadline so a silent client doesn't
	// burn a goroutine forever.
	_ = fd.SetReadDeadline(time.Now().Add(handshakeTimeout))
	variant, peeked, err := bip324handshake.PeekVersion(fd)
	// Reset read deadline — individual handshakes manage their own.
	_ = fd.SetReadDeadline(time.Time{})
	if err != nil {
		srv.log.Trace("Peek failed on inbound connection", "addr", fd.RemoteAddr(), "err", err)
		fd.Close()
		return nil
	}
	wrapped := &peekedConn{Conn: fd, peeked: peeked}
	switch variant {
	case bip324handshake.VariantV2:
		wrapped.variant = peekedVariantV2
		return wrapped
	case bip324handshake.VariantLegacy:
		if srv.legacyHandshakeMode() == legacyHandshakeOff {
			srv.log.Trace("Rejecting legacy inbound (LegacyHandshakeMode=off)", "addr", fd.RemoteAddr())
			fd.Close()
			return nil
		}
		wrapped.variant = peekedVariantLegacy
		return wrapped
	default:
		srv.log.Trace("Rejecting unknown-handshake inbound", "addr", fd.RemoteAddr())
		fd.Close()
		return nil
	}
}

// peekedConn wraps a net.Conn that's had its first byte(s) peeked by
// bip324handshake.PeekVersion. The v2 path has already consumed the
// magic byte; the legacy path replays it.
type peekedConn struct {
	net.Conn
	peeked  *bip324handshake.PeekedConn
	variant peekedVariant
}

// Read delegates to the PeekedConn's Read, which handles replay
// transparently for the legacy path.
func (p *peekedConn) Read(b []byte) (int, error) { return p.peeked.Read(b) }

type peekedVariant int

const (
	peekedVariantLegacy peekedVariant = iota
	peekedVariantV2
)

func (srv *Server) checkInboundConn(remoteIP net.IP) error {
	if remoteIP == nil {
		return nil
	}
	// Reject connections that do not match NetRestrict.
	if srv.NetRestrict != nil && !srv.NetRestrict.Contains(remoteIP) {
		return fmt.Errorf("not in netrestrict list")
	}
	// Hard-reject banned IPs (Bitcoin Core src/net.cpp:1800
	// AcceptConnection ban check). Trusted-list status would
	// override this in Bitcoin Core's CNode permissions, but at
	// this stage of the connection we don't yet know whether the
	// remote is one of our trusted nodes — if an operator wants
	// a banned subnet to still reach trusted peers they should
	// unban, not work around it here.
	if srv.BanList != nil && srv.BanList.IsBanned(remoteIP) {
		return fmt.Errorf("banned")
	}
	// Reject Internet peers that try too often. Allow up to
	// maxInboundConnAttemptsPerIP concurrent in-window attempts from
	// the same source IP — anything over that is rate-limited.
	now := srv.clock.Now()
	srv.inboundHistory.expire(now, nil)
	if !netutil.IsLAN(remoteIP) && srv.inboundHistory.count(remoteIP.String()) >= maxInboundConnAttemptsPerIP {
		return fmt.Errorf("too many attempts")
	}
	srv.inboundHistory.add(remoteIP.String(), now.Add(inboundThrottleTime))
	return nil
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *enode.Node) error {
	return srv.setupConnTarget(fd, flags, dialDest, addrman.NetAddr{})
}

// setupConnTarget is SetupConn carrying the outbound dial target so
// group-diversity accounting can use the real destination instead of
// a proxied socket's RemoteAddr. The v2 dial path is its only caller
// with a non-zero target.
func (srv *Server) setupConnTarget(fd net.Conn, flags connFlag, dialDest *enode.Node, target addrman.NetAddr) error {
	flags = srv.classifyInboundNetwork(fd, flags)
	c := &conn{fd: fd, flags: flags, cont: make(chan error)}
	c.setDialTarget(target)
	variant := srv.pickHandshakeVariant(fd, flags, dialDest)
	switch variant {
	case handshakeVariantV2:
		// Outbound v2 dial: the TCP connection is freshly open; the
		// v2Transport's DialHandshake will write the magic byte.
		c.transport = newV2Outbound(fd)
	case handshakeVariantV2Inbound:
		// Inbound v2: the listener-side PeekVersion has already
		// consumed the magic byte. Wrap the peeked connection.
		c.transport = newV2Inbound(fd)
	default:
		// Legacy RLPx path (unchanged).
		if dialDest == nil {
			c.transport = srv.newTransport(fd, nil)
		} else {
			c.transport = srv.newTransport(fd, dialDest.Pubkey())
		}
	}

	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
	}
	return err
}

// handshakeVariant is the per-connection choice between legacy RLPx
// ECIES and the Phase 2b v2 handshake. Chosen by pickHandshakeVariant
// at connection setup time.
type handshakeVariant int

const (
	handshakeVariantLegacy handshakeVariant = iota
	handshakeVariantV2
	handshakeVariantV2Inbound
)

// pickHandshakeVariant decides which handshake path to use for a given
// connection. The three axes that matter:
//
//   - Is this an outbound dial or an inbound accept?
//   - Is ExperimentalV2Handshake enabled?
//   - For outbound: does the dial target carry a legacy NodeID (its
//     pubkey resolves to a usable secp256k1 point) or is it a
//     v2-native entry (dialDest is nil / marker)?
//
// For inbound, the caller (listener goroutine) has already dispatched
// via bip324handshake.PeekVersion; pickHandshakeVariant reads a
// per-connection flag recorded on the fd.
func (srv *Server) pickHandshakeVariant(fd net.Conn, flags connFlag, dialDest *enode.Node) handshakeVariant {
	// Inbound: the peek-result is hung off the connection via a
	// *peekedConn wrapper. If peek said v2, the wrapper signals it
	// through the peekedVariant field.
	if flags&inboundConn != 0 {
		if pc, ok := fd.(*peekedConn); ok && pc.variant == peekedVariantV2 {
			return handshakeVariantV2Inbound
		}
		return handshakeVariantLegacy
	}
	// Outbound: the v2 dial path sets v2DialedConn explicitly, so we
	// key off that flag rather than guessing from dialDest. This
	// preserves the legacy outbound contract (dialDest==nil still
	// means "unspecified target, use legacy"), which existing tests
	// and callers rely on.
	if flags&v2DialedConn != 0 {
		return handshakeVariantV2
	}
	// --legacy-discovery=off forbids legacy outbound: anything that
	// reaches here without the v2-dial flag is a bug, but we route it
	// to v2 rather than silently use the legacy path.
	if srv.legacyHandshakeMode() == legacyHandshakeOff {
		return handshakeVariantV2
	}
	return handshakeVariantLegacy
}

// legacyHandshakeMode is a derived view of LegacyDiscoveryMode — UDP
// discovery and legacy RLPx handshake are the two halves of the same
// v1.x identity model, so they share a single operator knob.
type legacyHandshakeMode int

const (
	legacyHandshakeOn legacyHandshakeMode = iota
	legacyHandshakeOff
)

func (srv *Server) legacyHandshakeMode() legacyHandshakeMode {
	if srv.legacyDiscoveryMode() == legacyDiscoveryOff {
		return legacyHandshakeOff
	}
	return legacyHandshakeOn
}

func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *enode.Node) error {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}

	// If dialing, figure out the remote public key.
	if dialDest != nil {
		dialPubkey := new(ecdsa.PublicKey)
		if err := dialDest.Load((*enode.Secp256k1)(dialPubkey)); err != nil {
			err = errors.New("dial destination doesn't have a secp256k1 public key")
			srv.log.Trace("Setting up connection failed", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
			return err
		}
	}

	// Run the RLPx handshake.
	remotePubkey, err := c.doEncHandshake(srv.PrivateKey)
	if err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	// For v2 transports there is no persistent peer identity; we
	// derive c.node from the remote ephemeral X25519 key via
	// v2NodeFromConn, which uses enode.SignNull to assign a
	// session-scoped ID. Any dialDest we started with is replaced so
	// the run-loop's peers map is keyed by the real session identity.
	if v2t, v2 := c.transport.(*v2Transport); v2 {
		c.node = v2NodeFromConn(v2t.remoteEphem, c.fd)
	} else if dialDest == nil {
		c.node = nodeFromConn(remotePubkey, c.fd)
	} else {
		c.node = dialDest
	}
	clog := srv.log.New("id", c.node.ID(), "addr", c.fd.RemoteAddr(), "conn", c.flags)
	// Inbound: register the NodeID with the dial scheduler so an
	// outbound iterator pick on the same ID is rejected with
	// errInboundProgress. The defer brackets the entire window —
	// post-handshake checks, protocol handshake, addPeer — so the
	// registration is cleared regardless of which exit path runs.
	// By the time setupConn returns success, dialsched.peerAdded has
	// already populated d.peers[id] (peerAdded blocks on the dialer
	// loop), so the unregister leaves no protective gap.
	if c.is(inboundConn) && srv.dialsched != nil {
		id := c.node.ID()
		srv.dialsched.inboundProgressBegin(id)
		defer srv.dialsched.inboundProgressEnd(id)
	}
	err = srv.checkpoint(c, srv.checkpointPostHandshake)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	// Run the capability negotiation handshake.
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed p2p handshake", "err", err)
		return err
	}
	if id := c.node.ID(); !bytes.Equal(crypto.Keccak256(phs.ID), id[:]) {
		clog.Trace("Wrong devp2p handshake identity", "phsid", hex.EncodeToString(phs.ID))
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	// Inbound v1 peers: nodeFromConn built c.node with the ephemeral
	// source port from the TCP socket, which won't match any addrman
	// entry keyed by the peer's advertised listening port. Rebuild
	// c.node using phs.ListenPort so addrmanGood resolves to the
	// correct service-key.
	if _, isV2 := c.transport.(*v2Transport); !isV2 && c.is(inboundConn) && phs.ListenPort != 0 {
		if tcp, ok := c.fd.RemoteAddr().(*net.TCPAddr); ok {
			if pub := c.node.Pubkey(); pub != nil {
				c.node = enode.NewV4(pub, tcp.IP, int(phs.ListenPort), int(phs.ListenPort))
			}
		}
	}
	err = srv.checkpoint(c, srv.checkpointAddPeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	return nil
}

func nodeFromConn(pubkey *ecdsa.PublicKey, conn net.Conn) *enode.Node {
	var ip net.IP
	var port int
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcp.IP
		port = tcp.Port
	}
	return enode.NewV4(pubkey, ip, port, port)
}

// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	}
	return <-c.cont
}

// discourageTarget reports whether a disconnecting peer's misbehavior
// flag should stamp its source IP into the discourage filter, and if
// so which IP. Trusted (NoBan), static (manual), and loopback (local)
// sessions are exempt, mirroring Bitcoin Core's
// MaybeDiscourageAndDisconnect (src/net_processing.cpp). The
// exemptions matter because the filter has no clearing RPC: one bad
// message from a trusted or static peer would otherwise sever the
// peering until restart, and on a multi-node host one misbehaving
// loopback peer would sever every local peering sharing the address.
func discourageTarget(pd *Peer) (net.IP, bool) {
	if !pd.ShouldDiscourage() || pd.rw.is(trustedConn) || pd.rw.is(staticDialedConn) {
		return nil, false
	}
	remote, ok := pd.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.IsLoopback() {
		return nil, false
	}
	return remote.IP, true
}

func (srv *Server) launchPeer(c *conn) *Peer {
	p := newPeer(srv.log, c, srv.Protocols)
	if srv.EnableMsgEvents {
		// If message events are enabled, pass the peerFeed
		// to the peer.
		p.events = &srv.peerFeed
	}
	// Cache the peer's network-group bytes once. Eviction passes
	// read this on every candidate without recomputing.
	p.computeAndCacheNetworkGroup()
	// Block-relay-only is a sticky outbound-slot tag set by the dial
	// scheduler. Mirrors Bitcoin Core's m_relays_txs=false on
	// block-relay-only peers (src/net_processing.cpp:3681): no tx
	// traffic, no address gossip. Inbound peers never carry the bit.
	if c.is(blockRelayConn) {
		p.SetBlockRelayOnly(true)
		p.SetRelayTxs(false)
	}
	// Feelers take no part in tx relay either: Core never sets up tx
	// relay for ConnectionType::FEELER, so the broadcast path must
	// not pick a feeler during its short lifetime (the prl handlers
	// already drop tx-bearing messages FROM feelers).
	if c.is(feelerConn) {
		p.SetRelayTxs(false)
	}
	// Stamp admission-time discourage-filter membership so inbound
	// eviction prefers this peer over well-behaved ones. Bitcoin sets
	// CNode.m_prefer_evict from AddrIsDiscouraged at accept; the
	// session-local misbehavior flag alone misses a previously-
	// discouraged address that reconnects while inbound is
	// unsaturated (the saturation hard-reject doesn't fire) and then
	// behaves.
	if srv.BanList != nil && c.is(inboundConn) {
		if ra, ok := c.fd.RemoteAddr().(*net.TCPAddr); ok && srv.BanList.IsDiscouraged(ra.IP) {
			p.MarkPreferEvict()
		}
	}
	go srv.runPeer(p)
	return p
}

// runPeer runs in its own goroutine for each peer.
func (srv *Server) runPeer(p *Peer) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeAdd,
		Peer:          p.ID(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})

	// Run the per-peer main loop.
	remoteRequested, err := p.run()

	// Announce disconnect on the main loop to update the peer set.
	// The main loop waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	srv.delpeer <- peerDrop{p, err, remoteRequested}

	// Broadcast peer drop to external subscribers. This needs to be
	// after the send to delpeer so subscribers have a consistent view of
	// the peer set (i.e. Server.Peers() doesn't include the peer when the
	// event is received.
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeDrop,
		Peer:          p.ID(),
		Error:         err.Error(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})
}

// NodeInfo represents a short summary of the information known about the host.
//
// Enode and ENR are pointer types so they marshal to JSON null when the
// node is running in v2-only mode (--legacy-discovery=off) — the
// persistent secp256k1 identity has no peer-visible use in that mode,
// and emitting its URL as if it were a dialable identifier would
// mislead operators.
type NodeInfo struct {
	ID    string  `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string  `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Enode *string `json:"enode"` // Enode URL for adding this peer from remote peers; null in v2-only mode
	ENR   *string `json:"enr"`   // Parallax Node Record; null in v2-only mode
	IP    string  `json:"ip"`    // IP address of the node
	Ports struct {
		// Discovery is the UDP listening port for legacy discv4. In
		// v2-only mode (--legacy-discovery=off) there is no UDP
		// socket, and this field reports the TCP listener port
		// instead — discovery on a v2-only node happens entirely
		// over TCP via parallax-disc/1 gossip.
		Discovery int `json:"discovery"`
		Listener  int `json:"listener"` // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string         `json:"listenAddr"`
	Protocols  map[string]any `json:"protocols"`

	// Networks is the per-network reachability/proxy table — Core's
	// getnetworkinfo "networks" array (PIP-0007 §4).
	Networks []NetworkInfo `json:"networks"`
	// Onion is this node's established onion service ("host:port"),
	// empty while none is active.
	Onion string `json:"onion,omitempty"`
}

// NetworkInfo is one row of NodeInfo.Networks.
type NetworkInfo struct {
	Name           string `json:"name"`
	Reachable      bool   `json:"reachable"`
	Proxy          string `json:"proxy,omitempty"`
	ProxyRandomize bool   `json:"proxy_randomize_credentials"`
}

// NodeInfo gathers and returns a collection of metadata known about the host.
func (srv *Server) NodeInfo() *NodeInfo {
	// Gather and assemble the generic node infos
	node := srv.Self()
	info := &NodeInfo{
		Name:       srv.Name,
		ID:         node.ID().String(),
		IP:         node.IP().String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]any),
	}
	info.Ports.Listener = node.TCP()
	if srv.legacyHandshakeMode() == legacyHandshakeOff {
		// v2-only: no persistent identity is dialable, no UDP exists.
		// Enode/ENR null, discovery port mirrors the TCP port.
		info.Ports.Discovery = node.TCP()
	} else {
		enode := node.URLv4()
		enr := node.String()
		info.Enode = &enode
		info.ENR = &enr
		info.Ports.Discovery = node.UDP()
	}

	// Gather all the running protocol infos (only once per protocol type)
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := any("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}

	// Per-network reachability and proxy routing (PIP-0007 §4).
	// Row names follow Core's getnetworkinfo ("onion", not the
	// wire-format label).
	for _, n := range []addrman.NetID{addrman.NetIPv4, addrman.NetIPv6, addrman.NetTorV3} {
		name := n.String()
		if n == addrman.NetTorV3 {
			name = "onion"
		}
		row := NetworkInfo{Name: name, Reachable: srv.NetworkReachable(n)}
		if pr := srv.policy().proxyFor(n); pr != nil {
			row.Proxy = pr.Addr
			row.ProxyRandomize = pr.Isolation != nil
		}
		info.Networks = append(info.Networks, row)
	}
	if onion, ok := srv.OnionService(); ok {
		info.Onion = onion.String()
	}
	return info
}

// PeersInfo returns an array of metadata objects describing connected peers.
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	// Sort the result array by node identifier where available,
	// falling back to RemoteAddress for v2 peers (whose ID is nil).
	keyOf := func(p *PeerInfo) string {
		if p.ID != nil {
			return *p.ID
		}
		return p.Network.RemoteAddress
	}
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if keyOf(infos[i]) > keyOf(infos[j]) {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}
