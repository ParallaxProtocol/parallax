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

package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/internal/debug"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/banman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/rpc"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
)

// apis returns the collection of built-in RPC APIs.
func (n *Node) apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "admin",
			Version:   "1.0",
			Service:   &privateAdminAPI{n},
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   &publicAdminAPI{n},
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   debug.Handler,
		}, {
			Namespace: "web3",
			Version:   "1.0",
			Service:   &publicWeb3API{n},
			Public:    true,
		},
	}
}

// privateAdminAPI is the collection of administrative API methods exposed only
// over a secure RPC channel.
type privateAdminAPI struct {
	node *Node // Node interfaced by this API
}

// AddPeer requests connecting to a remote node. Input is either
//
//   - enode://<hex>@ip:port — legacy RLPx path, registers a static
//     dial task that auto-reconnects. Rejected when the node is
//     running in v2-only mode (--legacy-discovery=off).
//   - ip:port                — v2 path, opens a single BIP324-style
//     handshake via Server.DialV2. Works in every mode.
//
// Operators who want a persistent auto-reconnecting v2 peer should
// use admin_addnode instead (ingests into addrman with source=manual,
// survives restarts, dialed ahead of any other source).
func (api *privateAdminAPI) AddPeer(url string) (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	url = strings.TrimSpace(url)
	if strings.HasPrefix(url, "enode://") || strings.HasPrefix(url, "enr:") {
		// Legacy RLPx path — v2-only mode refuses legacy targets.
		if server.LegacyHandshakeRefused() {
			return false, errors.New("node is running with --legacy-discovery=off; pass ip:port (v2) or use admin_addnode")
		}
		node, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			return false, fmt.Errorf("invalid enode: %v", err)
		}
		server.AddPeer(node)
		return true, nil
	}
	// ip:port / onion:port → v2 dial (single-shot; use admin_addnode
	// for persistence).
	na, err := parseV2Target(url)
	if err != nil {
		return false, fmt.Errorf("invalid address %q: expected enode://…, ip:port or <addr>.onion:port (%v)", url, err)
	}
	if err := server.DialV2Manual(na); err != nil {
		return false, err
	}
	return true, nil
}

// parseV2Target parses an operator-supplied v2 dial target: "ip:port"
// or "<base32>.onion:port" (PIP-0007 — onion targets dial through the
// configured Tor proxy; the dial fails with "no route to network" when
// none is configured).
func parseV2Target(address string) (addrman.NetAddr, error) {
	return addrman.ParseHostPort(address)
}

// RemovePeer disconnects from a remote node. Symmetric with AddPeer:
//
//   - enode://<hex>@ip:port — legacy path, removes the static dial
//     task and disconnects the matching peer.
//   - ip:port                — scans current peers for one whose
//     RemoteAddr matches and disconnects it. Useful for v2 peers
//     whose node.ID is session-ephemeral and therefore not stable
//     across reconnects.
func (api *privateAdminAPI) RemovePeer(url string) (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	url = strings.TrimSpace(url)
	if strings.HasPrefix(url, "enode://") || strings.HasPrefix(url, "enr:") {
		if server.LegacyHandshakeRefused() {
			return false, errors.New("node is running with --legacy-discovery=off; pass ip:port to remove a v2 peer")
		}
		node, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			return false, fmt.Errorf("invalid enode: %v", err)
		}
		server.RemovePeer(node)
		return true, nil
	}
	// ip:port / onion:port → disconnect the matching peer. Matching
	// keys on the peer's dial target where one exists, so onion peers
	// are addressable and a proxied peer is found by its real address
	// rather than the proxy's.
	na, err := parseV2Target(url)
	if err != nil {
		return false, fmt.Errorf("invalid address %q: expected enode://…, ip:port or <addr>.onion:port (%v)", url, err)
	}
	return server.DisconnectByNetAddr(na), nil
}

// AddTrustedPeer allows a remote node to always connect, even if slots are full
func (api *privateAdminAPI) AddTrustedPeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	node, err := enode.Parse(enode.ValidSchemes, url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.AddTrustedPeer(node)
	return true, nil
}

// Addnode ingests an address into the addrman as an operator-pinned
// peer (source=manual). Accepts either plain `ip:port` (v2.0-native,
// KeyType=0x00) or the legacy `enode://<nodeID>@ip:port` form (v1.x,
// KeyType=0x01). Returns true if the entry was inserted or updated.
//
// PIP-0006 Phase 6 — mirrors Bitcoin Core's `addnode` RPC semantics.
// Manual entries persist across restarts, are exempt from the
// source-aware eviction, and are dialed before any other source in
// Select() via the manual chanceMultiplier.
func (api *privateAdminAPI) Addnode(address string) (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	book := server.AddrBook()
	if book == nil {
		return false, errors.New("addrman is not initialized (is the server running?)")
	}
	entry, err := parseAddrbookAddress(address)
	if err != nil {
		return false, err
	}
	return book.Add([]addrman.Entry{entry}, entry.Addr, addrman.SourceManual, 0), nil
}

// Removenode drops an address from the addrman, regardless of which
// table holds it. PIP-0006 Phase 6 — inverse of Addnode.
func (api *privateAdminAPI) Removenode(address string) (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	book := server.AddrBook()
	if book == nil {
		return false, errors.New("addrman is not initialized (is the server running?)")
	}
	entry, err := parseAddrbookAddress(address)
	if err != nil {
		return false, err
	}
	return book.Remove(entry.Addr), nil
}

// AddrbookStatus returns a Status snapshot for operator diagnostics.
// Read-only; PIP-0006 Phase 6.
func (api *privateAdminAPI) AddrbookStatus() (*addrman.Status, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	book := server.AddrBook()
	if book == nil {
		return nil, errors.New("addrman is not initialized (is the server running?)")
	}
	s := book.Snapshot()
	return &s, nil
}

// DialV2 directly opens a BIP324-style v2 RLPx connection to the given
// "ip:port". Bypasses the addrman routability filter, so it can
// target loopback/RFC1918 addresses for testing. PIP-0006 Phase 2b.
func (api *privateAdminAPI) DialV2(address string) (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	na, err := parseV2Target(address)
	if err != nil {
		return false, fmt.Errorf("invalid address %q: %w", address, err)
	}
	if err := server.DialV2Manual(na); err != nil {
		return false, err
	}
	return true, nil
}

// Setban adds or removes an entry in the persistent ban list.
// Mirrors Bitcoin Core's setban RPC (src/rpc/net.cpp:740).
//
// Arguments:
//
//   - subnet:   IP or CIDR. "1.2.3.4" → /32, "1.2.3.0/24" → CIDR.
//   - command:  "add" or "remove".
//   - bantime:  seconds. 0 → DefaultBanDuration. Honored only on
//     command="add".
//   - absolute: when true, bantime is a Unix timestamp; when false,
//     a relative offset from now. Default false. Honored only on
//     command="add".
//
// On "add" the matching live peers are also disconnected. On
// "remove" returns an error if the subnet wasn't previously banned
// (Bitcoin parity, src/rpc/net.cpp:817).
func (api *privateAdminAPI) Setban(subnet string, command string, bantime *int64, absolute *bool) (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	bm := server.BanList
	if bm == nil {
		return false, errors.New("ban subsystem is not initialized")
	}
	// Onion targets (PIP-0007 §4): exact-host bans on the bare
	// "<base32>.onion" name. No subnet form exists, and no live-peer
	// kick is possible — inbound onion streams arrive from the local
	// Tor daemon and can't be attributed to an onion address; the ban
	// is enforced at the outbound dial gate.
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(subnet)), ".onion") {
		host := strings.TrimSpace(subnet)
		switch command {
		case "add":
			if bm.IsBannedHost(host) {
				return false, errors.New("onion address already banned")
			}
			duration, err := banDurationFrom(bantime, absolute)
			if err != nil {
				return false, err
			}
			if err := bm.BanHost(host, duration, banman.ReasonManual); err != nil {
				return false, err
			}
			// Kick the banned peer if it is connected. Outbound onion
			// peers are attributable through their dial target;
			// inbound onion streams are not, and simply stay until
			// they drop.
			canonical, cerr := addrman.ParseOnion(host, 0)
			if cerr == nil {
				server.DisconnectMatching(func(a addrman.NetAddr) bool {
					return a.Network == addrman.NetTorV3 &&
						string(a.Bytes()) == string(canonical.Bytes())
				})
			}
			return true, nil
		case "remove":
			ok, err := bm.UnbanHost(host)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, fmt.Errorf("onion address %s is not currently banned", host)
			}
			return true, nil
		}
		return false, fmt.Errorf("invalid command %q (want add|remove)", command)
	}
	netw, err := parseBanSubnet(subnet)
	if err != nil {
		return false, err
	}
	switch command {
	case "add":
		// Bitcoin parity (rpc/net.cpp RPC_CLIENT_NODE_ALREADY_ADDED):
		// re-adding an active ban is an error and the operator must
		// remove it first. BanSubnet's extend-only rule would keep
		// the longer of the two expiries while reporting success, so
		// a "shortened" ban would silently not apply. Core's check is
		// form-sensitive: the subnet form looks up the exact banmap
		// entry, while the plain-IP form checks containment in ANY
		// active ban (isSubnet ? IsBanned(subNet) : IsBanned(netAddr)).
		alreadyBanned := bm.IsBannedSubnet(netw)
		if !strings.Contains(subnet, "/") {
			alreadyBanned = bm.IsBanned(netw.IP)
		}
		if alreadyBanned {
			return false, errors.New("IP/subnet already banned")
		}
		duration, err := banDurationFrom(bantime, absolute)
		if err != nil {
			return false, err
		}
		if err := bm.BanSubnet(netw, duration, banman.ReasonManual); err != nil {
			return false, err
		}
		// Bitcoin parity: kick any matching live peers
		// (rpc/net.cpp:808-811). Matching keys on the dial target
		// where one exists, so a peer reached through a proxy is
		// matched by its real address instead of the proxy's.
		server.DisconnectMatching(func(a addrman.NetAddr) bool {
			tcp := a.TCPAddr()
			return tcp != nil && netw.Contains(tcp.IP)
		})
		return true, nil
	case "remove":
		ok, err := bm.UnbanSubnet(netw)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, fmt.Errorf("subnet %s is not currently banned", subnet)
		}
		return true, nil
	}
	return false, fmt.Errorf("invalid command %q (want add|remove)", command)
}

// banDurationFrom resolves setban's (bantime, absolute) argument pair
// into a duration, shared by the subnet and onion branches. A zero,
// omitted, or negative relative bantime yields 0, which the BanMan
// layer resolves to the 24h default — matching BanMan::Ban's
// ban_time_offset <= 0 normalization (src/banman.cpp).
func banDurationFrom(bantime *int64, absolute *bool) (time.Duration, error) {
	if absolute != nil && *absolute {
		// With absolute set, bantime IS the expiry — including an
		// omitted or zero bantime, which resolves to the epoch and
		// errors, matching Core's "Error: Absolute timestamp is in
		// the past" rather than silently falling back to the 24h
		// default.
		var ts int64
		if bantime != nil {
			ts = *bantime
		}
		until := time.Unix(ts, 0)
		if !until.After(time.Now()) {
			return 0, errors.New("absolute bantime must be in the future")
		}
		return time.Until(until), nil
	}
	if bantime != nil && *bantime > 0 {
		// time.Duration counts int64 nanoseconds, so seconds above
		// ~292 years overflow the multiplication to a negative value
		// — which the ban layer would then silently replace with the
		// 24h default while the RPC reports success. Clamp so the
		// huge relative bantimes Bitcoin operators use as
		// "permanent" (e.g. 9999999999) keep their intent. Core adds
		// the offset in whole seconds and is immune (src/banman.cpp
		// BanMan::Ban).
		secs := *bantime
		if maxSecs := math.MaxInt64 / int64(time.Second); secs > maxSecs {
			secs = maxSecs
		}
		return time.Duration(secs) * time.Second, nil
	}
	return 0, nil
}

// Listbanned returns the active (non-expired) entries from the ban
// list. Mirrors src/rpc/net.cpp:820.
func (api *privateAdminAPI) Listbanned() ([]banman.BanInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	bm := server.BanList
	if bm == nil {
		return nil, errors.New("ban subsystem is not initialized")
	}
	return bm.ListBanned(), nil
}

// Clearbanned removes every entry from the persistent ban list.
// Mirrors src/rpc/net.cpp:868. Does NOT clear the in-memory
// discourage filter — that surface is restart-cleared by design.
func (api *privateAdminAPI) Clearbanned() (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	bm := server.BanList
	if bm == nil {
		return false, errors.New("ban subsystem is not initialized")
	}
	if err := bm.ClearBanned(); err != nil {
		return false, err
	}
	return true, nil
}

// parseBanSubnet accepts either a plain IP ("1.2.3.4") which
// implies /32 (IPv4) or /128 (IPv6), or a CIDR ("10.0.0.0/24").
// Empty / malformed inputs return an error verbatim suitable for
// RPC.
func parseBanSubnet(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("subnet is empty")
	}
	// CIDR form?
	if strings.Contains(s, "/") {
		ip, subnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		// An IPv4-mapped IPv6 CIDR ("::ffff:1.2.3.0/24") means the
		// embedded IPv4 subnet — Core's CSubNet normalizes the
		// address to IPv4 and applies the prefix to it. Convert
		// here, before the ::ffff: mapping prefix is masked away, or
		// the ban would silently cover a huge IPv6 range ("::/24")
		// instead. Prefixes above /32 are meaningless for a v4
		// target and rejected, exactly as Core rejects them —
		// including the IPv6-style /96../128 forms an earlier
		// revision accepted as a custom extension.
		if v4 := ip.To4(); v4 != nil {
			if ones, bits := subnet.Mask.Size(); bits == 128 {
				if ones > 32 {
					return nil, fmt.Errorf("invalid prefix length /%d for IPv4-mapped subnet %q", ones, s)
				}
				mask := net.CIDRMask(ones, 32)
				return &net.IPNet{IP: v4.Mask(mask), Mask: mask}, nil
			}
		}
		return subnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}, nil
}

// AddrbookResetKey regenerates the addrman's nKey and clears the tried
// table atomically. Operator-only; intended for cases where an nKey
// leak is credibly suspected. PIP-0006 Phase 6.
func (api *privateAdminAPI) AddrbookResetKey() (bool, error) {
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	book := server.AddrBook()
	if book == nil {
		return false, errors.New("addrman is not initialized (is the server running?)")
	}
	if err := book.ResetKey(); err != nil {
		return false, err
	}
	return true, nil
}

// parseAddrbookAddress accepts either a plain `ip:port` (v2.0-native)
// or the legacy `enode://<hex>@ip:port` form. Branches on the enode://
// prefix, matching the input format Bitcoin Core's addnode accepts.
func parseAddrbookAddress(s string) (addrman.Entry, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "enode://") {
		n, err := enode.ParseV4(s)
		if err != nil {
			return addrman.Entry{}, fmt.Errorf("invalid enode: %w", err)
		}
		ip := n.IP()
		if ip == nil || n.TCP() == 0 {
			return addrman.Entry{}, errors.New("enode missing ip or tcp port")
		}
		var net addrman.NetID
		var addrBytes []byte
		if v4 := ip.To4(); v4 != nil {
			net = addrman.NetIPv4
			addrBytes = v4
		} else {
			net = addrman.NetIPv6
			addrBytes = ip
		}
		naddr, err := addrman.NewNetAddr(net, addrBytes, uint16(n.TCP()))
		if err != nil {
			return addrman.Entry{}, err
		}
		pub := n.Pubkey()
		if pub == nil {
			return addrman.Entry{}, errors.New("enode missing pubkey")
		}
		return addrman.Entry{
			Addr:     naddr,
			KeyType:  0x01,
			NodeID:   pubkeyToNodeID(pub),
			LastSeen: time.Now(),
		}, nil
	}
	// Plain ip:port / onion:port form (PIP-0007: onion entries pin
	// like any other manual peer; dialing them needs a Tor route).
	naddr, err := parseV2Target(s)
	if err != nil {
		return addrman.Entry{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	return addrman.Entry{Addr: naddr, KeyType: 0x00, LastSeen: time.Now()}, nil
}

// pubkeyToNodeID returns the 64-byte (x || y) encoding used by discv4
// and parallax-disc/1 for KeyType=0x01 entries. Matches the format
// produced by elliptic.Marshal minus the 0x04 prefix.
func pubkeyToNodeID(pub *ecdsa.PublicKey) []byte {
	//nolint:staticcheck // elliptic.Marshal remains the canonical
	// encoder for discv4/enode NodeIDs; secp256k1 is not provided by
	// crypto/ecdh so the linter's suggested replacement doesn't apply.
	b := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(b) != 65 || b[0] != 0x04 {
		return nil
	}
	return b[1:]
}

// RemoveTrustedPeer removes a remote node from the trusted peer set, but it
// does not disconnect it automatically.
func (api *privateAdminAPI) RemoveTrustedPeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	node, err := enode.Parse(enode.ValidSchemes, url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.RemoveTrustedPeer(node)
	return true, nil
}

// Uptime returns the number of seconds the node has been running since its
// most recent Start. Returns 0 if the node is not yet running. Mirrors
// bitcoin-cli's `uptime` and backs the `parallax uptime` sugar command.
func (api *privateAdminAPI) Uptime() (uint64, error) {
	api.node.lock.Lock()
	startedAt := api.node.startedAt
	state := api.node.state
	api.node.lock.Unlock()
	if state != runningState || startedAt.IsZero() {
		return 0, nil
	}
	return uint64(time.Since(startedAt).Seconds()), nil
}

// Stop requests a graceful shutdown of the node. It returns immediately; the
// actual shutdown runs in a background goroutine so that the RPC response can
// be delivered to the caller before the RPC server is torn down.
func (api *privateAdminAPI) Stop() (bool, error) {
	go func() {
		// Give the RPC server a short grace period to flush the response.
		time.Sleep(100 * time.Millisecond)
		if err := api.node.Close(); err != nil && err != ErrNodeStopped {
			logging.Error("admin_stop: node close failed", "err", err)
		}
	}()
	return true, nil
}

// PeerEvents creates an RPC subscription which receives peer events from the
// node's p2p.Server
func (api *privateAdminAPI) PeerEvents(ctx context.Context) (*rpc.Subscription, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}

	// Create the subscription
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return nil, rpc.ErrNotificationsUnsupported
	}
	rpcSub := notifier.CreateSubscription()

	go func() {
		events := make(chan *p2p.PeerEvent)
		sub := server.SubscribeEvents(events)
		defer sub.Unsubscribe()

		for {
			select {
			case event := <-events:
				notifier.Notify(rpcSub.ID, event)
			case <-sub.Err():
				return
			case <-rpcSub.Err():
				return
			case <-notifier.Closed():
				return
			}
		}
	}()

	return rpcSub, nil
}

// StartHTTP starts the HTTP RPC API server.
func (api *privateAdminAPI) StartHTTP(host *string, port *int, cors *string, apis *string, vhosts *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	// Determine host and port.
	if host == nil {
		h := DefaultHTTPHost
		if api.node.config.HTTPHost != "" {
			h = api.node.config.HTTPHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.HTTPPort
	}

	// Determine config.
	config := httpConfig{
		CorsAllowedOrigins: api.node.config.HTTPCors,
		Vhosts:             api.node.config.HTTPVirtualHosts,
		Modules:            api.node.config.HTTPModules,
		rpcEndpointConfig: rpcEndpointConfig{
			batchItemLimit:         api.node.config.BatchRequestLimit,
			batchResponseSizeLimit: api.node.config.BatchResponseMaxSize,
			httpBodyLimit:          api.node.config.HTTPBodyLimit,
		},
	}
	if cors != nil {
		config.CorsAllowedOrigins = nil
		for _, origin := range strings.Split(*cors, ",") {
			config.CorsAllowedOrigins = append(config.CorsAllowedOrigins, strings.TrimSpace(origin))
		}
	}
	if vhosts != nil {
		config.Vhosts = nil
		for _, vhost := range strings.Split(*host, ",") {
			config.Vhosts = append(config.Vhosts, strings.TrimSpace(vhost))
		}
	}
	if apis != nil {
		config.Modules = nil
		for _, m := range strings.Split(*apis, ",") {
			config.Modules = append(config.Modules, strings.TrimSpace(m))
		}
	}

	if err := api.node.http.setListenAddr(*host, *port); err != nil {
		return false, err
	}
	if err := api.node.http.enableRPC(api.node.rpcAPIs, config); err != nil {
		return false, err
	}
	if err := api.node.http.start(); err != nil {
		return false, err
	}
	return true, nil
}

// StartRPC starts the HTTP RPC API server.
// Deprecated: use StartHTTP instead.
func (api *privateAdminAPI) StartRPC(host *string, port *int, cors *string, apis *string, vhosts *string) (bool, error) {
	logging.Warn("Deprecation warning", "method", "admin.StartRPC", "use-instead", "admin.StartHTTP")
	return api.StartHTTP(host, port, cors, apis, vhosts)
}

// StopHTTP shuts down the HTTP server.
func (api *privateAdminAPI) StopHTTP() (bool, error) {
	api.node.http.stop()
	return true, nil
}

// StopRPC shuts down the HTTP server.
// Deprecated: use StopHTTP instead.
func (api *privateAdminAPI) StopRPC() (bool, error) {
	logging.Warn("Deprecation warning", "method", "admin.StopRPC", "use-instead", "admin.StopHTTP")
	return api.StopHTTP()
}

// StartWS starts the websocket RPC API server.
func (api *privateAdminAPI) StartWS(host *string, port *int, allowedOrigins *string, apis *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	// Determine host and port.
	if host == nil {
		h := DefaultWSHost
		if api.node.config.WSHost != "" {
			h = api.node.config.WSHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.WSPort
	}

	// Determine config.
	config := wsConfig{
		Modules: api.node.config.WSModules,
		Origins: api.node.config.WSOrigins,
		// ExposeAll: api.node.config.WSExposeAll,
		rpcEndpointConfig: rpcEndpointConfig{
			batchItemLimit:         api.node.config.BatchRequestLimit,
			batchResponseSizeLimit: api.node.config.BatchResponseMaxSize,
			httpBodyLimit:          api.node.config.HTTPBodyLimit,
		},
	}
	if apis != nil {
		config.Modules = nil
		for _, m := range strings.Split(*apis, ",") {
			config.Modules = append(config.Modules, strings.TrimSpace(m))
		}
	}
	if allowedOrigins != nil {
		config.Origins = nil
		for _, origin := range strings.Split(*allowedOrigins, ",") {
			config.Origins = append(config.Origins, strings.TrimSpace(origin))
		}
	}

	// Enable WebSocket on the server.
	server := api.node.wsServerForPort(*port, false)
	if err := server.setListenAddr(*host, *port); err != nil {
		return false, err
	}
	openApis, _ := api.node.GetAPIs()
	if err := server.enableWS(openApis, config); err != nil {
		return false, err
	}
	if err := server.start(); err != nil {
		return false, err
	}
	api.node.http.log.Info("WebSocket endpoint opened", "url", api.node.WSEndpoint())
	return true, nil
}

// StopWS terminates all WebSocket servers.
func (api *privateAdminAPI) StopWS() (bool, error) {
	api.node.http.stopWS()
	api.node.ws.stop()
	return true, nil
}

// publicAdminAPI is the collection of administrative API methods exposed over
// both secure and unsecure RPC channels.
type publicAdminAPI struct {
	node *Node // Node interfaced by this API
}

// Peers retrieves all the information we know about each individual peer at the
// protocol granularity.
func (api *publicAdminAPI) Peers() ([]*p2p.PeerInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.PeersInfo(), nil
}

// NodeInfo retrieves all the information we know about the host node at the
// protocol granularity.
func (api *publicAdminAPI) NodeInfo() (*p2p.NodeInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.NodeInfo(), nil
}

// Datadir retrieves the current data directory the node is using.
func (api *publicAdminAPI) Datadir() string {
	return api.node.DataDir()
}

// publicWeb3API offers helper utils
type publicWeb3API struct {
	stack *Node
}

// ClientVersion returns the node name
func (s *publicWeb3API) ClientVersion() string {
	return s.stack.Server().Name
}

// Sha3 applies the parallax sha3 implementation on the input.
// It assumes the input is hex encoded.
func (s *publicWeb3API) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}
