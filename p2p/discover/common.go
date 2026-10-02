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
	"container/list"
	"crypto/ecdsa"
	"iter"
	"net"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enr"
	"github.com/ParallaxProtocol/parallax/v2/p2p/netutil"
	"github.com/ParallaxProtocol/parallax/v2/util/mclock"
)

// UDPConn is a network connection on which discovery can operate.
type UDPConn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// Config holds settings for the discovery listener.
type Config struct {
	// These settings are required and configure the UDP listener:
	PrivateKey *ecdsa.PrivateKey

	// These settings are optional:
	NetRestrict  *netutil.Netlist   // list of allowed IP networks
	Bootnodes    []*enode.Node      // list of bootstrap nodes
	Unhandled    chan<- ReadPacket  // unhandled packets are sent on this channel
	Log          logging.Logger     // if set, log messages go here
	ValidSchemes enr.IdentityScheme // allowed identity schemes
	Clock        mclock.Clock
	NodeFilter   func(*enode.Node) bool // if set, nodes failing this check are evicted during revalidation
}

func (cfg Config) withDefaults() Config {
	if cfg.Log == nil {
		cfg.Log = logging.Root()
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{}
	}
	return cfg
}

// ListenUDP starts listening for discovery packets on the given UDP socket.
func ListenUDP(c UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv4, error) {
	return ListenV4(c, ln, cfg)
}

// ReadPacket is a packet that couldn't be handled. Those packets are sent to the unhandled
// channel if configured.
type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

// iterList iterates over the elements of the given list. It is safe to
// remove the current element during iteration.
func iterList[T any](l *list.List) iter.Seq2[T, *list.Element] {
	return func(yield func(T, *list.Element) bool) {
		for el := l.Front(); el != nil; {
			next := el.Next()
			if !yield(el.Value.(T), el) {
				return
			}
			el = next
		}
	}
}
