// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package les

import (
	"github.com/ParallaxProtocol/parallax/core/forkid"
	"github.com/ParallaxProtocol/parallax/p2p/dnsdisc"
	"github.com/ParallaxProtocol/parallax/p2p/enode"
	"github.com/ParallaxProtocol/parallax/rlp"
)

// lpsEntry is the "lps" LPS entry. This is set for LPS servers only.
type lpsEntry struct {
	// Ignore additional fields (for forward compatibility).
	VfxVersion uint
	Rest       []rlp.RawValue `rlp:"tail"`
}

func (lpsEntry) ENRKey() string { return "les" }

// parallaxEntry is the "parallax" ENR entry. This is redeclared here to avoid depending on package prl.
type parallaxEntry struct {
	ForkID forkid.ID
	Tail   []rlp.RawValue `rlp:"tail"`
}

func (parallaxEntry) ENRKey() string { return "parallax" }

// setupDiscovery creates the node discovery source for the parallax protocol.
func (prl *LightParallax) setupDiscovery() (enode.Iterator, error) {
	it := enode.NewFairMix(0)

	// Enable DNS discovery.
	if len(prl.config.ParallaxDiscoveryURLs) != 0 {
		client := dnsdisc.NewClient(dnsdisc.Config{})
		dns, err := client.NewIterator(prl.config.ParallaxDiscoveryURLs...)
		if err != nil {
			return nil, err
		}
		it.AddSource(dns)
	}

	// Enable DHT.
	if prl.udpEnabled {
		it.AddSource(prl.p2pServer.DiscV5.RandomNodes())
	}

	forkFilter := forkid.NewFilter(prl.blockchain)
	iterator := enode.Filter(it, func(n *enode.Node) bool { return nodeIsServer(forkFilter, n) })
	return iterator, nil
}

// nodeIsServer checks whether n is an LPS server node.
func nodeIsServer(forkFilter forkid.Filter, n *enode.Node) bool {
	var les lpsEntry
	var prl parallaxEntry
	return n.Load(&les) == nil && n.Load(&prl) == nil && forkFilter(prl.ForkID) == nil
}
