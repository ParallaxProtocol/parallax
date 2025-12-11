// Copyright 2015 The go-ethereum Authors
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

package prl

import (
	"math/big"

	"github.com/ParallaxProtocol/parallax/prl/protocols/prl"
	"github.com/ParallaxProtocol/parallax/prl/protocols/snap"
)

// parallaxPeerInfo represents a short summary of the `eth` sub-protocol metadata known
// about a connected peer.
type parallaxPeerInfo struct {
	Version    uint     `json:"version"`    // Parallax protocol version negotiated
	Difficulty *big.Int `json:"difficulty"` // Total difficulty of the peer's blockchain
	Head       string   `json:"head"`       // Hex hash of the peer's best owned block
}

// parallaxPeer is a wrapper around prl.Peer to maintain a few extra metadata.
type parallaxPeer struct {
	*prl.Peer
	snapExt *snapPeer // Satellite `snap` connection
}

// info gathers and returns some `eth` protocol metadata known about a peer.
func (p *parallaxPeer) info() *parallaxPeerInfo {
	hash, td := p.Head()

	return &parallaxPeerInfo{
		Version:    p.Version(),
		Difficulty: td,
		Head:       hash.Hex(),
	}
}

// snapPeerInfo represents a short summary of the `snap` sub-protocol metadata known
// about a connected peer.
type snapPeerInfo struct {
	Version uint `json:"version"` // Snapshot protocol version negotiated
}

// snapPeer is a wrapper around snap.Peer to maintain a few extra metadata.
type snapPeer struct {
	*snap.Peer
}

// info gathers and returns some `snap` protocol metadata known about a peer.
func (p *snapPeer) info() *snapPeerInfo {
	return &snapPeerInfo{
		Version: p.Version(),
	}
}
