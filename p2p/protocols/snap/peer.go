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

package snap

import (
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/tracker"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

// Peer is a collection of relevant information we have about a `snap` peer.
type Peer struct {
	id string // Unique ID for the peer, cached

	*p2p.Peer                   // The embedded P2P package peer
	rw        p2p.MsgReadWriter // Input/output streams for snap
	version   uint              // Protocol version negotiated
	tracker   *tracker.Tracker  // Per-peer request tracker, also enforcing response limits

	logger logging.Logger // Contextual logger with the peer id injected
}

// NewPeer create a wrapper for a network connection and negotiated  protocol
// version.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	cap := p2p.Cap{Name: ProtocolName, Version: version}
	id := p.ID().String()
	return &Peer{
		id:      id,
		Peer:    p,
		rw:      rw,
		version: version,
		tracker: tracker.New(cap, id, time.Minute),
		logger:  logging.New("peer", id[:8]),
	}
}

// NewFakePeer create a fake snap peer without a backing p2p peer, for testing purposes.
func NewFakePeer(version uint, id string, rw p2p.MsgReadWriter) *Peer {
	cap := p2p.Cap{Name: ProtocolName, Version: version}
	return &Peer{
		id:      id,
		rw:      rw,
		version: version,
		tracker: tracker.New(cap, id, time.Minute),
		logger:  logging.New("peer", id[:8]),
	}
}

// ID retrieves the peer's unique identifier.
func (p *Peer) ID() string {
	return p.id
}

// Version retrieves the peer's negoatiated `snap` protocol version.
func (p *Peer) Version() uint {
	return p.version
}

// Log overrides the P2P logget with the higher level one containing only the id.
func (p *Peer) Log() logging.Logger {
	return p.logger
}

// Close releases resources associated with the peer.
func (p *Peer) Close() {
	p.tracker.Stop()
}

// RequestAccountRange fetches a batch of accounts rooted in a specific account
// trie, starting with the origin.
func (p *Peer) RequestAccountRange(id uint64, root util.Hash, origin, limit util.Hash, bytes uint64) error {
	p.logger.Trace("Fetching range of accounts", "reqid", id, "root", root, "origin", origin, "limit", limit, "bytes", util.StorageSize(bytes))

	err := p.tracker.Track(tracker.Request{
		ReqCode:  GetAccountRangeMsg,
		RespCode: AccountRangeMsg,
		ID:       id,
		Size:     2 * int(bytes),
	})
	if err != nil {
		return err
	}
	return p2p.Send(p.rw, GetAccountRangeMsg, &GetAccountRangePacket{
		ID:     id,
		Root:   root,
		Origin: origin,
		Limit:  limit,
		Bytes:  bytes,
	})
}

// RequestStorageRange fetches a batch of storage slots belonging to one or more
// accounts. If slots from only one accout is requested, an origin marker may also
// be used to retrieve from there.
func (p *Peer) RequestStorageRanges(id uint64, root util.Hash, accounts []util.Hash, origin, limit []byte, bytes uint64) error {
	if len(accounts) == 1 && origin != nil {
		p.logger.Trace("Fetching range of large storage slots", "reqid", id, "root", root, "account", accounts[0], "origin", util.BytesToHash(origin), "limit", util.BytesToHash(limit), "bytes", util.StorageSize(bytes))
	} else {
		p.logger.Trace("Fetching ranges of small storage slots", "reqid", id, "root", root, "accounts", len(accounts), "first", accounts[0], "bytes", util.StorageSize(bytes))
	}
	err := p.tracker.Track(tracker.Request{
		ReqCode:  GetStorageRangesMsg,
		RespCode: StorageRangesMsg,
		ID:       id,
		Size:     2 * int(bytes),
	})
	if err != nil {
		return err
	}
	return p2p.Send(p.rw, GetStorageRangesMsg, &GetStorageRangesPacket{
		ID:       id,
		Root:     root,
		Accounts: accounts,
		Origin:   origin,
		Limit:    limit,
		Bytes:    bytes,
	})
}

// RequestByteCodes fetches a batch of bytecodes by hash.
func (p *Peer) RequestByteCodes(id uint64, hashes []util.Hash, bytes uint64) error {
	p.logger.Trace("Fetching set of byte codes", "reqid", id, "hashes", len(hashes), "bytes", util.StorageSize(bytes))

	err := p.tracker.Track(tracker.Request{
		ReqCode:  GetByteCodesMsg,
		RespCode: ByteCodesMsg,
		ID:       id,
		Size:     len(hashes), // ByteCodes is limited by the length of the hash list.
	})
	if err != nil {
		return err
	}
	return p2p.Send(p.rw, GetByteCodesMsg, &GetByteCodesPacket{
		ID:     id,
		Hashes: hashes,
		Bytes:  bytes,
	})
}

// RequestTrieNodes fetches a batch of account or storage trie nodes rooted in
// a specificstate trie.
func (p *Peer) RequestTrieNodes(id uint64, root util.Hash, paths []TrieNodePathSet, bytes uint64) error {
	p.logger.Trace("Fetching set of trie nodes", "reqid", id, "root", root, "pathsets", len(paths), "bytes", util.StorageSize(bytes))

	// TrieNodes is limited by the number of requested nodes: a single-item
	// pathset names one account trie node, longer ones name one storage trie
	// node per path after the leading account hash.
	var count int
	for _, pathset := range paths {
		if len(pathset) <= 1 {
			count++
		} else {
			count += len(pathset) - 1
		}
	}
	err := p.tracker.Track(tracker.Request{
		ReqCode:  GetTrieNodesMsg,
		RespCode: TrieNodesMsg,
		ID:       id,
		Size:     count,
	})
	if err != nil {
		return err
	}
	encPaths, err := rlp.EncodeToRawList(paths)
	if err != nil {
		return err
	}
	return p2p.Send(p.rw, GetTrieNodesMsg, &GetTrieNodesPacket{
		ID:    id,
		Root:  root,
		Paths: encPaths,
		Bytes: bytes,
	})
}
