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
	"bytes"
	"fmt"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enr"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/support/metrics"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/trie"
)

const (
	// softResponseLimit is the target maximum size of replies to data retrievals.
	softResponseLimit = 2 * 1024 * 1024

	// maxCodeLookups is the maximum number of bytecodes to serve. This number is
	// there to limit the number of disk lookups.
	maxCodeLookups = 1024

	// stateLookupSlack defines the ratio by how much a state response can exceed
	// the requested limit in order to try and avoid breaking up contracts into
	// multiple packages and proving them.
	stateLookupSlack = 0.1

	// maxTrieNodeLookups is the maximum number of state trie nodes to serve. This
	// number is there to limit the number of disk lookups.
	maxTrieNodeLookups = 1024

	// maxTrieNodeTimeSpent is the maximum time we should spend on looking up trie nodes.
	// If we spend too much time, then it's a fairly high chance of timing out
	// at the remote side, which means all the work is in vain.
	maxTrieNodeTimeSpent = 5 * time.Second
)

// Handler is a callback to invoke from an outside runner after the boilerplate
// exchanges have passed.
type Handler func(peer *Peer) error

// Backend defines the data retrieval methods to serve remote requests and the
// callback methods to invoke on remote deliveries.
type Backend interface {
	// Chain retrieves the blockchain object to serve data.
	Chain() *validation.BlockChain

	// RunPeer is invoked when a peer joins on the `eth` protocol. The handler
	// should do any peer maintenance work, handshakes and validations. If all
	// is passed, control should be given back to the `handler` to process the
	// inbound messages going forward.
	RunPeer(peer *Peer, handler Handler) error

	// PeerInfo retrieves all known `snap` information about a peer.
	PeerInfo(id enode.ID) any

	// Handle is a callback to be invoked when a data packet is received from
	// the remote peer. Only packets not consumed by the protocol handler will
	// be forwarded to the backend.
	Handle(peer *Peer, packet Packet) error
}

// handleDiscard reads and discards every message until the connection
// is torn down. Feeler sessions use this: nothing past capability
// negotiation may be served to a probe.
func handleDiscard(rw p2p.MsgReadWriter) error {
	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			return err
		}
		if err := msg.Discard(); err != nil {
			return err
		}
	}
}

// MakeProtocols constructs the P2P protocol definitions for `snap`.
func MakeProtocols(backend Backend, dnsdisc enode.Iterator) []p2p.Protocol {
	// Filter the discovery iterator for nodes advertising snap support.
	dnsdisc = enode.Filter(dnsdisc, func(n *enode.Node) bool {
		var snap enrEntry
		return n.Load(&snap) == nil
	})

	protocols := make([]p2p.Protocol, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		protocols[i] = p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  protocolLengths[version],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				// Feeler probes exist only to confirm reachability at
				// the prl status handshake; serving them snapshot data
				// would do real work for a session that is torn down
				// within seconds (Bitcoin Core feelers disconnect
				// right after version/verack and are served nothing).
				// Discard without registering the extension — the prl
				// side skips its snap barrier for feelers to match.
				if p.Feeler() {
					return handleDiscard(rw)
				}
				return backend.RunPeer(NewPeer(version, p, rw), func(peer *Peer) error {
					return Handle(backend, peer)
				})
			},
			NodeInfo: func() any {
				return nodeInfo(backend.Chain())
			},
			PeerInfo: func(id enode.ID) any {
				return backend.PeerInfo(id)
			},
			Attributes:     []enr.Entry{&enrEntry{}},
			DialCandidates: dnsdisc,
		}
	}
	return protocols
}

// Handle is the callback invoked to manage the life cycle of a `snap` peer.
// When this function terminates, the peer is disconnected.
func Handle(backend Backend, peer *Peer) error {
	for {
		if err := HandleMessage(backend, peer); err != nil {
			peer.Log().Debug("Message handling failed in `snap`", "err", err)
			return err
		}
	}
}

// HandleMessage is invoked whenever an inbound message is received from a
// remote peer on the `snap` protocol. The remote connection is torn down upon
// returning any error.
func HandleMessage(backend Backend, peer *Peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := peer.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > maxMessageSize {
		return fmt.Errorf("%w: %v > %v", errMsgTooLarge, msg.Size, maxMessageSize)
	}
	defer msg.Discard()
	start := time.Now()
	// Track the emount of time it takes to serve the request and run the handler
	if metrics.Enabled {
		h := fmt.Sprintf("%s/%s/%d/%#02x", p2p.HandleHistName, ProtocolName, peer.Version(), msg.Code)
		defer func(start time.Time) {
			sampler := func() metrics.Sample {
				return metrics.ResettingSample(
					metrics.NewExpDecaySample(1028, 0.015),
				)
			}
			metrics.GetOrRegisterHistogramLazy(h, nil, sampler).Update(time.Since(start).Microseconds())
		}(start)
	}
	// Handle the message depending on its contents
	switch {
	case msg.Code == GetAccountRangeMsg:
		// Decode the account retrieval request
		var req GetAccountRangePacket
		if err := msg.Decode(&req); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Service the request, potentially returning nothing in case of errors
		accounts, proofs := ServiceGetAccountRangeQuery(backend.Chain(), &req)

		// Send back anything accumulated (or empty in case of errors)
		return p2p.Send(peer.rw, AccountRangeMsg, &AccountRangePacket{
			ID:       req.ID,
			Accounts: accounts,
			Proof:    proofs,
		})

	case msg.Code == AccountRangeMsg:
		// A range of accounts arrived to one of our previous requests
		res := new(AccountRangePacket)
		if err := msg.Decode(res); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Ensure the range is monotonically increasing
		for i := 1; i < len(res.Accounts); i++ {
			if bytes.Compare(res.Accounts[i-1].Hash[:], res.Accounts[i].Hash[:]) >= 0 {
				return fmt.Errorf("accounts not monotonically increasing: #%d [%x] vs #%d [%x]", i-1, res.Accounts[i-1].Hash[:], i, res.Accounts[i].Hash[:])
			}
		}
		requestTracker.Fulfil(peer.id, peer.version, AccountRangeMsg, res.ID)

		return backend.Handle(peer, res)

	case msg.Code == GetStorageRangesMsg:
		// Decode the storage retrieval request
		var req GetStorageRangesPacket
		if err := msg.Decode(&req); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Service the request, potentially returning nothing in case of errors
		slots, proofs := ServiceGetStorageRangesQuery(backend.Chain(), &req)

		// Send back anything accumulated (or empty in case of errors)
		return p2p.Send(peer.rw, StorageRangesMsg, &StorageRangesPacket{
			ID:    req.ID,
			Slots: slots,
			Proof: proofs,
		})

	case msg.Code == StorageRangesMsg:
		// A range of storage slots arrived to one of our previous requests
		res := new(StorageRangesPacket)
		if err := msg.Decode(res); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Ensure the ranges are monotonically increasing
		for i, slots := range res.Slots {
			for j := 1; j < len(slots); j++ {
				if bytes.Compare(slots[j-1].Hash[:], slots[j].Hash[:]) >= 0 {
					return fmt.Errorf("storage slots not monotonically increasing for account #%d: #%d [%x] vs #%d [%x]", i, j-1, slots[j-1].Hash[:], j, slots[j].Hash[:])
				}
			}
		}
		requestTracker.Fulfil(peer.id, peer.version, StorageRangesMsg, res.ID)

		return backend.Handle(peer, res)

	case msg.Code == GetByteCodesMsg:
		// Decode bytecode retrieval request
		var req GetByteCodesPacket
		if err := msg.Decode(&req); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Service the request, potentially returning nothing in case of errors
		codes := ServiceGetByteCodesQuery(backend.Chain(), &req)

		// Send back anything accumulated (or empty in case of errors)
		return p2p.Send(peer.rw, ByteCodesMsg, &ByteCodesPacket{
			ID:    req.ID,
			Codes: codes,
		})

	case msg.Code == ByteCodesMsg:
		// A batch of byte codes arrived to one of our previous requests
		res := new(ByteCodesPacket)
		if err := msg.Decode(res); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		requestTracker.Fulfil(peer.id, peer.version, ByteCodesMsg, res.ID)

		return backend.Handle(peer, res)

	case msg.Code == GetTrieNodesMsg:
		// Decode trie node retrieval request
		var req GetTrieNodesPacket
		if err := msg.Decode(&req); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Service the request, potentially returning nothing in case of errors
		nodes, err := ServiceGetTrieNodesQuery(backend.Chain(), &req, start)
		if err != nil {
			return err
		}
		// Send back anything accumulated (or empty in case of errors)
		return p2p.Send(peer.rw, TrieNodesMsg, &TrieNodesPacket{
			ID:    req.ID,
			Nodes: nodes,
		})

	case msg.Code == TrieNodesMsg:
		// A batch of trie nodes arrived to one of our previous requests
		res := new(TrieNodesPacket)
		if err := msg.Decode(res); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		requestTracker.Fulfil(peer.id, peer.version, TrieNodesMsg, res.ID)

		return backend.Handle(peer, res)

	default:
		return fmt.Errorf("%w: %v", errInvalidMsgCode, msg.Code)
	}
}

// ServiceGetAccountRangeQuery assembles the response to an account range query.
// It is exposed to allow external packages to test protocol behavior.
func ServiceGetAccountRangeQuery(chain *validation.BlockChain, req *GetAccountRangePacket) ([]*AccountData, [][]byte) {
	if req.Bytes > softResponseLimit {
		req.Bytes = softResponseLimit
	}
	// Retrieve the requested state and bail out if non existent
	tr, err := trie.New(req.Root, chain.StateCache().TrieDB())
	if err != nil {
		return nil, nil
	}
	it, err := chain.Snapshots().AccountIterator(req.Root, req.Origin)
	if err != nil {
		return nil, nil
	}
	// Iterate over the requested range and pile accounts up
	var (
		accounts []*AccountData
		size     uint64
		last     util.Hash
	)
	for it.Next() {
		hash, account := it.Hash(), util.CopyBytes(it.Account())

		// Track the returned interval for the Merkle proofs
		last = hash

		// Assemble the reply item
		size += uint64(util.HashLength + len(account))
		accounts = append(accounts, &AccountData{
			Hash: hash,
			Body: account,
		})
		// If we've exceeded the request threshold, abort
		if bytes.Compare(hash[:], req.Limit[:]) >= 0 {
			break
		}
		if size > req.Bytes {
			break
		}
	}
	it.Release()

	// Generate the Merkle proofs for the first and last account
	proof := trie.NewNodeSet()
	if err := tr.Prove(req.Origin[:], 0, proof); err != nil {
		logging.Warn("Failed to prove account range", "origin", req.Origin, "err", err)
		return nil, nil
	}
	if last != (util.Hash{}) {
		if err := tr.Prove(last[:], 0, proof); err != nil {
			logging.Warn("Failed to prove account range", "last", last, "err", err)
			return nil, nil
		}
	}
	var proofs [][]byte
	for _, blob := range proof.NodeList() {
		proofs = append(proofs, blob)
	}
	return accounts, proofs
}

func ServiceGetStorageRangesQuery(chain *validation.BlockChain, req *GetStorageRangesPacket) ([][]*StorageData, [][]byte) {
	if req.Bytes > softResponseLimit {
		req.Bytes = softResponseLimit
	}
	// TODO(karalabe): Do we want to enforce > 0 accounts and 1 account if origin is set?
	// TODO(karalabe):   - Logging locally is not ideal as remote faulst annoy the local user
	// TODO(karalabe):   - Dropping the remote peer is less flexible wrt client bugs (slow is better than non-functional)

	// Calculate the hard limit at which to abort, even if mid storage trie
	hardLimit := uint64(float64(req.Bytes) * (1 + stateLookupSlack))

	// Retrieve storage ranges until the packet limit is reached
	var (
		slots  [][]*StorageData
		proofs [][]byte
		size   uint64
	)
	for _, account := range req.Accounts {
		// If we've exceeded the requested data limit, abort without opening
		// a new storage range (that we'd need to prove due to exceeded size)
		if size >= req.Bytes {
			break
		}
		// The first account might start from a different origin and end sooner
		var origin util.Hash
		if len(req.Origin) > 0 {
			origin, req.Origin = util.BytesToHash(req.Origin), nil
		}
		limit := util.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		if len(req.Limit) > 0 {
			limit, req.Limit = util.BytesToHash(req.Limit), nil
		}
		// Retrieve the requested state and bail out if non existent
		it, err := chain.Snapshots().StorageIterator(req.Root, account, origin)
		if err != nil {
			return nil, nil
		}
		// Iterate over the requested range and pile slots up
		var (
			storage []*StorageData
			last    util.Hash
			abort   bool
		)
		for it.Next() {
			if size >= hardLimit {
				abort = true
				break
			}
			hash, slot := it.Hash(), util.CopyBytes(it.Slot())

			// Track the returned interval for the Merkle proofs
			last = hash

			// Assemble the reply item
			size += uint64(util.HashLength + len(slot))
			storage = append(storage, &StorageData{
				Hash: hash,
				Body: slot,
			})
			// If we've exceeded the request threshold, abort
			if bytes.Compare(hash[:], limit[:]) >= 0 {
				abort = true
				break
			}
		}
		if len(storage) > 0 {
			slots = append(slots, storage)
		}
		it.Release()

		// Generate the Merkle proofs for the first and last storage slot, but
		// only if the response was capped. If the entire storage trie included
		// in the response, no need for any proofs.
		if origin != (util.Hash{}) || (abort && len(storage) > 0) {
			// Request started at a non-zero hash or was capped prematurely, add
			// the endpoint Merkle proofs
			accTrie, err := trie.New(req.Root, chain.StateCache().TrieDB())
			if err != nil {
				return nil, nil
			}
			var acc types.StateAccount
			if err := rlp.DecodeBytes(accTrie.Get(account[:]), &acc); err != nil {
				return nil, nil
			}
			stTrie, err := trie.New(acc.Root, chain.StateCache().TrieDB())
			if err != nil {
				return nil, nil
			}
			proof := trie.NewNodeSet()
			if err := stTrie.Prove(origin[:], 0, proof); err != nil {
				logging.Warn("Failed to prove storage range", "origin", req.Origin, "err", err)
				return nil, nil
			}
			if last != (util.Hash{}) {
				if err := stTrie.Prove(last[:], 0, proof); err != nil {
					logging.Warn("Failed to prove storage range", "last", last, "err", err)
					return nil, nil
				}
			}
			for _, blob := range proof.NodeList() {
				proofs = append(proofs, blob)
			}
			// Proof terminates the reply as proofs are only added if a node
			// refuses to serve more data (exception when a contract fetch is
			// finishing, but that's that).
			break
		}
	}
	return slots, proofs
}

// ServiceGetByteCodesQuery assembles the response to a byte codes query.
// It is exposed to allow external packages to test protocol behavior.
func ServiceGetByteCodesQuery(chain *validation.BlockChain, req *GetByteCodesPacket) [][]byte {
	if req.Bytes > softResponseLimit {
		req.Bytes = softResponseLimit
	}
	if len(req.Hashes) > maxCodeLookups {
		req.Hashes = req.Hashes[:maxCodeLookups]
	}
	// Retrieve bytecodes until the packet size limit is reached
	var (
		codes [][]byte
		bytes uint64
	)
	for _, hash := range req.Hashes {
		if hash == emptyCode {
			// Peers should not request the empty code, but if they do, at
			// least sent them back a correct response without db lookups
			codes = append(codes, []byte{})
		} else if blob, err := chain.ContractCodeWithPrefix(hash); err == nil {
			codes = append(codes, blob)
			bytes += uint64(len(blob))
		}
		if bytes > req.Bytes {
			break
		}
	}
	return codes
}

// ServiceGetTrieNodesQuery assembles the response to a trie nodes query.
// It is exposed to allow external packages to test protocol behavior.
func ServiceGetTrieNodesQuery(chain *validation.BlockChain, req *GetTrieNodesPacket, start time.Time) ([][]byte, error) {
	if req.Bytes > softResponseLimit {
		req.Bytes = softResponseLimit
	}
	// Make sure we have the state associated with the request
	triedb := chain.StateCache().TrieDB()

	accTrie, err := trie.NewSecure(req.Root, triedb)
	if err != nil {
		// We don't have the requested state available, bail out
		return nil, nil
	}
	snap := chain.Snapshots().Snapshot(req.Root)
	if snap == nil {
		// We don't have the requested state snapshotted yet, bail out.
		// In reality we could still serve using the account and storage
		// tries only, but let's protect the node a bit while it's doing
		// snapshot generation.
		return nil, nil
	}
	// Retrieve trie nodes until the packet size limit is reached
	var (
		nodes [][]byte
		bytes uint64
		loads int // Trie hash expansions to cound database reads
	)
	for _, pathset := range req.Paths {
		switch len(pathset) {
		case 0:
			// Ensure we penalize invalid requests
			return nil, fmt.Errorf("%w: zero-item pathset requested", errBadRequest)

		case 1:
			// If we're only retrieving an account trie node, fetch it directly
			blob, resolved, err := accTrie.TryGetNode(pathset[0])
			loads += resolved // always account database reads, even for failures
			if err != nil {
				break
			}
			nodes = append(nodes, blob)
			bytes += uint64(len(blob))

		default:
			// Storage slots requested, open the storage trie and retrieve from there
			account, err := snap.Account(util.BytesToHash(pathset[0]))
			loads++ // always account database reads, even for failures
			if err != nil || account == nil {
				break
			}
			stTrie, err := trie.NewSecure(util.BytesToHash(account.Root), triedb)
			loads++ // always account database reads, even for failures
			if err != nil {
				break
			}
			for _, path := range pathset[1:] {
				blob, resolved, err := stTrie.TryGetNode(path)
				loads += resolved // always account database reads, even for failures
				if err != nil {
					break
				}
				nodes = append(nodes, blob)
				bytes += uint64(len(blob))

				// Sanity check limits to avoid DoS on the store trie loads
				if bytes > req.Bytes || loads > maxTrieNodeLookups || time.Since(start) > maxTrieNodeTimeSpent {
					break
				}
			}
		}
		// Abort request processing if we've exceeded our limits
		if bytes > req.Bytes || loads > maxTrieNodeLookups || time.Since(start) > maxTrieNodeTimeSpent {
			break
		}
	}
	return nodes, nil
}

// NodeInfo represents a short summary of the `snap` sub-protocol metadata
// known about the host peer.
type NodeInfo struct{}

// nodeInfo retrieves some `snap` protocol metadata about the running host node.
func nodeInfo(chain *validation.BlockChain) *NodeInfo {
	return &NodeInfo{}
}
