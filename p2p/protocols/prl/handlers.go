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

package prl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"

	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/p2p/tracker"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/trie"
)

// handleGetBlockHeaders66 is the eth/66 version of handleGetBlockHeaders
func handleGetBlockHeaders66(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the complex header query
	var query GetBlockHeadersPacket66
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	response := ServiceGetBlockHeadersQuery(backend.Chain(), query.GetBlockHeadersPacket, peer)
	return peer.ReplyBlockHeadersRLP(query.RequestId, response)
}

// ServiceGetBlockHeadersQuery assembles the response to a header query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetBlockHeadersQuery(chain *validation.BlockChain, query *GetBlockHeadersPacket, peer *Peer) []rlp.RawValue {
	if query.Skip == 0 {
		// The fast path: when the request is for a contiguous segment of headers.
		return serviceContiguousBlockHeaderQuery(chain, query)
	} else {
		return serviceNonContiguousBlockHeaderQuery(chain, query, peer)
	}
}

func serviceNonContiguousBlockHeaderQuery(chain *validation.BlockChain, query *GetBlockHeadersPacket, peer *Peer) []rlp.RawValue {
	hashMode := query.Origin.Hash != (util.Hash{})
	first := true
	maxNonCanonical := uint64(100)

	// Gather headers until the fetch or network limits is reached
	var (
		bytes   util.StorageSize
		headers []rlp.RawValue
		unknown bool
		lookups int
	)
	for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit &&
		len(headers) < maxHeadersServe && lookups < 2*maxHeadersServe {
		lookups++
		// Retrieve the next header satisfying the query
		var origin *types.Header
		if hashMode {
			if first {
				first = false
				origin = chain.GetHeaderByHash(query.Origin.Hash)
				if origin != nil {
					query.Origin.Number = origin.Number.Uint64()
				}
			} else {
				origin = chain.GetHeader(query.Origin.Hash, query.Origin.Number)
			}
		} else {
			origin = chain.GetHeaderByNumber(query.Origin.Number)
		}
		if origin == nil {
			break
		}
		if rlpData, err := rlp.EncodeToBytes(origin); err != nil {
			logging.Crit("Unable to decode our own headers", "err", err)
		} else {
			headers = append(headers, rlp.RawValue(rlpData))
			bytes += util.StorageSize(len(rlpData))
		}
		// Advance to the next header of the query
		switch {
		case hashMode && query.Reverse:
			// Hash based traversal towards the genesis block
			ancestor := query.Skip + 1
			if ancestor == 0 {
				unknown = true
			} else {
				query.Origin.Hash, query.Origin.Number = chain.GetAncestor(query.Origin.Hash, query.Origin.Number, ancestor, &maxNonCanonical)
				unknown = (query.Origin.Hash == util.Hash{})
			}
		case hashMode && !query.Reverse:
			// Hash based traversal towards the leaf block
			var (
				current = origin.Number.Uint64()
				next    = current + query.Skip + 1
			)
			if next <= current {
				infos, _ := json.MarshalIndent(peer.Peer.Info(), "", "  ")
				peer.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
				unknown = true
			} else {
				if header := chain.GetHeaderByNumber(next); header != nil {
					nextHash := header.Hash()
					expOldHash, _ := chain.GetAncestor(nextHash, next, query.Skip+1, &maxNonCanonical)
					if expOldHash == query.Origin.Hash {
						query.Origin.Hash, query.Origin.Number = nextHash, next
					} else {
						unknown = true
					}
				} else {
					unknown = true
				}
			}
		case query.Reverse:
			// Number based traversal towards the genesis block
			current := query.Origin.Number
			ancestor := current - (query.Skip + 1)
			if ancestor >= current { // check for underflow
				unknown = true
			} else {
				query.Origin.Number = ancestor
			}

		case !query.Reverse:
			// Number based traversal towards the leaf block
			current := query.Origin.Number
			next := current + query.Skip + 1
			if next <= current { // check for overflow
				unknown = true
			} else {
				query.Origin.Number = next
			}
		}
	}
	return headers
}

func serviceContiguousBlockHeaderQuery(chain *validation.BlockChain, query *GetBlockHeadersPacket) []rlp.RawValue {
	count := query.Amount
	if count > maxHeadersServe {
		count = maxHeadersServe
	}
	if count == 0 {
		// Nothing requested. Bail out early, otherwise the hash-mode path
		// below underflows count-1 and bypasses maxHeadersServe.
		return nil
	}
	if query.Origin.Hash == (util.Hash{}) {
		// Number mode, just return the canon chain segment. The backend
		// delivers in [N, N-1, N-2..] descending order, so we need to
		// accommodate for that.
		from := query.Origin.Number
		if !query.Reverse {
			from = from + count - 1
		}
		headers := chain.GetHeadersFrom(from, count)
		if !query.Reverse {
			for i, j := 0, len(headers)-1; i < j; i, j = i+1, j-1 {
				headers[i], headers[j] = headers[j], headers[i]
			}
		}
		return headers
	}
	// Hash mode.
	var (
		headers []rlp.RawValue
		hash    = query.Origin.Hash
		header  = chain.GetHeaderByHash(hash)
	)
	if header != nil {
		rlpData, _ := rlp.EncodeToBytes(header)
		headers = append(headers, rlpData)
	} else {
		// We don't even have the origin header
		return headers
	}
	num := header.Number.Uint64()
	if !query.Reverse {
		// Theoretically, we are tasked to deliver header by hash H, and onwards.
		// However, if H is not canon, we will be unable to deliver any descendants of
		// H.
		if canonHash := chain.GetCanonicalHash(num); canonHash != hash {
			// Not canon, we can't deliver descendants
			return headers
		}
		descendants := chain.GetHeadersFrom(num+count-1, count-1)
		for i, j := 0, len(descendants)-1; i < j; i, j = i+1, j-1 {
			descendants[i], descendants[j] = descendants[j], descendants[i]
		}
		headers = append(headers, descendants...)
		return headers
	}
	{ // Last mode: deliver ancestors of H
		for i := uint64(1); header != nil && i < count; i++ {
			header = chain.GetHeaderByHash(header.ParentHash)
			if header == nil {
				break
			}
			rlpData, _ := rlp.EncodeToBytes(header)
			headers = append(headers, rlpData)
		}
		return headers
	}
}

func handleGetBlockBodies66(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the block body retrieval message
	var query GetBlockBodiesPacket66
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	response := ServiceGetBlockBodiesQuery(backend.Chain(), query.GetBlockBodiesPacket)
	return peer.ReplyBlockBodiesRLP(query.RequestId, response)
}

// ServiceGetBlockBodiesQuery assembles the response to a body query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetBlockBodiesQuery(chain *validation.BlockChain, query GetBlockBodiesPacket) []rlp.RawValue {
	// Gather blocks until the fetch or network limits is reached
	var (
		bytes  int
		bodies []rlp.RawValue
	)
	for lookups, hash := range query {
		if bytes >= softResponseLimit || len(bodies) >= maxBodiesServe ||
			lookups >= 2*maxBodiesServe {
			break
		}
		if data := chain.GetBodyRLP(hash); len(data) != 0 {
			bodies = append(bodies, data)
			bytes += len(data)
		}
	}
	return bodies
}

func handleGetNodeData66(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the trie node data retrieval message
	var query GetNodeDataPacket66
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	response := ServiceGetNodeDataQuery(backend.Chain(), query.GetNodeDataPacket)
	return peer.ReplyNodeData(query.RequestId, response)
}

// ServiceGetNodeDataQuery assembles the response to a node data query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetNodeDataQuery(chain *validation.BlockChain, query GetNodeDataPacket) [][]byte {
	// Gather state data until the fetch or network limits is reached
	var (
		bytes int
		nodes [][]byte
	)
	for lookups, hash := range query {
		if bytes >= softResponseLimit || len(nodes) >= maxNodeDataServe ||
			lookups >= 2*maxNodeDataServe {
			break
		}
		// Retrieve the requested state entry
		entry, err := chain.TrieNode(hash)
		if len(entry) == 0 || err != nil {
			// Read the contract code with prefix only to save unnecessary lookups.
			entry, err = chain.ContractCodeWithPrefix(hash)
		}
		if err == nil && len(entry) > 0 {
			nodes = append(nodes, entry)
			bytes += len(entry)
		}
	}
	return nodes
}

func handleGetReceipts66(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the block receipts retrieval message
	var query GetReceiptsPacket66
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	response := ServiceGetReceiptsQuery(backend.Chain(), query.GetReceiptsPacket)
	return peer.ReplyReceiptsRLP(query.RequestId, response)
}

// ServiceGetReceiptsQuery assembles the response to a receipt query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetReceiptsQuery(chain *validation.BlockChain, query GetReceiptsPacket) []rlp.RawValue {
	// Gather state data until the fetch or network limits is reached
	var (
		bytes    int
		receipts []rlp.RawValue
	)
	for lookups, hash := range query {
		if bytes >= softResponseLimit || len(receipts) >= maxReceiptsServe ||
			lookups >= 2*maxReceiptsServe {
			break
		}
		// Retrieve the requested block's receipts
		results := chain.GetReceiptsByHash(hash)
		if results == nil {
			if header := chain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
				continue
			}
		}
		// If known, encode and queue for response packet
		if encoded, err := rlp.EncodeToBytes(results); err != nil {
			logging.Error("Failed to encode receipt", "err", err)
		} else {
			receipts = append(receipts, encoded)
			bytes += len(encoded)
		}
	}
	return receipts
}

func handleNewBlockhashes(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of new block announcements just arrived
	ann := new(NewBlockHashesPacket)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Mark the hashes as present at the remote node
	for _, block := range *ann {
		peer.markBlock(block.Hash)
	}
	// Deliver them all to the backend for queuing
	return backend.Handle(peer, ann)
}

func handleNewBlock(backend Backend, msg Decoder, peer *Peer) error {
	// Retrieve and decode the propagated block
	ann := new(NewBlockPacket)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	if err := ann.sanityCheck(); err != nil {
		return err
	}
	if hash := types.DeriveSha(ann.Block.Transactions(), trie.NewStackTrie(nil)); hash != ann.Block.TxHash() {
		logging.Warn("Propagated block has invalid body", "have", hash, "exp", ann.Block.TxHash())
		return nil // TODO(karalabe): return error eventually, but wait a few releases
	}
	ann.Block.ReceivedAt = msg.Time()
	ann.Block.ReceivedFrom = peer

	// Mark the peer as owning the block
	peer.markBlock(ann.Block.Hash())

	return backend.Handle(peer, ann)
}

func handleBlockHeaders66(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of headers arrived to one of our previous requests
	res := new(blockHeadersInput)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Check against the request before decoding the items.
	tresp := tracker.Response{ID: res.RequestId, MsgCode: BlockHeadersMsg, Size: res.List.Len()}
	if err := peer.tracker.Fulfil(tresp); err != nil {
		return fmt.Errorf("BlockHeaders: %w", err)
	}
	headers, err := res.List.Items()
	if err != nil {
		return fmt.Errorf("%w: BlockHeaders: %v", errDecode, err)
	}

	metadata := func() any {
		hashes := make([]util.Hash, len(headers))
		for i, header := range headers {
			hashes[i] = header.Hash()
		}
		return hashes
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: BlockHeadersMsg,
		Res:  (*BlockHeadersPacket)(&headers),
	}, metadata)
}

func handleBlockBodies66(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of block bodies arrived to one of our previous requests
	res := new(blockBodiesInput)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Check against the request before decoding the items.
	tresp := tracker.Response{ID: res.RequestId, MsgCode: BlockBodiesMsg, Size: res.List.Len()}
	if err := peer.tracker.Fulfil(tresp); err != nil {
		return fmt.Errorf("BlockBodies: %w", err)
	}
	// Split into bodies, but keep the transactions undecoded. They are only
	// decoded by the requester after the body is matched against its header.
	items, err := res.List.Items()
	if err != nil {
		return fmt.Errorf("%w: BlockBodies: %v", errDecode, err)
	}
	metadata := func() any { return hashBodyParts(items) }
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: BlockBodiesMsg,
		Res:  (*BlockBodiesResponse)(&items),
	}, metadata)
}

// hashBodyParts computes the transaction roots of the given block bodies
// directly from their encoded form.
func hashBodyParts(items []RawBlockBody) BlockBodyHashes {
	h := BlockBodyHashes{
		TransactionRoots: make([]util.Hash, len(items)),
	}
	hasher := trie.NewStackTrie(nil)
	for i, body := range items {
		txsList := newDerivableRawList(&body.Transactions, writeTxForHash)
		h.TransactionRoots[i] = types.DeriveSha(txsList, hasher)
	}
	return h
}

// derivableRawList implements types.DerivableList for a serialized RLP list.
type derivableRawList struct {
	data    []byte
	offsets []uint32
	write   func([]byte, *bytes.Buffer)
}

func newDerivableRawList[T any](list *rlp.RawList[T], write func([]byte, *bytes.Buffer)) *derivableRawList {
	dl := derivableRawList{data: list.Content(), write: write}
	if dl.write == nil {
		// default transform is identity
		dl.write = func(b []byte, buf *bytes.Buffer) { buf.Write(b) }
	}
	// Assert to ensure 32-bit offsets are valid. This can never trigger
	// unless a block body component is larger than 4GB.
	if uint(len(dl.data)) > math.MaxUint32 {
		panic("list data too big for derivableRawList")
	}
	it := list.ContentIterator()
	dl.offsets = make([]uint32, list.Len())
	for i := 0; it.Next(); i++ {
		dl.offsets[i] = uint32(it.Offset())
	}
	return &dl
}

// Len returns the number of items in the list.
func (dl *derivableRawList) Len() int {
	return len(dl.offsets)
}

// EncodeIndex writes the i'th item to the buffer.
func (dl *derivableRawList) EncodeIndex(i int, buf *bytes.Buffer) {
	start := dl.offsets[i]
	end := uint32(len(dl.data))
	if i != len(dl.offsets)-1 {
		end = dl.offsets[i+1]
	}
	dl.write(dl.data[start:end], buf)
}

// writeTxForHash changes a transaction in 'network encoding' into the format used for
// the transactions MPT.
func writeTxForHash(tx []byte, buf *bytes.Buffer) {
	k, content, _, _ := rlp.Split(tx)
	if k == rlp.List {
		buf.Write(tx) // legacy tx
	} else {
		buf.Write(content) // typed tx
	}
}

func handleNodeData66(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of node state data arrived to one of our previous requests
	res := new(nodeDataInput)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Check against the request before decoding the items.
	tresp := tracker.Response{ID: res.RequestId, MsgCode: NodeDataMsg, Size: res.List.Len()}
	if err := peer.tracker.Fulfil(tresp); err != nil {
		return fmt.Errorf("NodeData: %w", err)
	}
	nodes, err := res.List.Items()
	if err != nil {
		return fmt.Errorf("%w: NodeData: %v", errDecode, err)
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: NodeDataMsg,
		Res:  (*NodeDataPacket)(&nodes),
	}, nil) // No post-processing, we're not using this packet anymore
}

func handleReceipts66(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of receipts arrived to one of our previous requests
	res := new(receiptsInput)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Check against the request before decoding the items.
	tresp := tracker.Response{ID: res.RequestId, MsgCode: ReceiptsMsg, Size: res.List.Len()}
	if err := peer.tracker.Fulfil(tresp); err != nil {
		return fmt.Errorf("Receipts: %w", err)
	}
	receipts, err := res.List.Items()
	if err != nil {
		return fmt.Errorf("%w: Receipts: %v", errDecode, err)
	}
	metadata := func() any {
		hasher := trie.NewStackTrie(nil)
		hashes := make([]util.Hash, len(receipts))
		for i, receipt := range receipts {
			hashes[i] = types.DeriveSha(types.Receipts(receipt), hasher)
		}
		return hashes
	}
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: ReceiptsMsg,
		Res:  (*ReceiptsPacket)(&receipts),
	}, metadata)
}

func handleNewPooledTransactionHashes(backend Backend, msg Decoder, peer *Peer) error {
	// Feelers never register into the peerset; this is a defensive
	// backstop, drained silently.
	if peer.Feeler() {
		return nil
	}
	// A block-relay-only peer announcing transactions is a protocol
	// violation: it saw our Hello with the relay bit cleared. Core
	// disconnects ("transaction inv sent in violation of protocol",
	// net_processing.cpp) — a silent drop would hand the violator a
	// free slot to spam from.
	if peer.BlockRelayOnly() {
		return errTxFromBlockRelayPeer
	}
	// New transaction announcement arrived, make sure we have
	// a valid and fresh chain to handle them
	if !backend.AcceptTxs() {
		return nil
	}
	ann := new(NewPooledTransactionHashesPacket)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Schedule all the unknown hashes for retrieval
	for _, hash := range *ann {
		peer.markTransaction(hash)
	}
	return backend.Handle(peer, ann)
}

func handleGetPooledTransactions66(backend Backend, msg Decoder, peer *Peer) error {
	// Block-relay-only peers should never request pooled tx from us
	// (we advertised m_relay_txs=false in Hello.Services). Treat the
	// request as a protocol-discipline violation: drop without
	// answering. Silent so an attacker can't probe the bit.
	if peer.BlockRelayOnly() || peer.Feeler() {
		return nil
	}
	// Decode the pooled transactions retrieval message
	var query GetPooledTransactionsPacket66
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	hashes, txs := answerGetPooledTransactions(backend, query.GetPooledTransactionsPacket, peer)
	return peer.ReplyPooledTransactionsRLP(query.RequestId, hashes, txs)
}

func answerGetPooledTransactions(backend Backend, query GetPooledTransactionsPacket, peer *Peer) ([]util.Hash, []rlp.RawValue) {
	// Gather transactions until the fetch or network limits is reached
	var (
		bytes  int
		hashes []util.Hash
		txs    []rlp.RawValue
	)
	for _, hash := range query {
		if bytes >= softResponseLimit {
			break
		}
		// Retrieve the requested transaction, skipping if unknown to us
		tx := backend.TxPool().Get(hash)
		if tx == nil {
			continue
		}
		// If known, encode and queue for response packet
		if encoded, err := rlp.EncodeToBytes(tx); err != nil {
			logging.Error("Failed to encode transaction", "err", err)
		} else {
			hashes = append(hashes, hash)
			txs = append(txs, encoded)
			bytes += len(encoded)
		}
	}
	return hashes, txs
}

func handleTransactions(backend Backend, msg Decoder, peer *Peer) error {
	// Feelers never register into the peerset; defensive backstop.
	if peer.Feeler() {
		return nil
	}
	// Block-relay-only peers MUST NOT push tx to us: Core disconnects
	// ("transaction sent in violation of protocol"). Never stamping
	// lastTxRx for them also keeps the eviction "newest tx among
	// tx-relayers" round honest (eviction.cpp:194).
	if peer.BlockRelayOnly() {
		return errTxFromBlockRelayPeer
	}
	// Transactions arrived, make sure we have a valid and fresh chain to handle them
	if !backend.AcceptTxs() {
		return nil
	}
	// Transactions can be processed, parse all of them and deliver to the pool.
	// The item count is checked before decoding the transactions themselves.
	var list rlp.RawList[*types.Transaction]
	if err := msg.Decode(&list); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	if list.Len() > maxTransactionAnnouncements {
		return fmt.Errorf("%w: too many transactions (%d)", errDecode, list.Len())
	}
	items, err := list.Items()
	if err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	txs := TransactionsPacket(items)
	for i, tx := range txs {
		// Validate and mark the remote transaction
		if tx == nil {
			return fmt.Errorf("%w: transaction %d is nil", errDecode, i)
		}
		peer.markTransaction(tx.Hash())
	}
	return backend.Handle(peer, &txs)
}

func handlePooledTransactions66(backend Backend, msg Decoder, peer *Peer) error {
	// Same block-relay-only rule as handleTransactions.
	if peer.Feeler() {
		return nil
	}
	if peer.BlockRelayOnly() {
		return errTxFromBlockRelayPeer
	}
	// Transactions arrived, make sure we have a valid and fresh chain to handle them
	if !backend.AcceptTxs() {
		return nil
	}
	// Check against the request before decoding the transactions.
	var res pooledTransactionsInput
	if err := msg.Decode(&res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	tresp := tracker.Response{ID: res.RequestId, MsgCode: PooledTransactionsMsg, Size: res.List.Len()}
	if err := peer.tracker.Fulfil(tresp); err != nil {
		return fmt.Errorf("PooledTransactions: %w", err)
	}
	items, err := res.List.Items()
	if err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	txs := PooledTransactionsPacket(items)
	for i, tx := range txs {
		// Validate and mark the remote transaction
		if tx == nil {
			return fmt.Errorf("%w: transaction %d is nil", errDecode, i)
		}
		peer.markTransaction(tx.Hash())
	}
	return backend.Handle(peer, &txs)
}
