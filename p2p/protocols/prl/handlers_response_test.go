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
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/tracker"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation/trie"
)

func encodeRL[T any](slice []T) rlp.RawList[T] {
	rl, err := rlp.EncodeToRawList(slice)
	if err != nil {
		panic(err)
	}
	return rl
}

func encodeBody(b *types.Block) RawBlockBody {
	return RawBlockBody{Transactions: encodeRL([]*types.Transaction(b.Transactions()))}
}

// Tests that the transaction roots computed from the undecoded block bodies
// match the ones in the block headers.
func TestHashBody(t *testing.T) {
	key, _ := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	signer := types.NewLondonSigner(big.NewInt(1))

	// block 1 has a typed and a legacy transaction
	header := &types.Header{Number: big.NewInt(11)}
	txs := []*types.Transaction{
		types.MustSignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID: big.NewInt(1),
			Nonce:   1,
			Data:    []byte("testing"),
		}),
		types.MustSignNewTx(key, signer, &types.LegacyTx{
			Nonce: 2,
			Data:  []byte("testing"),
		}),
	}
	block1 := types.NewBlock(header, txs, nil, nil, trie.NewStackTrie(nil))

	// block 2 is empty
	header2 := &types.Header{Number: big.NewInt(12)}
	block2 := types.NewBlock(header2, nil, nil, nil, trie.NewStackTrie(nil))

	expected := BlockBodyHashes{
		TransactionRoots: []util.Hash{block1.TxHash(), block2.TxHash()},
	}
	hashes := hashBodyParts([]RawBlockBody{encodeBody(block1), encodeBody(block2)})
	if !reflect.DeepEqual(hashes, expected) {
		t.Errorf("wrong hashes: have %x, want %x", hashes.TransactionRoots, expected.TransactionRoots)
	}
}

// waitHandlerError waits for the protocol handler of the given peer to fail and
// returns the error it terminated with.
func waitHandlerError(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("protocol handler did not terminate")
		return nil
	}
}

// Tests that responses which don't match any request are rejected before
// their content is decoded.
func TestUnsolicitedResponses(t *testing.T) {
	backend := newTestBackend(4)
	defer backend.close()

	block := backend.chain.GetBlockByNumber(1)
	tests := []struct {
		code uint64
		data any
	}{
		{BlockHeadersMsg, &BlockHeadersPacket66{RequestId: 1, BlockHeadersPacket: BlockHeadersPacket{block.Header()}}},
		{BlockBodiesMsg, &blockBodiesInput{RequestId: 1, List: encodeRL([]RawBlockBody{encodeBody(block)})}},
		{NodeDataMsg, &NodeDataPacket66{RequestId: 1, NodeDataPacket: NodeDataPacket{{0x01}}}},
		{ReceiptsMsg, &ReceiptsPacket66{RequestId: 1, ReceiptsPacket: ReceiptsPacket{{}}}},
	}
	for i, tt := range tests {
		peer, errc := newTestPeer("peer", Parallax66, backend)
		if err := p2p.Send(peer.app, tt.code, tt.data); err != nil {
			t.Fatalf("test %d: send failed: %v", i, err)
		}
		if err := waitHandlerError(t, errc); !errors.Is(err, tracker.ErrNoMatchingRequest) {
			t.Errorf("test %d: wrong error: %v", i, err)
		}
		peer.close()
	}
}

// Tests that a response containing more items than requested is rejected.
func TestResponseTooManyItems(t *testing.T) {
	backend := newTestBackend(4)
	defer backend.close()

	peer, errc := newTestPeer("peer", Parallax66, backend)
	defer peer.close()

	// Request a single body.
	block := backend.chain.GetBlockByNumber(1)
	sink := make(chan *Response, 1)
	go peer.RequestBodies([]util.Hash{block.Hash()}, sink)

	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatal("failed to read request:", err)
	}
	var req GetBlockBodiesPacket66
	if err := msg.Decode(&req); err != nil {
		t.Fatal("failed to decode request:", err)
	}
	// Answer it with two bodies.
	bodies := []RawBlockBody{encodeBody(block), encodeBody(block)}
	resp := &blockBodiesInput{RequestId: req.RequestId, List: encodeRL(bodies)}
	if err := p2p.Send(peer.app, BlockBodiesMsg, resp); err != nil {
		t.Fatal("send failed:", err)
	}
	if err := waitHandlerError(t, errc); !errors.Is(err, tracker.ErrTooManyItems) {
		t.Errorf("wrong error: %v", err)
	}
}
