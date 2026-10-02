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
	"errors"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/tracker"
	"github.com/ParallaxProtocol/parallax/v2/util"
)

// Tests that snap responses are checked against the originating request
// before their content is decoded.
func TestResponseValidation(t *testing.T) {
	proof := make([][]byte, 129)
	for i := range proof {
		proof[i] = []byte{0x01}
	}
	tests := []struct {
		name    string
		request func(p *Peer) error
		code    uint64
		data    any
		err     error
	}{
		{
			name: "unsolicited AccountRange",
			code: AccountRangeMsg,
			data: &AccountRangePacket{ID: 1, Accounts: []*AccountData{{Hash: util.Hash{1}, Body: []byte{0x80}}}},
			err:  tracker.ErrNoMatchingRequest,
		},
		{
			name: "unsolicited StorageRanges",
			code: StorageRangesMsg,
			data: &StorageRangesPacket{ID: 1, Slots: [][]*StorageData{{}}},
			err:  tracker.ErrNoMatchingRequest,
		},
		{
			name: "unsolicited ByteCodes",
			code: ByteCodesMsg,
			data: &ByteCodesPacket{ID: 1, Codes: [][]byte{{0x01}}},
			err:  tracker.ErrNoMatchingRequest,
		},
		{
			name: "unsolicited TrieNodes",
			code: TrieNodesMsg,
			data: &TrieNodesPacket{ID: 1, Nodes: [][]byte{{0x01}}},
			err:  tracker.ErrNoMatchingRequest,
		},
		{
			name: "too many ByteCodes",
			request: func(p *Peer) error {
				return p.RequestByteCodes(1, []util.Hash{{1}}, 1024)
			},
			code: ByteCodesMsg,
			data: &ByteCodesPacket{ID: 1, Codes: [][]byte{{0x01}, {0x02}}},
			err:  tracker.ErrTooManyItems,
		},
		{
			name: "too many TrieNodes",
			request: func(p *Peer) error {
				return p.RequestTrieNodes(1, util.Hash{}, []TrieNodePathSet{{{0x01}}}, 1024)
			},
			code: TrieNodesMsg,
			data: &TrieNodesPacket{ID: 1, Nodes: [][]byte{{0x01}, {0x02}}},
			err:  tracker.ErrTooManyItems,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, net := p2p.MsgPipe()
			defer app.Close()
			peer := NewFakePeer(SNAP1, "0123456789abcdef", net)
			defer peer.Close()

			if tt.request != nil {
				go func() {
					if err := tt.request(peer); err != nil {
						t.Error("request failed:", err)
					}
				}()
				msg, err := app.ReadMsg()
				if err != nil {
					t.Fatal("failed to read request:", err)
				}
				msg.Discard()
			}
			go p2p.Send(app, tt.code, tt.data)
			if err := HandleMessage(nil, peer); !errors.Is(err, tt.err) {
				t.Fatalf("wrong error: have %v, want %v", err, tt.err)
			}
		})
	}

	// Oversized proofs are rejected outright.
	app, net := p2p.MsgPipe()
	defer app.Close()
	peer := NewFakePeer(SNAP1, "0123456789abcdef", net)
	defer peer.Close()
	go p2p.Send(app, AccountRangeMsg, &AccountRangePacket{ID: 1, Proof: proof})
	if err := HandleMessage(nil, peer); err == nil {
		t.Fatal("oversized proof accepted")
	}
}
