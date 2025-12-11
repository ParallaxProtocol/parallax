// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package prltest

import (
	"strconv"
	"testing"

	"github.com/ParallaxProtocol/parallax/p2p"
	"github.com/stretchr/testify/assert"
)

// TestParallaxProtocolNegotiation tests whether the test suite
// can negotiate the highest parallax protocol in a status message exchange
func TestParallaxProtocolNegotiation(t *testing.T) {
	tests := []struct {
		conn     *Conn
		caps     []p2p.Cap
		expected uint32
	}{
		{
			conn: &Conn{
				ourHighestProtoVersion: 65,
			},
			caps: []p2p.Cap{
				{Name: "parallax", Version: 63},
				{Name: "parallax", Version: 64},
				{Name: "parallax", Version: 65},
			},
			expected: uint32(65),
		},
		{
			conn: &Conn{
				ourHighestProtoVersion: 65,
			},
			caps: []p2p.Cap{
				{Name: "parallax", Version: 63},
				{Name: "parallax", Version: 64},
				{Name: "parallax", Version: 65},
			},
			expected: uint32(65),
		},
		{
			conn: &Conn{
				ourHighestProtoVersion: 65,
			},
			caps: []p2p.Cap{
				{Name: "parallax", Version: 63},
				{Name: "parallax", Version: 64},
				{Name: "parallax", Version: 65},
			},
			expected: uint32(65),
		},
		{
			conn: &Conn{
				ourHighestProtoVersion: 64,
			},
			caps: []p2p.Cap{
				{Name: "parallax", Version: 63},
				{Name: "parallax", Version: 64},
				{Name: "parallax", Version: 65},
			},
			expected: 64,
		},
		{
			conn: &Conn{
				ourHighestProtoVersion: 65,
			},
			caps: []p2p.Cap{
				{Name: "parallax", Version: 0},
				{Name: "parallax", Version: 89},
				{Name: "parallax", Version: 65},
			},
			expected: uint32(65),
		},
		{
			conn: &Conn{
				ourHighestProtoVersion: 64,
			},
			caps: []p2p.Cap{
				{Name: "parallax", Version: 63},
				{Name: "parallax", Version: 64},
				{Name: "wrongProto", Version: 65},
			},
			expected: uint32(64),
		},
		{
			conn: &Conn{
				ourHighestProtoVersion: 65,
			},
			caps: []p2p.Cap{
				{Name: "parallax", Version: 63},
				{Name: "parallax", Version: 64},
				{Name: "wrongProto", Version: 65},
			},
			expected: uint32(64),
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			tt.conn.negotiateParallaxProtocol(tt.caps)
			assert.Equal(t, tt.expected, uint32(tt.conn.negotiatedProtoVersion))
		})
	}
}
