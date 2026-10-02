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

package rlpx

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/crypto/ecies"
)

// TestHandshakeMessageTooBig checks that oversized handshake messages are
// rejected before the packet body is read.
func TestHandshakeMessageTooBig(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Size prefix of 0xFFFF followed by no body: the read must fail on the
	// size check, not by waiting for (or buffering) 64KB of input.
	var h handshakeState
	_, err = h.readMsg(new(authMsgV4), key, bytes.NewReader([]byte{0xFF, 0xFF}))
	if err == nil || err.Error() != "message too big" {
		t.Fatalf("expected 'message too big' error, got %v", err)
	}
}

func TestHandshakeECIESInvalidCurveOracle(t *testing.T) {
	initKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	respKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	init := handshakeState{
		initiator: true,
		remote:    ecies.ImportECDSAPublic(&respKey.PublicKey),
	}
	authMsg, err := init.makeAuthMsg(initKey)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := init.sealEIP8(authMsg)
	if err != nil {
		t.Fatal(err)
	}

	var recv handshakeState
	if _, err := recv.readMsg(new(authMsgV4), respKey, bytes.NewReader(packet)); err != nil {
		t.Fatalf("expected valid packet to decrypt: %v", err)
	}

	tampered := append([]byte(nil), packet...)
	if len(tampered) < 2+65 {
		t.Fatalf("unexpected packet length %d", len(tampered))
	}
	tampered[2] = 0x04
	for i := 1; i < 65; i++ {
		tampered[2+i] = 0x00
	}

	var recv2 handshakeState
	_, err = recv2.readMsg(new(authMsgV4), respKey, bytes.NewReader(tampered))
	if err == nil {
		t.Fatal("expected decryption failure for invalid curve point")
	}
	if !errors.Is(err, ecies.ErrInvalidPublicKey) {
		t.Fatalf("unexpected error: %v", err)
	}
}
