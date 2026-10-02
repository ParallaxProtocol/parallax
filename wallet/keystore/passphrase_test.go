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

package keystore

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/google/uuid"
)

const (
	veryLightScryptN = 2
	veryLightScryptP = 1
)

// Tests that decrypting a key file whose payload is not a valid secp256k1
// private key returns an error instead of panicking.
func TestDecryptInvalidKey(t *testing.T) {
	id, _ := uuid.NewRandom()
	for _, keyBytes := range [][]byte{
		make([]byte, 32),               // zero key
		bytes.Repeat([]byte{0xff}, 32), // key >= N
		{0x01},                         // wrong length
	} {
		cryptoStruct, err := EncryptDataV3(keyBytes, []byte("foo"), veryLightScryptN, veryLightScryptP)
		if err != nil {
			t.Fatal(err)
		}
		keyjson, err := json.Marshal(encryptedKeyJSONV3{
			Address: "0000000000000000000000000000000000000000",
			Crypto:  cryptoStruct,
			Id:      id.String(),
			Version: version,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecryptKey(keyjson, "foo"); err == nil {
			t.Errorf("key %x: expected error, got nil", keyBytes)
		}
	}
}

// Tests that a json key file can be decrypted and encrypted in multiple rounds.
func TestKeyEncryptDecrypt(t *testing.T) {
	keyjson, err := os.ReadFile("testdata/very-light-scrypt.json")
	if err != nil {
		t.Fatal(err)
	}
	password := ""
	address := util.HexToAddress("45dea0fb0bba44f4fcf290bba71fd57d7117cbb8")

	// Do a few rounds of decryption and encryption
	for i := 0; i < 3; i++ {
		// Try a bad password first
		if _, err := DecryptKey(keyjson, password+"bad"); err == nil {
			t.Errorf("test %d: json key decrypted with bad password", i)
		}
		// Decrypt with the correct password
		key, err := DecryptKey(keyjson, password)
		if err != nil {
			t.Fatalf("test %d: json key failed to decrypt: %v", i, err)
		}
		if key.Address != address {
			t.Errorf("test %d: key address mismatch: have %x, want %x", i, key.Address, address)
		}
		// Recrypt with a new password and start over
		password += "new data appended"
		if keyjson, err = EncryptKey(key, password, veryLightScryptN, veryLightScryptP); err != nil {
			t.Errorf("test %d: failed to recrypt key %v", i, err)
		}
	}
}
