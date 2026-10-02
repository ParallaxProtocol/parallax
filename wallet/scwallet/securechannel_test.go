// Copyright 2026 The Parallax Protocol Authors
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

package scwallet

import (
	"testing"
)

// Tests that decryptAPDU rejects ciphertexts that are empty or not a multiple
// of the AES block size instead of panicking.
func TestDecryptAPDUInvalidLength(t *testing.T) {
	s := &SecureChannelSession{
		sessionEncKey: make([]byte, 32),
		iv:            make([]byte, 16),
	}
	for _, n := range []int{0, 1, 15, 17, 31} {
		if _, err := s.decryptAPDU(make([]byte, n)); err == nil {
			t.Errorf("length %d: expected error, got nil", n)
		}
	}
}
