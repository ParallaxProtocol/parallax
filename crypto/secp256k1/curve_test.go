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

//go:build !gofuzz && cgo

package secp256k1

import (
	"math/big"
	"testing"
)

// smallXPoint returns a curve point whose x coordinate is small enough that
// x+P still fits into 256 bits.
func smallXPoint(t *testing.T) (x, y *big.Int) {
	curve := S256()
	for i := int64(1); i < 1000; i++ {
		x = big.NewInt(i)
		rhs := new(big.Int).Exp(x, big.NewInt(3), curve.P)
		rhs.Add(rhs, curve.B)
		rhs.Mod(rhs, curve.P)
		if y = new(big.Int).ModSqrt(rhs, curve.P); y != nil {
			return x, y
		}
	}
	t.Fatal("no point with small x found")
	return nil, nil
}

// TestCoordinateRange checks that coordinates which are congruent to a valid
// point but not reduced modulo P are rejected.
func TestCoordinateRange(t *testing.T) {
	curve := S256()
	x, y := smallXPoint(t)
	if !curve.IsOnCurve(x, y) {
		t.Fatal("reduced point not on curve")
	}
	xBig := new(big.Int).Add(x, curve.P)
	yBig := new(big.Int).Add(y, curve.P)
	if xBig.BitLen() > 256 {
		t.Fatal("test point too large")
	}
	if curve.IsOnCurve(xBig, y) {
		t.Error("IsOnCurve accepted x >= P")
	}
	if yBig.BitLen() <= 256 && curve.IsOnCurve(x, yBig) {
		t.Error("IsOnCurve accepted y >= P")
	}
	scalar := make([]byte, 32)
	scalar[31] = 2
	if rx, ry := curve.ScalarMult(xBig, y, scalar); rx != nil || ry != nil {
		t.Error("ScalarMult accepted x >= P")
	}
	if rx, _ := curve.ScalarMult(x, y, scalar); rx == nil {
		t.Error("ScalarMult rejected valid point")
	}
}
