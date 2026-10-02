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

package rpc

import (
	"errors"
	"strings"
	"testing"
)

func TestLimitedBufferEnforcesLimit(t *testing.T) {
	buf := limitedBuffer{limit: 10}
	for i := 0; i < 5; i++ {
		buf.Write([]byte("abcd"))
	}
	if len(buf.output) != 10 {
		t.Fatalf("buffer grew past its limit: have %d bytes, want 10", len(buf.output))
	}
	if n, err := buf.Write([]byte("x")); n != 0 || !errors.Is(err, errTruncatedOutput) {
		t.Fatalf("write to full buffer: have (%d, %v), want (0, %v)", n, err, errTruncatedOutput)
	}
}

func TestFormatErrorData(t *testing.T) {
	if have := formatErrorData("short"); have != `"short"` {
		t.Fatalf("wrong short error data: %s", have)
	}
	have := formatErrorData(strings.Repeat("x", 5000))
	if !strings.HasSuffix(have, "... (truncated)") {
		t.Fatalf("long error data not truncated")
	}
	if len(have) > 1024+len("... (truncated)") {
		t.Fatalf("truncated error data too long: %d bytes", len(have))
	}
}
