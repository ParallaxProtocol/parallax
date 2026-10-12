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

package nat

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// This test checks that autodisc doesn't hang and returns
// consistent results when multiple goroutines call its methods
// concurrently.
func TestAutoDiscRace(t *testing.T) {
	ad := startautodisc("thing", func() Interface {
		time.Sleep(500 * time.Millisecond)
		return ExtIP{33, 44, 55, 66}
	})

	// Spawn a few concurrent calls to ad.ExternalIP.
	type rval struct {
		ip  net.IP
		err error
	}
	results := make(chan rval, 50)
	for i := 0; i < cap(results); i++ {
		go func() {
			ip, err := ad.ExternalIP()
			results <- rval{ip, err}
		}()
	}

	// Check that they all return the correct result within the deadline.
	deadline := time.After(2 * time.Second)
	for i := 0; i < cap(results); i++ {
		select {
		case <-deadline:
			t.Fatal("deadline exceeded")
		case rval := <-results:
			if rval.err != nil {
				t.Errorf("result %d: unexpected error: %v", i, rval.err)
			}
			wantIP := net.IP{33, 44, 55, 66}
			if !rval.ip.Equal(wantIP) {
				t.Errorf("result %d: got IP %v, want %v", i, rval.ip, wantIP)
			}
		}
	}
}

// flakyMapper succeeds, then fails once, then succeeds again.
type flakyMapper struct {
	ExtIP
	calls atomic.Int32
}

func (m *flakyMapper) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	if m.calls.Add(1) == 2 {
		return 0, errors.New("SOAP timeout")
	}
	return uint16(extport), nil
}

// TestMapReportsLostMapping — a failed renewal reports port 0 so the
// caller stops advertising a mapping the router may have dropped, and
// the next successful renewal reports the port again.
func TestMapReportsLostMapping(t *testing.T) {
	prev := mapRefresh
	mapRefresh = 5 * time.Millisecond
	t.Cleanup(func() { mapRefresh = prev })

	m := &flakyMapper{ExtIP: ExtIP{1, 2, 3, 4}}
	quit := make(chan struct{})
	ports := make(chan uint16, 8)
	done := make(chan struct{})
	go func() {
		Map(m, quit, "tcp", 32110, 32110, "test", func(p uint16) { ports <- p })
		close(done)
	}()
	for i, want := range []uint16{32110, 0, 32110} {
		select {
		case got := <-ports:
			if got != want {
				t.Fatalf("report %d: got port %d, want %d", i, got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("report %d: timed out waiting for port %d", i, want)
		}
	}
	close(quit)
	<-done
}
