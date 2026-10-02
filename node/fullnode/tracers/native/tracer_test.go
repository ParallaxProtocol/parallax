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

package native_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers"
	_ "github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers/native"
)

// TestTracerStopRace exercises the concurrent Stop / GetResult path that the
// trace RPC handler uses: a timeout watchdog goroutine calls Stop while the
// main goroutine is still running the trace and will eventually call
// GetResult. Under -race, writes to the interruption reason field must not
// race with reads, for every tracer that implements it.
func TestTracerStopRace(t *testing.T) {
	for _, name := range []string{"callTracer", "4byteTracer", "prestateTracer"} {
		t.Run(name, func(t *testing.T) {
			tr, err := tracers.New(name, &tracers.Context{})
			if err != nil {
				t.Fatalf("failed to create tracer: %v", err)
			}
			stopErr := errors.New("execution timeout")
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				tr.Stop(stopErr)
			}()
			go func() {
				defer wg.Done()
				_, _ = tr.GetResult()
			}()
			wg.Wait()
		})
	}
}
