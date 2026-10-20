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

//go:build !ios && !js

package metrics

import (
	"math"
	"runtime"
	"testing"
	"time"

	"github.com/shirou/gopsutil/cpu"
)

// busySeconds is the CPU time the whole machine has worked, as gopsutil gives it.
func busySeconds(t *testing.T) float64 {
	times, err := cpu.Times(false)
	if err != nil || len(times) == 0 {
		t.Fatalf("cpu times: %v", err)
	}
	return times[0].User + times[0].Nice + times[0].System
}

// The machine's CPU time is in hundredths of a second on every system, as
// the process's is: Windows' ticks are 100ns, which read as 100,000 times
// the load.
func TestReadCPUStatsHundredths(t *testing.T) {
	var before, after CPUStats
	from := busySeconds(t)
	ReadCPUStats(&before)
	time.Sleep(time.Second)
	ReadCPUStats(&after)
	to := busySeconds(t)

	// The two readings bracket the same second, a tick apart at each end
	got := float64(after.GlobalTime-before.GlobalTime) / 100
	if want := to - from; math.Abs(got-want) > 0.05*float64(runtime.NumCPU())+0.05 {
		t.Fatalf("machine CPU time over a second = %vs, gopsutil says %vs", got, want)
	}
	if share := got / float64(runtime.NumCPU()); share < 0 || share > 1.1 {
		t.Fatalf("machine CPU load over a second = %v of its cores, want 0..1", share)
	}
}
