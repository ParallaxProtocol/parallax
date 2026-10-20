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
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/shirou/gopsutil/cpu"
)

// ReadCPUStats retrieves the current CPU stats.
func ReadCPUStats(stats *CPUStats) {
	// passing false to request all cpu times
	timeStats, err := cpu.Times(false)
	if err != nil {
		logging.Error("Could not read cpu stats", "err", err)
		return
	}
	if len(timeStats) == 0 {
		logging.Error("Empty cpu stats")
		return
	}
	// requesting all cpu times will always return an array with only one time stats entry
	timeStat := timeStats[0]
	// In hundredths of a second, as LocalTime is, on every system: gopsutil gives
	// seconds, and its own ClocksPerSec is 100ns on Windows (a share of hundredths
	// read 100,000 times the load there)
	stats.GlobalTime = int64((timeStat.User + timeStat.Nice + timeStat.System) * 100)
	stats.GlobalWait = int64(timeStat.Iowait * 100)
	stats.LocalTime = getProcessCPUTime()
}
