// Copyright 2025-2026 The Parallax Protocol Authors
// This file is part of parallax.
//
// parallax is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// parallax is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with parallax. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"slices"
	"testing"

	"github.com/ParallaxProtocol/parallax/v2/node/stats"
)

func TestExpandBarePrlStats(t *testing.T) {
	def := "--prlstats=" + stats.DefaultHost
	cases := []struct {
		args, want []string
	}{
		// Bare: last, before a flag, before a command.
		{[]string{"parallaxd", "--prlstats"}, []string{"parallaxd", def}},
		{[]string{"parallaxd", "--prlstats", "--http"}, []string{"parallaxd", def, "--http"}},
		{[]string{"parallaxd", "--prlstats", "console"}, []string{"parallaxd", def, "console"}},
		{[]string{"parallaxd", "-prlstats", "console"}, []string{"parallaxd", "-prlstats=" + stats.DefaultHost, "console"}},
		// With a value: unchanged.
		{[]string{"parallaxd", "--prlstats", "me@status.parallaxprotocol.org", "console"}, []string{"parallaxd", "--prlstats", "me@status.parallaxprotocol.org", "console"}},
		{[]string{"parallaxd", "--prlstats", "stats.example.org:3000"}, []string{"parallaxd", "--prlstats", "stats.example.org:3000"}},
		{[]string{"parallaxd", "--prlstats=me@host"}, []string{"parallaxd", "--prlstats=me@host"}},
		// After "--": not a flag.
		{[]string{"parallaxd", "js", "--", "--prlstats"}, []string{"parallaxd", "js", "--", "--prlstats"}},
	}
	for _, c := range cases {
		if got := expandBarePrlStats(c.args, app.Commands); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.args, got, c.want)
		}
	}
}
