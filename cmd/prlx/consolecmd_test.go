// Copyright 2016 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"crypto/rand"
	"math/big"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ParallaxProtocol/parallax/params"
)

const (
	ipcAPIs  = "admin:1.0 debug:1.0 eth:1.0 miner:1.0 net:1.0 personal:1.0 rpc:1.0 txpool:1.0 web3:1.0 xhash:1.0"
	httpAPIs = "eth:1.0 net:1.0 rpc:1.0 web3:1.0"
)

// spawns prlx with the given command line args, using a set of flags to minimise
// memory and disk IO. If the args don't set --datadir, the
// child g gets a temporary data directory.
func runMinimalPrlx(t *testing.T, args ...string) *testprlx {
	// --testnet to make the 'writing genesis to disk' faster (no accounts)
	// --networkid=2111 to avoid cache bump
	// --syncmode=full to avoid allocating fast sync bloom
	allArgs := []string{
		"--testnet", "--networkid", "2111", "--syncmode=full", "--port", "0",
		"--nat", "none", "--nodiscover", "--maxpeers", "0", "--cache", "64",
		"--datadir.minfreedisk", "0",
	}
	return runPrlx(t, append(allArgs, args...)...)
}

// Tests that a node embedded within a console can be started up properly and
// then terminated by closing the input stream.
func TestConsoleWelcome(t *testing.T) {
	coinbase := "0x8605cdbbdb6d264aa742e77020dcbc58fcdce182"

	// Start a prlx console, make sure it's cleaned up and terminate the console
	prlx := runMinimalPrlx(t, "--miner.coinbase", coinbase, "console")

	// Gather all the infos the welcome message needs to contain
	prlx.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	prlx.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	prlx.SetTemplateFunc("gover", runtime.Version)
	prlx.SetTemplateFunc("prlxver", func() string { return params.VersionWithCommit("", "") })
	prlx.SetTemplateFunc("niltime", func() string {
		return time.Unix(1759695695, 0).Format("Mon Jan 02 2006 15:04:05 GMT-0700 (MST)")
	})
	prlx.SetTemplateFunc("apis", func() string { return ipcAPIs })

	// Verify the actual welcome message to the required template
	prlx.Expect(`
Welcome to the Parallax JavaScript console!

instance: Parallax/v{{prlxver}}/{{goos}}-{{goarch}}/{{gover}}
coinbase: {{.Coinbase}}
at block: 0 ({{niltime}})
 datadir: {{.Datadir}}
 modules: {{apis}}

To exit, press ctrl-d or type exit
> {{.InputLine "exit"}}
`)
	prlx.ExpectExit()
}

// Tests that a console can be attached to a running node via various means.
func TestAttachWelcome(t *testing.T) {
	var (
		ipc      string
		httpPort string
		wsPort   string
	)
	// Configure the instance for IPC attachment
	if runtime.GOOS == "windows" {
		ipc = `\\.\pipe\prlx` + strconv.Itoa(trulyRandInt(100000, 999999))
	} else {
		ipc = filepath.Join(t.TempDir(), "prlx.ipc")
	}
	// And HTTP + WS attachment
	p := trulyRandInt(1024, 65533) // Yeah, sometimes this will fail, sorry :P
	httpPort = strconv.Itoa(p)
	wsPort = strconv.Itoa(p + 1)
	prlx := runMinimalPrlx(t, "--miner.coinbase", "0x8605cdbbdb6d264aa742e77020dcbc58fcdce182",
		"--ipcpath", ipc,
		"--http", "--http.port", httpPort,
		"--ws", "--ws.port", wsPort)
	t.Run("ipc", func(t *testing.T) {
		waitForEndpoint(t, ipc, 3*time.Second)
		testAttachWelcome(t, prlx, "ipc:"+ipc, ipcAPIs)
	})
	t.Run("http", func(t *testing.T) {
		endpoint := "http://127.0.0.1:" + httpPort
		waitForEndpoint(t, endpoint, 3*time.Second)
		testAttachWelcome(t, prlx, endpoint, httpAPIs)
	})
	t.Run("ws", func(t *testing.T) {
		endpoint := "ws://127.0.0.1:" + wsPort
		waitForEndpoint(t, endpoint, 3*time.Second)
		testAttachWelcome(t, prlx, endpoint, httpAPIs)
	})
	prlx.ExpectExit()
}

func testAttachWelcome(t *testing.T, prlx *testprlx, endpoint, apis string) {
	// Attach to a running prlx note and terminate immediately
	attach := runPrlx(t, "attach", endpoint)
	defer attach.ExpectExit()
	attach.CloseStdin()

	// Gather all the infos the welcome message needs to contain
	attach.SetTemplateFunc("goos", func() string { return runtime.GOOS })
	attach.SetTemplateFunc("goarch", func() string { return runtime.GOARCH })
	attach.SetTemplateFunc("gover", runtime.Version)
	attach.SetTemplateFunc("prlxver", func() string { return params.VersionWithCommit("", "") })
	attach.SetTemplateFunc("coinbase", func() string { return prlx.Coinbase })
	attach.SetTemplateFunc("niltime", func() string {
		return time.Unix(1759695695, 0).Format("Mon Jan 02 2006 15:04:05 GMT-0700 (MST)")
	})
	attach.SetTemplateFunc("ipc", func() bool { return strings.HasPrefix(endpoint, "ipc") })
	attach.SetTemplateFunc("datadir", func() string { return prlx.Datadir })
	attach.SetTemplateFunc("apis", func() string { return apis })

	// Verify the actual welcome message to the required template
	attach.Expect(`
Welcome to the Parallax JavaScript console!

instance: Parallax/v{{prlxver}}/{{goos}}-{{goarch}}/{{gover}}
coinbase: {{coinbase}}
at block: 0 ({{niltime}}){{if ipc}}
 datadir: {{datadir}}{{end}}
 modules: {{apis}}

To exit, press ctrl-d or type exit
> {{.InputLine "exit" }}
`)
	attach.ExpectExit()
}

// trulyRandInt generates a crypto random integer used by the console tests to
// not clash network ports with other tests running cocurrently.
func trulyRandInt(lo, hi int) int {
	num, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	return int(num.Int64()) + lo
}
