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

// parallax-wallet is the offline wallet management tool for the Parallax
// client suite. It consolidates the previous parallaxkey (single-keyfile
// operations) and "parallax account" (keystore-directory operations) into
// a single binary modeled after Bitcoin Core's bitcoin-wallet. It never
// talks to a running node; RPC-backed wallet commands live in
// parallax-cli.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/ParallaxProtocol/parallax/v2/internal/flags"
	"gopkg.in/urfave/cli.v1"
)

const defaultKeyfileName = "keyfile.json"

// Git SHA1 commit hash of the release (set via linker flags).
var (
	gitCommit = ""
	gitDate   = ""
)

var app *cli.App

// Flags shared across multiple subcommands.
var (
	passphraseFlag = cli.StringFlag{
		Name:  "passwordfile",
		Usage: "file containing the password for the keyfile",
	}
	newPassphraseFlag = cli.StringFlag{
		Name:  "newpasswordfile",
		Usage: "file containing the new password for the keyfile",
	}
	jsonFlag = cli.BoolFlag{
		Name:  "json",
		Usage: "output JSON instead of human-readable format",
	}
	lightKDFFlag = cli.BoolFlag{
		Name:  "lightkdf",
		Usage: "use less secure scrypt parameters",
	}
	privateKeyFlag = cli.StringFlag{
		Name:  "privatekey",
		Usage: "file containing a raw private key to encrypt",
	}
	privateFlag = cli.BoolFlag{
		Name:  "private",
		Usage: "include the private key in the output",
	}
	msgfileFlag = cli.StringFlag{
		Name:  "msgfile",
		Usage: "file containing the message to sign/verify",
	}
	dataDirFlag = cli.StringFlag{
		Name:  "datadir",
		Usage: "root data directory (default: $HOME/.parallax)",
	}
	keyStoreDirFlag = cli.StringFlag{
		Name:  "keystore",
		Usage: "keystore directory (default: <datadir>/keystore)",
	}
)

func init() {
	app = flags.NewApp(gitCommit, gitDate, "the Parallax offline wallet tool")
	app.Commands = []cli.Command{
		// Keystore-directory operations (formerly `parallax account …`).
		commandList,
		commandNew,
		commandUpdate,
		commandImport,
		commandInfo,
		commandDump,
		commandCreateFromDump,

		// Single-keyfile operations (formerly `parallaxkey …`).
		commandGenerate,
		commandInspect,
		commandChangePassphrase,
		commandSignMessage,
		commandVerifyMessage,
		commandSignTx,
		commandSignRequest,
	}
	sort.Sort(cli.CommandsByName(app.Commands))
	cli.CommandHelpTemplate = flags.OriginCommandHelpTemplate
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
