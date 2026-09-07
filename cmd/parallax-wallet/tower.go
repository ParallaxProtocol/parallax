// Copyright 2026 The Parallax Protocol Authors
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
	"context"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/cmd/utils"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/proofstore"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/towerd"
	"gopkg.in/urfave/cli.v1"
)

var commandTower = cli.Command{
	Name:      "tower",
	Usage:     "run a watchtower (challenge stale closes for delegators)",
	ArgsUsage: "<keyfile>",
	Description: `
Runs the channel node in tower mode (Part 3 §10): accepts delegated states
over Nostr (kind 21906) from the npubs in [tower].delegators, watches every
CloseStarted on the configured registry, and challenges any close that is
stale against a held delegation. The keyfile's account pays challenge gas
and receives the on-chain refund. The tower can be lazy, never a thief:
delegated material only fits the anyone-can-call challenge.`,
	Flags:  []cli.Flag{passphraseFlag, channelConfigFlag, channelDataDirFlag},
	Action: towerDaemon,
	Subcommands: []cli.Command{
		{
			Name:  "quarantine",
			Usage: "inspect delegation records the tower could not decode",
			Description: `
A delegation record that no longer decodes is moved out of the live set so
it neither blocks the delegator's next delegation nor fails every read
that touches it. The tower alarms when it quarantines one and keeps the
affected close pinned for re-evaluation until its challenge deadline. The
raw bytes stay here for inspection until cleared.`,
			Subcommands: []cli.Command{
				{
					Name:      "list",
					Usage:     "list quarantined delegation records",
					ArgsUsage: "<keyfile>",
					Flags:     []cli.Flag{passphraseFlag, channelConfigFlag, channelDataDirFlag, jsonFlag},
					Action:    towerQuarantineList,
				},
				{
					Name:      "clear",
					Usage:     "discard a quarantined delegation record",
					ArgsUsage: "<keyfile> <chain-id>:<registry>:<channel-id>",
					Flags:     []cli.Flag{passphraseFlag, channelConfigFlag, channelDataDirFlag},
					Action:    towerQuarantineClear,
				},
			},
		},
	},
}

func towerQuarantineList(ctx *cli.Context) error {
	node, cleanup, err := newChannelNode(ctx, false)
	if err != nil {
		return err
	}
	defer cleanup()
	rows, err := node.Store.QuarantinedDelegations()
	if err != nil {
		return err
	}
	if ctx.Bool(jsonFlag.Name) {
		mustPrintJSON(rows)
		return nil
	}
	if len(rows) == 0 {
		fmt.Println("no quarantined delegation records")
		return nil
	}
	for _, q := range rows {
		fmt.Printf("%s  at %s  %d bytes  %s\n", q.Key, time.Unix(q.AtUnix, 0).UTC().Format(time.RFC3339), len(q.Raw), q.Error)
	}
	return nil
}

func towerQuarantineClear(ctx *cli.Context) error {
	if ctx.NArg() != 2 {
		utils.Fatalf("usage: tower quarantine clear <keyfile> <chain-id>:<registry>:<channel-id>")
	}
	key, err := proofstore.ParseChannelKey(ctx.Args().Get(1))
	if err != nil {
		return err
	}
	node, cleanup, err := newChannelNode(ctx, false)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := node.Store.ClearQuarantine(key); err != nil {
		return err
	}
	fmt.Printf("cleared quarantined delegation record for %s\n", key)
	return nil
}

func towerDaemon(ctx *cli.Context) error {
	node, cleanup, err := newChannelNode(ctx, true)
	if err != nil {
		return err
	}
	defer cleanup()

	cfg := node.Cfg
	if !cfg.Tower.Enabled {
		utils.Fatalf("set tower.enabled = true in the config to run a tower")
	}
	delegators := make(map[string]bool, len(cfg.Tower.Delegators))
	for _, npub := range cfg.Tower.Delegators {
		delegators[npub] = true
	}
	minDiscrepancy := new(big.Int)
	if s := cfg.Tower.MinDiscrepancyWei; s != "" {
		if _, ok := minDiscrepancy.SetString(s, 10); !ok {
			utils.Fatalf("bad tower.min_discrepancy_wei %q", s)
		}
	}

	// One tower instance per configured registry, sharing the node's
	// per-chain transaction manager so tower and watcher submissions on the
	// same key never race nonces.
	var towers []*towerd.Tower
	for label, entries := range cfg.Registries {
		for _, e := range entries {
			chainID := fmt.Sprintf("%d", e.ChainID)
			t, err := towerd.New(towerd.Config{
				ChainID:               chainID,
				Registry:              util.HexToAddress(e.Address),
				Confirmations:         cfg.Node.Confirmations,
				Delegators:            delegators,
				OpenRegistration:      cfg.Tower.OpenRegistration,
				MaxDelegationsPerNpub: cfg.Tower.MaxDelegationsPerNpub,
				MinDiscrepancyWei:     minDiscrepancy,
			}, node.Store, node.Backend(), node.TxManagerFor(chainID))
			if err != nil {
				return fmt.Errorf("tower for registry %s: %w", label, err)
			}
			t.Alarm = func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, "TOWER ALARM: "+format+"\n", args...)
			}
			towers = append(towers, t)
		}
	}
	if len(towers) == 1 {
		node.DelegationHandler = towers[0].HandleDelegation
	} else {
		// Route by registry when several coexist.
		node.DelegationHandler = towerd.Route(towers)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for _, t := range towers {
					if _, err := t.Tick(runCtx); err != nil {
						fmt.Fprintf(os.Stderr, "tower tick: %v\n", err)
					}
				}
			case <-runCtx.Done():
				return
			}
		}
	}()

	fmt.Printf("tower running: address %s npub %s (%d delegators%s)\n",
		node.Signer.Address().Hex(), node.SelfPub, len(delegators),
		map[bool]string{true: ", open registration", false: ""}[cfg.Tower.OpenRegistration])
	node.Run(runCtx, 30*time.Second)
	return nil
}
