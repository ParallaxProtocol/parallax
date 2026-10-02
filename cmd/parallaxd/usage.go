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

// Contains the prlx command usage template and generator.

package main

import (
	"io"
	"sort"

	"github.com/ParallaxProtocol/parallax/v2/cmd/utils"
	"github.com/ParallaxProtocol/parallax/v2/internal/debug"
	"github.com/ParallaxProtocol/parallax/v2/internal/flags"
	"gopkg.in/urfave/cli.v1"
)

// AppHelpFlagGroups is the application flags, grouped by functionality.
var AppHelpFlagGroups = []flags.FlagGroup{
	{
		Name: "PARALLAX",
		Flags: utils.GroupFlags([]cli.Flag{
			configFileFlag,
			utils.MinFreeDiskSpaceFlag,
			utils.KeyStoreDirFlag,
			utils.USBFlag,
			utils.SmartCardDaemonPathFlag,
			utils.NetworkIdFlag,
			utils.SyncModeFlag,
			utils.ExitWhenSyncedFlag,
			utils.GCModeFlag,
			utils.TxLookupLimitFlag,
			utils.PrlStatsURLFlag,
			utils.IdentityFlag,
			utils.LightKDFFlag,
			utils.PrlRequiredBlocksFlag,
		}, utils.NetworkFlags, utils.DatabasePathFlags),
	},
	{
		Name: "DEVELOPER CHAIN",
		Flags: []cli.Flag{
			utils.DeveloperFlag,
			utils.DeveloperPeriodFlag,
			utils.DeveloperGasLimitFlag,
		},
	},
	{
		Name: "XHASH",
		Flags: []cli.Flag{
			utils.XHashCacheDirFlag,
			utils.XHashCachesInMemoryFlag,
			utils.XHashCachesOnDiskFlag,
			utils.XHashCachesLockMmapFlag,
			utils.XHashDatasetDirFlag,
			utils.XHashDatasetsInMemoryFlag,
			utils.XHashDatasetsOnDiskFlag,
			utils.XHashDatasetsLockMmapFlag,
		},
	},
	{
		Name: "TRANSACTION POOL",
		Flags: []cli.Flag{
			utils.TxPoolLocalsFlag,
			utils.TxPoolNoLocalsFlag,
			utils.TxPoolJournalFlag,
			utils.TxPoolRejournalFlag,
			utils.TxPoolPriceLimitFlag,
			utils.TxPoolPriceBumpFlag,
			utils.TxPoolAccountSlotsFlag,
			utils.TxPoolGlobalSlotsFlag,
			utils.TxPoolAccountQueueFlag,
			utils.TxPoolGlobalQueueFlag,
			utils.TxPoolLifetimeFlag,
		},
	},
	{
		Name: "PERFORMANCE TUNING",
		Flags: []cli.Flag{
			utils.CacheFlag,
			utils.CacheDatabaseFlag,
			utils.CacheTrieFlag,
			utils.CacheTrieJournalFlag,
			utils.CacheTrieRejournalFlag,
			utils.CacheGCFlag,
			utils.CacheSnapshotFlag,
			utils.CacheNoPrefetchFlag,
			utils.CachePreimagesFlag,
			utils.FDLimitFlag,
		},
	},
	{
		Name: "ACCOUNT",
		Flags: []cli.Flag{
			utils.UnlockedAccountFlag,
			utils.PasswordFileFlag,
			utils.ExternalSignerFlag,
			utils.InsecureUnlockAllowedFlag,
		},
	},
	{
		Name: "API AND CONSOLE",
		Flags: []cli.Flag{
			utils.IPCDisabledFlag,
			utils.IPCPathFlag,
			utils.HTTPEnabledFlag,
			utils.HTTPListenAddrFlag,
			utils.HTTPPortFlag,
			utils.HTTPApiFlag,
			utils.HTTPPathPrefixFlag,
			utils.HTTPCORSDomainFlag,
			utils.HTTPVirtualHostsFlag,
			utils.WSEnabledFlag,
			utils.WSListenAddrFlag,
			utils.WSPortFlag,
			utils.WSApiFlag,
			utils.WSPathPrefixFlag,
			utils.WSAllowedOriginsFlag,
			utils.JWTSecretFlag,
			utils.AuthListenFlag,
			utils.AuthPortFlag,
			utils.AuthVirtualHostsFlag,
			utils.GraphQLEnabledFlag,
			utils.GraphQLCORSDomainFlag,
			utils.GraphQLVirtualHostsFlag,
			utils.RPCGlobalGasCapFlag,
			utils.RPCGlobalPVMTimeoutFlag,
			utils.RPCGlobalTxFeeCapFlag,
			utils.RPCGlobalLogQueryLimit,
			utils.RPCGlobalRangeLimitFlag,
			utils.AllowUnprotectedTxs,
			utils.BatchRequestLimit,
			utils.BatchResponseMaxSize,
			utils.HTTPBodyLimitFlag,
			utils.JSpathFlag,
			utils.ExecFlag,
			utils.PreloadJSFlag,
		},
	},
	{
		Name: "NETWORKING",
		Flags: []cli.Flag{
			utils.BootnodesFlag,
			utils.DNSDiscoveryFlag,
			utils.DNSSeedFlag,
			utils.ListenPortFlag,
			utils.MaxPeersFlag,
			utils.MaxPendingPeersFlag,
			utils.NATFlag,
			utils.NoDiscoverFlag,
			utils.NetrestrictFlag,
			utils.NodeKeyFileFlag,
			utils.NodeKeyHexFlag,
			utils.LegacyDiscoveryFlag,
			utils.ProxyFlag,
			utils.OnionFlag,
			utils.OnlyNetFlag,
			utils.ProxyRandomizeFlag,
			utils.ListenOnionFlag,
			utils.TorControlFlag,
			utils.TorPasswordFlag,
		},
	},
	{
		Name: "MINER",
		Flags: []cli.Flag{
			utils.MiningEnabledFlag,
			utils.MinerThreadsFlag,
			utils.MinerNotifyFlag,
			utils.MinerNotifyFullFlag,
			utils.MinerGasPriceFlag,
			utils.MinerGasLimitFlag,
			utils.MinerCoinbaseFlag,
			utils.MinerExtraDataFlag,
			utils.MinerRecommitIntervalFlag,
			utils.MinerNoVerifyFlag,
		},
	},
	{
		Name: "GAS PRICE ORACLE",
		Flags: []cli.Flag{
			utils.GpoBlocksFlag,
			utils.GpoPercentileFlag,
			utils.GpoMaxGasPriceFlag,
			utils.GpoIgnoreGasPriceFlag,
			utils.GpoEnableSmartFeeFlag,
		},
	},
	{
		Name: "VIRTUAL MACHINE",
		Flags: []cli.Flag{
			utils.VMEnableDebugFlag,
		},
	},
	{
		Name: "LOGGING AND DEBUGGING",
		Flags: append([]cli.Flag{
			utils.FakePoWFlag,
			utils.NoCompactionFlag,
		}, debug.Flags...),
	},
	{
		Name:  "METRICS AND STATS",
		Flags: metricsFlags,
	},
	{
		Name:  "DAEMON",
		Flags: daemonFlags,
	},
	{
		Name: "MISC",
		Flags: []cli.Flag{
			utils.SnapshotFlag,
			utils.BloomFilterSizeFlag,
			cli.HelpFlag,
		},
	},
}

func init() {
	// Override the default app help template
	cli.AppHelpTemplate = flags.AppHelpTemplate

	// Override the default app help printer, but only for the global app help
	originalHelpPrinter := cli.HelpPrinter
	cli.HelpPrinter = func(w io.Writer, tmpl string, data any) {
		if tmpl == flags.AppHelpTemplate {
			// Iterate over all the flags and add any uncategorized ones
			categorized := make(map[string]struct{})
			for _, group := range AppHelpFlagGroups {
				for _, flag := range group.Flags {
					categorized[flag.String()] = struct{}{}
				}
			}
			var uncategorized []cli.Flag
			for _, flag := range data.(*cli.App).Flags {
				if _, ok := categorized[flag.String()]; !ok {
					uncategorized = append(uncategorized, flag)
				}
			}
			if len(uncategorized) > 0 {
				// Append all ungategorized options to the misc group
				miscs := len(AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags)
				AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags = append(AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags, uncategorized...)

				// Make sure they are removed afterwards
				defer func() {
					AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags = AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags[:miscs]
				}()
			}
			// Render out custom usage screen
			originalHelpPrinter(w, tmpl, flags.HelpData{
				App:           data,
				FlagGroups:    AppHelpFlagGroups,
				CommandGroups: groupCommands(data.(*cli.App).Commands),
			})
		} else if tmpl == flags.CommandHelpTemplate {
			// Iterate over all command specific flags and categorize them
			categorized := make(map[string][]cli.Flag)
			for _, flag := range data.(cli.Command).Flags {
				if _, ok := categorized[flag.String()]; !ok {
					categorized[flags.FlagCategory(flag, AppHelpFlagGroups)] = append(categorized[flags.FlagCategory(flag, AppHelpFlagGroups)], flag)
				}
			}

			// sort to get a stable ordering
			sorted := make([]flags.FlagGroup, 0, len(categorized))
			for cat, flgs := range categorized {
				sorted = append(sorted, flags.FlagGroup{Name: cat, Flags: flgs})
			}
			sort.Sort(flags.ByCategory(sorted))

			// add sorted array to data and render with default printer
			originalHelpPrinter(w, tmpl, map[string]any{
				"cmd":              data,
				"categorizedFlags": sorted,
			})
		} else {
			originalHelpPrinter(w, tmpl, data)
		}
	}
}

// commandCategoryOrder is the display order of command category headings
// in the app help output. Categories not listed here are appended at the
// end in alphabetical order; commands with no Category land in a trailing
// "COMMANDS" bucket so `help` itself stays visible.
var commandCategoryOrder = []string{
	"BLOCKCHAIN COMMANDS",
	"ACCOUNT COMMANDS",
	"DATABASE COMMANDS",
	"CLIENT COMMANDS",
	"CONSOLE COMMANDS",
	"MISCELLANEOUS COMMANDS",
}

// groupCommands buckets the app's commands by their Category field and
// returns them in the display order defined by commandCategoryOrder.
// Within each bucket commands are sorted alphabetically by name to match
// the default flat help output users are already familiar with.
func groupCommands(cmds []cli.Command) []flags.CommandGroup {
	buckets := make(map[string][]cli.Command)
	for _, c := range cmds {
		cat := c.Category
		if cat == "" {
			cat = "COMMANDS"
		}
		buckets[cat] = append(buckets[cat], c)
	}
	for cat := range buckets {
		sort.Slice(buckets[cat], func(i, j int) bool {
			return buckets[cat][i].Name < buckets[cat][j].Name
		})
	}

	groups := make([]flags.CommandGroup, 0, len(buckets))
	seen := make(map[string]bool)
	for _, cat := range commandCategoryOrder {
		if cmds := buckets[cat]; len(cmds) > 0 {
			groups = append(groups, flags.CommandGroup{Name: cat, Commands: cmds})
			seen[cat] = true
		}
	}
	// Append any remaining categories (e.g. future additions, or the
	// fallback "COMMANDS" bucket for uncategorised entries like `help`).
	var extras []string
	for cat := range buckets {
		if !seen[cat] {
			extras = append(extras, cat)
		}
	}
	sort.Strings(extras)
	for _, cat := range extras {
		groups = append(groups, flags.CommandGroup{Name: cat, Commands: buckets[cat]})
	}
	return groups
}
