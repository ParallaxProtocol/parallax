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

// parallaxd is the official command-line client for Parallax.
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/cmd/utils"
	"github.com/ParallaxProtocol/parallax/v2/internal/api"
	"github.com/ParallaxProtocol/parallax/v2/internal/debug"
	"github.com/ParallaxProtocol/parallax/v2/internal/flags"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/node"
	"github.com/ParallaxProtocol/parallax/v2/node/console/prompt"
	protocol "github.com/ParallaxProtocol/parallax/v2/node/fullnode"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/downloader"
	client "github.com/ParallaxProtocol/parallax/v2/rpc/client"
	"github.com/ParallaxProtocol/parallax/v2/support/metrics"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet"
	"github.com/ParallaxProtocol/parallax/v2/wallet/keystore"

	// Force-load the tracer engines to trigger registration
	_ "github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers/js"
	_ "github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers/native"

	"gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "Parallax" // Client identifier to advertise over the network
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	gitDate   = ""
	// The app that holds all commands and flags.
	app = flags.NewApp(gitCommit, gitDate, "the Parallax command line interface")
	// flags that configure the node
	nodeFlags = utils.GroupFlags([]cli.Flag{
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.MinFreeDiskSpaceFlag,
		utils.KeyStoreDirFlag,
		utils.ExternalSignerFlag,
		utils.USBFlag,
		utils.SmartCardDaemonPathFlag,
		utils.XHashCacheDirFlag,
		utils.XHashCachesInMemoryFlag,
		utils.XHashCachesOnDiskFlag,
		utils.XHashCachesLockMmapFlag,
		utils.XHashDatasetDirFlag,
		utils.XHashDatasetsInMemoryFlag,
		utils.XHashDatasetsOnDiskFlag,
		utils.XHashDatasetsLockMmapFlag,
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
		utils.SyncModeFlag,
		utils.ExitWhenSyncedFlag,
		utils.GCModeFlag,
		utils.SnapshotFlag,
		utils.TxLookupLimitFlag,
		utils.LightKDFFlag,
		utils.PrlRequiredBlocksFlag,
		utils.BloomFilterSizeFlag,
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
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.MiningEnabledFlag,
		utils.MinerThreadsFlag,
		utils.MinerNotifyFlag,
		utils.MinerGasLimitFlag,
		utils.MinerGasPriceFlag,
		utils.MinerCoinbaseFlag,
		utils.MinerExtraDataFlag,
		utils.MinerRecommitIntervalFlag,
		utils.MinerNoVerifyFlag,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DNSDiscoveryFlag,
		utils.DNSSeedFlag,
		utils.LegacyDiscoveryFlag,
		utils.ProxyFlag,
		utils.OnionFlag,
		utils.OnlyNetFlag,
		utils.ProxyRandomizeFlag,
		utils.ListenOnionFlag,
		utils.TorControlFlag,
		utils.TorPasswordFlag,
		utils.DeveloperFlag,
		utils.DeveloperPeriodFlag,
		utils.DeveloperGasLimitFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.PrlStatsURLFlag,
		utils.FakePoWFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.GpoMaxGasPriceFlag,
		utils.GpoIgnoreGasPriceFlag,
		utils.GpoEnableSmartFeeFlag,
		utils.MinerNotifyFullFlag,
		configFileFlag,
		DaemonFlag,
		PIDFileFlag,
	}, utils.NetworkFlags, utils.DatabasePathFlags)

	rpcFlags = []cli.Flag{
		utils.HTTPEnabledFlag,
		utils.HTTPListenAddrFlag,
		utils.HTTPPortFlag,
		utils.HTTPCORSDomainFlag,
		utils.AuthListenFlag,
		utils.AuthPortFlag,
		utils.AuthVirtualHostsFlag,
		utils.JWTSecretFlag,
		utils.HTTPVirtualHostsFlag,
		utils.GraphQLEnabledFlag,
		utils.GraphQLCORSDomainFlag,
		utils.GraphQLVirtualHostsFlag,
		utils.HTTPApiFlag,
		utils.HTTPPathPrefixFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.WSPathPrefixFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
		utils.InsecureUnlockAllowedFlag,
		utils.RPCGlobalGasCapFlag,
		utils.RPCGlobalPVMTimeoutFlag,
		utils.RPCGlobalTxFeeCapFlag,
		utils.AllowUnprotectedTxs,
		utils.BatchRequestLimit,
		utils.BatchResponseMaxSize,
	}

	metricsFlags = []cli.Flag{
		utils.MetricsEnabledFlag,
		utils.MetricsEnabledExpensiveFlag,
		utils.MetricsHTTPFlag,
		utils.MetricsPortFlag,
		utils.MetricsEnableInfluxDBFlag,
		utils.MetricsInfluxDBEndpointFlag,
		utils.MetricsInfluxDBDatabaseFlag,
		utils.MetricsInfluxDBUsernameFlag,
		utils.MetricsInfluxDBPasswordFlag,
		utils.MetricsInfluxDBTagsFlag,
		utils.MetricsEnableInfluxDBV2Flag,
		utils.MetricsInfluxDBTokenFlag,
		utils.MetricsInfluxDBBucketFlag,
		utils.MetricsInfluxDBOrganizationFlag,
	}
)

func init() {
	// Initialize the CLI app and start the node
	app.Action = parallaxd
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2025-2026 The Parallax Protocol Authors"
	app.EnableBashCompletion = true
	app.Commands = []cli.Command{
		// See chaincmd.go:
		initCommand,
		importCommand,
		exportCommand,
		importPreimagesCommand,
		exportPreimagesCommand,
		removedbCommand,
		dumpCommand,
		dumpGenesisCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		makecacheCommand,
		makedagCommand,
		versionCommand,
		versionCheckCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
		// see dbcmd.go
		dbCommand,
		// See snapshot.go
		snapshotCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = utils.GroupFlags(nodeFlags,
		rpcFlags,
		consoleFlags,
		debug.Flags,
		metricsFlags)

	app.Before = func(ctx *cli.Context) error {
		return debug.Setup(ctx)
	}
	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		prompt.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// prepare manipulates memory cache allowance and setups metric system.
// This function should be called before launching devp2p stack.
func prepare(ctx *cli.Context) {
	// If we're running a known preset, log it for convenience.
	switch {
	case ctx.GlobalBool(utils.TestnetFlag.Name):
		logging.Info("Starting Parallax testnet...")

	case ctx.GlobalIsSet(utils.DeveloperFlag.Name):
		logging.Info("Starting Parallax in ephemeral dev mode...")
		logging.Warn(`You are running Parallax in --dev mode. Please note the following:

  1. This mode is only intended for fast, iterative development without assumptions on
     security or persistence.
  2. The database is created in memory unless specified otherwise. Therefore, shutting down
     your computer or losing power will wipe your entire block data and chain state for
     your dev environment.
  3. A random, pre-allocated developer account will be available and unlocked as
     eth.coinbase, which can be used for testing. The random dev account is temporary,
     stored on a ramdisk, and will be lost if your machine is restarted.
  4. Mining is enabled by default. However, the client will only seal blocks if transactions
     are pending in the mempool. The miner's minimum accepted gas price is 1.
  5. Networking is disabled; there is no listen-address, the maximum number of peers is set
     to 0, and discovery is disabled.
`)

	case !ctx.GlobalIsSet(utils.NetworkIdFlag.Name):
		logging.Info("Starting Parallax mainnet...")
	}
	// If we're a full node on mainnet without --cache specified, bump default cache allowance
	if ctx.GlobalString(utils.SyncModeFlag.Name) != "light" && !ctx.GlobalIsSet(utils.CacheFlag.Name) && !ctx.GlobalIsSet(utils.NetworkIdFlag.Name) {
		// Make sure we're not on any supported preconfigured testnet either

		if !ctx.GlobalIsSet(utils.TestnetFlag.Name) &&
			!ctx.GlobalIsSet(utils.DeveloperFlag.Name) {
			// Nope, we're really on mainnet. Bump that cache up!
			logging.Info("Bumping default cache on mainnet", "provided", ctx.GlobalInt(utils.CacheFlag.Name), "updated", 4096)
			ctx.GlobalSet(utils.CacheFlag.Name, strconv.Itoa(4096))
		}
	}

	// Start metrics export if enabled
	utils.SetupMetrics(ctx)

	// Start system runtime metrics collection
	go metrics.CollectProcessMetrics(3 * time.Second)
}

// parallaxd is the main entry point into the system if no special subcommand is ran.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func parallaxd(ctx *cli.Context) error {
	if args := ctx.Args(); len(args) > 0 {
		return fmt.Errorf("invalid command: %q", args[0])
	}

	// Daemonization: if --daemon is set and we are the original (pre-fork)
	// process, re-exec ourselves into the background. daemonize() does not
	// return on success — the parent exits with status 0.
	if ctx.GlobalBool(DaemonFlag.Name) && !isDaemonChild() {
		if err := daemonize(ctx); err != nil {
			return fmt.Errorf("daemonize: %v", err)
		}
		return nil // unreachable
	}

	prepare(ctx)
	stack, backend := makeFullNode(ctx)
	defer stack.Close()

	startNode(ctx, stack, backend, false)

	// Once the node has started and its RPC/IPC endpoints are up, write the
	// PID file so external tooling (and `parallax stop`) can locate us. Only
	// do this when running as the daemon child — foreground mode doesn't
	// own a PID file.
	if isDaemonChild() {
		cleanup, err := writeDaemonPIDFile(ctx)
		if err != nil {
			logging.Error("Failed to write PID file", "err", err)
			return err
		}
		defer cleanup()
	}

	stack.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node, backend api.Backend, isConsole bool) {
	// Start up the node itself
	utils.StartNode(ctx, stack, isConsole)

	// Unlock any account specifically requested
	unlockAccounts(ctx, stack)

	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan wallet.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	// Create a client to interact with the local node.
	rpcClient, err := stack.Attach()
	if err != nil {
		utils.Fatalf("Failed to attach to self: %v", err)
	}
	prlclient := client.NewClient(rpcClient)

	go func() {
		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				logging.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case wallet.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					logging.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case wallet.WalletOpened:
				status, _ := event.Wallet.Status()
				logging.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				var derivationPaths []wallet.DerivationPath
				if event.Wallet.URL().Scheme == "ledger" {
					derivationPaths = append(derivationPaths, wallet.LegacyLedgerBaseDerivationPath)
				}
				derivationPaths = append(derivationPaths, wallet.DefaultBaseDerivationPath)

				event.Wallet.SelfDerive(derivationPaths, prlclient)

			case wallet.WalletDropped:
				logging.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	// Spawn a standalone goroutine for status synchronization monitoring,
	// close the node when synchronization is complete if user required.
	if ctx.GlobalBool(utils.ExitWhenSyncedFlag.Name) {
		go func() {
			sub := stack.EventMux().Subscribe(downloader.DoneEvent{})
			defer sub.Unsubscribe()
			for {
				event := <-sub.Chan()
				if event == nil {
					continue
				}
				done, ok := event.Data.(downloader.DoneEvent)
				if !ok {
					continue
				}
				if timestamp := time.Unix(int64(done.Latest.Time), 0); time.Since(timestamp) < 10*time.Minute {
					logging.Info("Synchronisation completed", "latestnum", done.Latest.Number, "latesthash", done.Latest.Hash(),
						"age", util.PrettyAge(timestamp))
					stack.Close()
				}
			}
		}()
	}

	// Start auxiliary services if enabled
	if ctx.GlobalBool(utils.MiningEnabledFlag.Name) || ctx.GlobalBool(utils.DeveloperFlag.Name) {
		parallaxBackend, ok := backend.(*protocol.PrlAPIBackend)
		if !ok {
			utils.Fatalf("Parallax service not running")
		}
		// Set the gas price to the limits from the CLI and start mining
		gasprice := utils.GlobalBig(ctx, utils.MinerGasPriceFlag.Name)
		parallaxBackend.TxPool().SetGasPrice(gasprice)
		// start mining
		threads := ctx.GlobalInt(utils.MinerThreadsFlag.Name)
		if err := parallaxBackend.StartMining(threads); err != nil {
			utils.Fatalf("Failed to start mining: %v", err)
		}
	}
}

// unlockAccounts unlocks any account specifically requested.
func unlockAccounts(ctx *cli.Context, stack *node.Node) {
	var unlocks []string
	inputs := strings.Split(ctx.GlobalString(utils.UnlockedAccountFlag.Name), ",")
	for _, input := range inputs {
		if trimmed := strings.TrimSpace(input); trimmed != "" {
			unlocks = append(unlocks, trimmed)
		}
	}
	// Short circuit if there is no account to unlock.
	if len(unlocks) == 0 {
		return
	}
	// If insecure account unlocking is not allowed if node's APIs are exposed to external.
	// Print warning log to user and skip unlocking.
	if !stack.Config().InsecureUnlockAllowed && stack.Config().ExtRPCEnabled() {
		utils.Fatalf("Account unlock with HTTP access is forbidden!")
	}
	backends := stack.AccountManager().Backends(keystore.KeyStoreType)
	if len(backends) == 0 {
		logging.Warn("Failed to unlock accounts, keystore is not available")
		return
	}
	ks := backends[0].(*keystore.KeyStore)
	passwords := utils.MakePasswordList(ctx)
	for i, account := range unlocks {
		unlockAccount(ks, account, i, passwords)
	}
}
