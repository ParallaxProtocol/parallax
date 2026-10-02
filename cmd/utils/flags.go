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

// Package utils contains internal helper functions for parallax commands.
package utils

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	godebug "runtime/debug"
	"strconv"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/crypto"
	"github.com/ParallaxProtocol/parallax/v2/dbstore"
	"github.com/ParallaxProtocol/parallax/v2/dbstore/remotedb"
	"github.com/ParallaxProtocol/parallax/v2/internal/api"
	"github.com/ParallaxProtocol/parallax/v2/internal/flags"
	"github.com/ParallaxProtocol/parallax/v2/kernel"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/kernel/xhash"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/node"
	protocol "github.com/ParallaxProtocol/parallax/v2/node/fullnode"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/downloader"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/tracers"
	"github.com/ParallaxProtocol/parallax/v2/node/miner"
	"github.com/ParallaxProtocol/parallax/v2/node/nodeconfig"
	"github.com/ParallaxProtocol/parallax/v2/node/stats"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/addrman"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/nat"
	"github.com/ParallaxProtocol/parallax/v2/p2p/netparams"
	"github.com/ParallaxProtocol/parallax/v2/p2p/netutil"
	"github.com/ParallaxProtocol/parallax/v2/policy/fees"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/rpc/graphql"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/support/metrics"
	"github.com/ParallaxProtocol/parallax/v2/support/metrics/exp"
	"github.com/ParallaxProtocol/parallax/v2/support/metrics/influxdb"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/fdlimit"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"
	"github.com/ParallaxProtocol/parallax/v2/wallet"
	"github.com/ParallaxProtocol/parallax/v2/wallet/keystore"
	pcsclite "github.com/gballet/go-libpcsclite"
	gopsutil "github.com/shirou/gopsutil/mem"
	"gopkg.in/urfave/cli.v1"
)

func init() {
	cli.AppHelpTemplate = `{{.Name}} {{if .Flags}}[global options] {{end}}command{{if .Flags}} [command options]{{end}} [arguments...]

VERSION:
   {{.Version}}

COMMANDS:
   {{range .Commands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
   {{end}}{{if .Flags}}
GLOBAL OPTIONS:
   {{range .Flags}}{{.}}
   {{end}}{{end}}
`
	cli.CommandHelpTemplate = flags.CommandHelpTemplate
	cli.HelpPrinter = printHelp
}

func printHelp(out io.Writer, templ string, data any) {
	funcMap := template.FuncMap{"join": strings.Join}
	t := template.Must(template.New("help").Funcs(funcMap).Parse(templ))
	w := tabwriter.NewWriter(out, 38, 8, 2, ' ', 0)
	err := t.Execute(w, data)
	if err != nil {
		panic(err)
	}
	w.Flush()
}

// These are all the command line flags we support.
// If you add to this list, please remember to include the
// flag in the appropriate command definition.
//
// The flags are defined here so their names and help texts
// are the same for all commands.

var (
	// General settings
	DataDirFlag = DirectoryFlag{
		Name:  "datadir",
		Usage: "Data directory for the databases and keystore",
		Value: DirectoryString(node.DefaultDataDir()),
	}
	RemoteDBFlag = cli.StringFlag{
		Name:  "remotedb",
		Usage: "URL for remote database",
	}
	AncientFlag = DirectoryFlag{
		Name:  "datadir.ancient",
		Usage: "Data directory for ancient chain segments (default = inside chaindata)",
	}
	MinFreeDiskSpaceFlag = DirectoryFlag{
		Name:  "datadir.minfreedisk",
		Usage: "Minimum free disk space in MB, once reached triggers auto shut down (default = --cache.gc converted to MB, 0 = disabled)",
	}
	KeyStoreDirFlag = DirectoryFlag{
		Name:  "keystore",
		Usage: "Directory for the keystore (default = inside the datadir)",
	}
	USBFlag = cli.BoolFlag{
		Name:  "usb",
		Usage: "Enable monitoring and management of USB hardware wallets",
	}
	SmartCardDaemonPathFlag = cli.StringFlag{
		Name:  "pcscdpath",
		Usage: "Path to the smartcard daemon (pcscd) socket file",
		Value: pcsclite.PCSCDSockName,
	}
	NetworkIdFlag = cli.Uint64Flag{
		Name:  "networkid",
		Usage: "Explicitly set network id (integer)(For testnet: use --testnet instead)",
		Value: nodeconfig.Defaults.NetworkId,
	}
	MainnetFlag = cli.BoolFlag{
		Name:  "mainnet",
		Usage: "Parallax mainnet",
	}
	TestnetFlag = cli.BoolFlag{
		Name:  "testnet",
		Usage: "Testnet: pre-configured proof-of-work test network",
	}
	DeveloperFlag = cli.BoolFlag{
		Name:  "dev",
		Usage: "Ephemeral proof-of-authority network with a pre-funded developer account, mining enabled",
	}
	DeveloperPeriodFlag = cli.IntFlag{
		Name:  "dev.period",
		Usage: "Block period to use in developer mode (0 = mine only if transaction pending)",
	}
	DeveloperGasLimitFlag = cli.Uint64Flag{
		Name:  "dev.gaslimit",
		Usage: "Initial block gas limit",
		Value: 11500000,
	}
	IdentityFlag = cli.StringFlag{
		Name:  "identity",
		Usage: "Custom node name",
	}
	DocRootFlag = DirectoryFlag{
		Name:  "docroot",
		Usage: "Document Root for HTTPClient file scheme",
		Value: DirectoryString(HomeDir()),
	}
	ExitWhenSyncedFlag = cli.BoolFlag{
		Name:  "exitwhensynced",
		Usage: "Exits after block synchronisation completes",
	}
	IterativeOutputFlag = cli.BoolTFlag{
		Name:  "iterative",
		Usage: "Print streaming JSON iteratively, delimited by newlines",
	}
	ExcludeStorageFlag = cli.BoolFlag{
		Name:  "nostorage",
		Usage: "Exclude storage entries (save db lookups)",
	}
	IncludeIncompletesFlag = cli.BoolFlag{
		Name:  "incompletes",
		Usage: "Include accounts for which we don't have the address (missing preimage)",
	}
	ExcludeCodeFlag = cli.BoolFlag{
		Name:  "nocode",
		Usage: "Exclude contract code (save db lookups)",
	}
	StartKeyFlag = cli.StringFlag{
		Name:  "start",
		Usage: "Start position. Either a hash or address",
		Value: "0x0000000000000000000000000000000000000000000000000000000000000000",
	}
	DumpLimitFlag = cli.Uint64Flag{
		Name:  "limit",
		Usage: "Max number of elements (0 = no limit)",
		Value: 0,
	}
	defaultSyncMode = nodeconfig.Defaults.SyncMode
	SyncModeFlag    = TextMarshalerFlag{
		Name:  "syncmode",
		Usage: `Blockchain sync mode ("snap" or "full")`,
		Value: &defaultSyncMode,
	}
	GCModeFlag = cli.StringFlag{
		Name:  "gcmode",
		Usage: `Blockchain garbage collection mode ("full", "archive")`,
		Value: "full",
	}
	SnapshotFlag = cli.BoolTFlag{
		Name:  "snapshot",
		Usage: `Enables snapshot-database mode (default = enable)`,
	}
	TxLookupLimitFlag = cli.Uint64Flag{
		Name:  "txlookuplimit",
		Usage: "Number of recent blocks to maintain transactions index for (default = about one year, 0 = entire chain)",
		Value: nodeconfig.Defaults.TxLookupLimit,
	}
	LightKDFFlag = cli.BoolFlag{
		Name:  "lightkdf",
		Usage: "Reduce key-derivation RAM & CPU usage at some expense of KDF strength",
	}
	PrlRequiredBlocksFlag = cli.StringFlag{
		Name:  "prl.requiredblocks",
		Usage: "Comma separated block number-to-hash mappings to require for peering (<number>=<hash>)",
	}
	BloomFilterSizeFlag = cli.Uint64Flag{
		Name:  "bloomfilter.size",
		Usage: "Megabytes of memory allocated to bloom-filter for pruning",
		Value: 2048,
	}
	// Light server and client settings
	// XHash settings
	XHashCacheDirFlag = DirectoryFlag{
		Name:  "xhash.cachedir",
		Usage: "Directory to store the XHash verification caches (default = inside the datadir)",
	}
	XHashCachesInMemoryFlag = cli.IntFlag{
		Name:  "xhash.cachesinmem",
		Usage: "Number of recent XHash caches to keep in memory (16MB each)",
		Value: nodeconfig.Defaults.XHash.CachesInMem,
	}
	XHashCachesOnDiskFlag = cli.IntFlag{
		Name:  "xhash.cachesondisk",
		Usage: "Number of recent xhash caches to keep on disk (16MB each)",
		Value: nodeconfig.Defaults.XHash.CachesOnDisk,
	}
	XHashCachesLockMmapFlag = cli.BoolFlag{
		Name:  "xhash.cacheslockmmap",
		Usage: "Lock memory maps of recent XHash caches",
	}
	XHashDatasetDirFlag = DirectoryFlag{
		Name:  "xhash.dagdir",
		Usage: "Directory to store the XHash mining DAGs",
		Value: DirectoryString(nodeconfig.Defaults.XHash.DatasetDir),
	}
	XHashDatasetsInMemoryFlag = cli.IntFlag{
		Name:  "xhash.dagsinmem",
		Usage: "Number of recent XHash mining DAGs to keep in memory (1+GB each)",
		Value: nodeconfig.Defaults.XHash.DatasetsInMem,
	}
	XHashDatasetsOnDiskFlag = cli.IntFlag{
		Name:  "xhash.dagsondisk",
		Usage: "Number of recent XHash mining DAGs to keep on disk (1+GB each)",
		Value: nodeconfig.Defaults.XHash.DatasetsOnDisk,
	}
	XHashDatasetsLockMmapFlag = cli.BoolFlag{
		Name:  "xhash.dagslockmmap",
		Usage: "Lock memory maps for recent XHash mining DAGs",
	}
	// Transaction pool settings
	TxPoolLocalsFlag = cli.StringFlag{
		Name:  "txpool.locals",
		Usage: "Comma separated accounts to treat as locals (no flush, priority inclusion)",
	}
	TxPoolNoLocalsFlag = cli.BoolFlag{
		Name:  "txpool.nolocals",
		Usage: "Disables price exemptions for locally submitted transactions",
	}
	TxPoolJournalFlag = cli.StringFlag{
		Name:  "txpool.journal",
		Usage: "Disk journal for local transaction to survive node restarts",
		Value: validation.DefaultTxPoolConfig.Journal,
	}
	TxPoolRejournalFlag = cli.DurationFlag{
		Name:  "txpool.rejournal",
		Usage: "Time interval to regenerate the local transaction journal",
		Value: validation.DefaultTxPoolConfig.Rejournal,
	}
	TxPoolPriceLimitFlag = cli.Uint64Flag{
		Name:  "txpool.pricelimit",
		Usage: "Minimum gas price limit to enforce for acceptance into the pool",
		Value: nodeconfig.Defaults.TxPool.PriceLimit,
	}
	TxPoolPriceBumpFlag = cli.Uint64Flag{
		Name:  "txpool.pricebump",
		Usage: "Price bump percentage to replace an already existing transaction",
		Value: nodeconfig.Defaults.TxPool.PriceBump,
	}
	TxPoolAccountSlotsFlag = cli.Uint64Flag{
		Name:  "txpool.accountslots",
		Usage: "Minimum number of executable transaction slots guaranteed per account",
		Value: nodeconfig.Defaults.TxPool.AccountSlots,
	}
	TxPoolGlobalSlotsFlag = cli.Uint64Flag{
		Name:  "txpool.globalslots",
		Usage: "Maximum number of executable transaction slots for all accounts",
		Value: nodeconfig.Defaults.TxPool.GlobalSlots,
	}
	TxPoolAccountQueueFlag = cli.Uint64Flag{
		Name:  "txpool.accountqueue",
		Usage: "Maximum number of non-executable transaction slots permitted per account",
		Value: nodeconfig.Defaults.TxPool.AccountQueue,
	}
	TxPoolGlobalQueueFlag = cli.Uint64Flag{
		Name:  "txpool.globalqueue",
		Usage: "Maximum number of non-executable transaction slots for all accounts",
		Value: nodeconfig.Defaults.TxPool.GlobalQueue,
	}
	TxPoolLifetimeFlag = cli.DurationFlag{
		Name:  "txpool.lifetime",
		Usage: "Maximum amount of time non-executable transaction are queued",
		Value: nodeconfig.Defaults.TxPool.Lifetime,
	}
	// Performance tuning settings
	CacheFlag = cli.IntFlag{
		Name:  "cache",
		Usage: "Megabytes of memory allocated to internal caching (default = 4096 mainnet full node, 128 light mode)",
		Value: 1024,
	}
	CacheDatabaseFlag = cli.IntFlag{
		Name:  "cache.database",
		Usage: "Percentage of cache memory allowance to use for database io",
		Value: 50,
	}
	CacheTrieFlag = cli.IntFlag{
		Name:  "cache.trie",
		Usage: "Percentage of cache memory allowance to use for trie caching (default = 15% full mode, 30% archive mode)",
		Value: 15,
	}
	CacheTrieJournalFlag = cli.StringFlag{
		Name:  "cache.trie.journal",
		Usage: "Disk journal directory for trie cache to survive node restarts",
		Value: nodeconfig.Defaults.TrieCleanCacheJournal,
	}
	CacheTrieRejournalFlag = cli.DurationFlag{
		Name:  "cache.trie.rejournal",
		Usage: "Time interval to regenerate the trie cache journal",
		Value: nodeconfig.Defaults.TrieCleanCacheRejournal,
	}
	CacheGCFlag = cli.IntFlag{
		Name:  "cache.gc",
		Usage: "Percentage of cache memory allowance to use for trie pruning (default = 25% full mode, 0% archive mode)",
		Value: 25,
	}
	CacheSnapshotFlag = cli.IntFlag{
		Name:  "cache.snapshot",
		Usage: "Percentage of cache memory allowance to use for snapshot caching (default = 10% full mode, 20% archive mode)",
		Value: 10,
	}
	CacheNoPrefetchFlag = cli.BoolFlag{
		Name:  "cache.noprefetch",
		Usage: "Disable heuristic state prefetch during block import (less CPU and disk IO, more time waiting for data)",
	}
	CachePreimagesFlag = cli.BoolFlag{
		Name:  "cache.preimages",
		Usage: "Enable recording the SHA3/keccak preimages of trie keys",
	}
	FDLimitFlag = cli.IntFlag{
		Name:  "fdlimit",
		Usage: "Raise the open file descriptor resource limit (default = system fd limit)",
	}
	// Miner settings
	MiningEnabledFlag = cli.BoolFlag{
		Name:  "mine",
		Usage: "Enable mining",
	}
	MinerThreadsFlag = cli.IntFlag{
		Name:  "miner.threads",
		Usage: "Number of CPU threads to use for mining",
		Value: 0,
	}
	MinerNotifyFlag = cli.StringFlag{
		Name:  "miner.notify",
		Usage: "Comma separated HTTP URL list to notify of new work packages",
	}
	MinerNotifyFullFlag = cli.BoolFlag{
		Name:  "miner.notify.full",
		Usage: "Notify with pending block headers instead of work packages",
	}
	MinerGasLimitFlag = cli.Uint64Flag{
		Name:  "miner.gaslimit",
		Usage: "Target gas ceiling for mined blocks",
		Value: nodeconfig.Defaults.Miner.GasCeil,
	}
	MinerGasPriceFlag = BigFlag{
		Name:  "miner.gasprice",
		Usage: "Minimum gas price for mining a transaction",
		Value: nodeconfig.Defaults.Miner.GasPrice,
	}
	MinerCoinbaseFlag = cli.StringFlag{
		Name:  "miner.coinbase",
		Usage: "Public address for block mining rewards (default = first account)",
		Value: "0",
	}
	MinerExtraDataFlag = cli.StringFlag{
		Name:  "miner.extradata",
		Usage: "Block extra data set by the miner (default = client version)",
	}
	MinerRecommitIntervalFlag = cli.DurationFlag{
		Name:  "miner.recommit",
		Usage: "Time interval to recreate the block being mined",
		Value: nodeconfig.Defaults.Miner.Recommit,
	}
	MinerNoVerifyFlag = cli.BoolFlag{
		Name:  "miner.noverify",
		Usage: "Disable remote sealing verification",
	}
	// Account settings
	UnlockedAccountFlag = cli.StringFlag{
		Name:  "unlock",
		Usage: "Comma separated list of accounts to unlock",
		Value: "",
	}
	PasswordFileFlag = cli.StringFlag{
		Name:  "password",
		Usage: "Password file to use for non-interactive password input",
		Value: "",
	}
	ExternalSignerFlag = cli.StringFlag{
		Name:  "signer",
		Usage: "External signer (url or path to ipc file)",
		Value: "",
	}
	VMEnableDebugFlag = cli.BoolFlag{
		Name:  "vmdebug",
		Usage: "Record information useful for VM and contract debugging",
	}
	InsecureUnlockAllowedFlag = cli.BoolFlag{
		Name:  "allow-insecure-unlock",
		Usage: "Allow insecure account unlocking when account-related RPCs are exposed by http",
	}
	RPCGlobalGasCapFlag = cli.Uint64Flag{
		Name:  "rpc.gascap",
		Usage: "Sets a cap on gas that can be used in eth_call/estimateGas (0=infinite)",
		Value: nodeconfig.Defaults.RPCGasCap,
	}
	RPCGlobalPVMTimeoutFlag = cli.DurationFlag{
		Name:  "rpc.pvmtimeout",
		Usage: "Sets a timeout used for eth_call (0=infinite)",
		Value: nodeconfig.Defaults.RPCPVMTimeout,
	}
	RPCGlobalTxFeeCapFlag = cli.Float64Flag{
		Name:  "rpc.txfeecap",
		Usage: "Sets a cap on transaction fee (in laxes) that can be sent via the RPC APIs (0 = no cap)",
		Value: nodeconfig.Defaults.RPCTxFeeCap,
	}
	// Authenticated RPC HTTP settings
	AuthListenFlag = cli.StringFlag{
		Name:  "authrpc.addr",
		Usage: "Listening address for authenticated APIs",
		Value: node.DefaultConfig.AuthAddr,
	}
	AuthPortFlag = cli.IntFlag{
		Name:  "authrpc.port",
		Usage: "Listening port for authenticated APIs",
		Value: node.DefaultConfig.AuthPort,
	}
	AuthVirtualHostsFlag = cli.StringFlag{
		Name:  "authrpc.vhosts",
		Usage: "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value: strings.Join(node.DefaultConfig.AuthVirtualHosts, ","),
	}
	JWTSecretFlag = cli.StringFlag{
		Name:  "authrpc.jwtsecret",
		Usage: "Path to a JWT secret to use for authenticated RPC endpoints",
	}
	// Logging and debug settings
	PrlStatsURLFlag = cli.StringFlag{
		Name:  "prlstats",
		Usage: "Reporting URL of a prlstats service (nodename:secret@host:port)",
	}
	FakePoWFlag = cli.BoolFlag{
		Name:  "fakepow",
		Usage: "Disables proof-of-work verification",
	}
	NoCompactionFlag = cli.BoolFlag{
		Name:  "nocompaction",
		Usage: "Disables db compaction after import",
	}
	// RPC settings
	IPCDisabledFlag = cli.BoolFlag{
		Name:  "ipcdisable",
		Usage: "Disable the IPC-RPC server",
	}
	IPCPathFlag = DirectoryFlag{
		Name:  "ipcpath",
		Usage: "Filename for IPC socket/pipe within the datadir (explicit paths escape it)",
	}
	HTTPEnabledFlag = cli.BoolFlag{
		Name:  "http",
		Usage: "Enable the HTTP-RPC server",
	}
	HTTPListenAddrFlag = cli.StringFlag{
		Name:  "http.addr",
		Usage: "HTTP-RPC server listening interface",
		Value: node.DefaultHTTPHost,
	}
	HTTPPortFlag = cli.IntFlag{
		Name:  "http.port",
		Usage: "HTTP-RPC server listening port",
		Value: node.DefaultHTTPPort,
	}
	HTTPCORSDomainFlag = cli.StringFlag{
		Name:  "http.corsdomain",
		Usage: "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
		Value: "",
	}
	HTTPVirtualHostsFlag = cli.StringFlag{
		Name:  "http.vhosts",
		Usage: "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value: strings.Join(node.DefaultConfig.HTTPVirtualHosts, ","),
	}
	HTTPApiFlag = cli.StringFlag{
		Name:  "http.api",
		Usage: "API's offered over the HTTP-RPC interface",
		Value: "",
	}
	HTTPPathPrefixFlag = cli.StringFlag{
		Name:  "http.rpcprefix",
		Usage: "HTTP path path prefix on which JSON-RPC is served. Use '/' to serve on all paths.",
		Value: "",
	}
	GraphQLEnabledFlag = cli.BoolFlag{
		Name:  "graphql",
		Usage: "Enable GraphQL on the HTTP-RPC server. Note that GraphQL can only be started if an HTTP server is started as well.",
	}
	GraphQLCORSDomainFlag = cli.StringFlag{
		Name:  "graphql.corsdomain",
		Usage: "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
		Value: "",
	}
	GraphQLVirtualHostsFlag = cli.StringFlag{
		Name:  "graphql.vhosts",
		Usage: "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
		Value: strings.Join(node.DefaultConfig.GraphQLVirtualHosts, ","),
	}
	WSEnabledFlag = cli.BoolFlag{
		Name:  "ws",
		Usage: "Enable the WS-RPC server",
	}
	WSListenAddrFlag = cli.StringFlag{
		Name:  "ws.addr",
		Usage: "WS-RPC server listening interface",
		Value: node.DefaultWSHost,
	}
	WSPortFlag = cli.IntFlag{
		Name:  "ws.port",
		Usage: "WS-RPC server listening port",
		Value: node.DefaultWSPort,
	}
	WSApiFlag = cli.StringFlag{
		Name:  "ws.api",
		Usage: "API's offered over the WS-RPC interface",
		Value: "",
	}
	WSAllowedOriginsFlag = cli.StringFlag{
		Name:  "ws.origins",
		Usage: "Origins from which to accept websockets requests",
		Value: "",
	}
	WSPathPrefixFlag = cli.StringFlag{
		Name:  "ws.rpcprefix",
		Usage: "HTTP path prefix on which JSON-RPC is served. Use '/' to serve on all paths.",
		Value: "",
	}
	ExecFlag = cli.StringFlag{
		Name:  "exec",
		Usage: "Execute JavaScript statement",
	}
	PreloadJSFlag = cli.StringFlag{
		Name:  "preload",
		Usage: "Comma separated list of JavaScript files to preload into the console",
	}
	AllowUnprotectedTxs = cli.BoolFlag{
		Name:  "rpc.allow-unprotected-txs",
		Usage: "Allow for unprotected (non EIP155 signed) transactions to be submitted via RPC",
	}

	// Network Settings
	MaxPeersFlag = cli.IntFlag{
		Name:  "maxpeers",
		Usage: "Maximum number of network peers (network disabled if set to 0)",
		Value: node.DefaultConfig.P2P.MaxPeers,
	}
	MaxPendingPeersFlag = cli.IntFlag{
		Name:  "maxpendpeers",
		Usage: "Maximum number of pending connection attempts (defaults used if set to 0)",
		Value: node.DefaultConfig.P2P.MaxPendingPeers,
	}
	ListenPortFlag = cli.IntFlag{
		Name:  "port",
		Usage: "Network listening port",
		Value: 32110,
	}
	BootnodesFlag = cli.StringFlag{
		Name:  "bootnodes",
		Usage: "Comma separated enode URLs for P2P discovery bootstrap",
		Value: "",
	}
	NodeKeyFileFlag = cli.StringFlag{
		Name:  "nodekey",
		Usage: "P2P node key file",
	}
	NodeKeyHexFlag = cli.StringFlag{
		Name:  "nodekeyhex",
		Usage: "P2P node key as hex (for testing)",
	}
	NATFlag = cli.StringFlag{
		Name:  "nat",
		Usage: "NAT port mapping mechanism (any|none|upnp|pmp|extip:<IP>)",
		Value: "any",
	}
	NoDiscoverFlag = cli.BoolFlag{
		Name:  "nodiscover",
		Usage: "Disables the peer discovery mechanism (manual peer addition)",
	}
	NetrestrictFlag = cli.StringFlag{
		Name:  "netrestrict",
		Usage: "Restricts network communication to the given IP networks (CIDR masks)",
	}
	DNSDiscoveryFlag = cli.StringFlag{
		Name:  "discovery.dns",
		Usage: "Sets DNS discovery entry points (use \"\" to disable DNS)",
	}
	DNSSeedFlag = cli.StringFlag{
		Name: "dnsseed",
		Usage: "Comma-separated DNS hostnames resolved every 24h (Bitcoin parity) for plain A/AAAA peer bootstrap. " +
			"Each resolved IP is paired with the default v2 listen port (32110) and ingested into addrman with source=dns_seed. " +
			"Empty string disables. Defaults to netparams.MainnetDNSSeeds when unset. --nodiscover overrides to disable.",
	}
	LegacyDiscoveryFlag = cli.StringFlag{
		Name: "legacy-discovery",
		Usage: "Compatibility mode for the v1.x transport stack (auto|on|off). " +
			"Controls UDP discv4 AND legacy RLPx handshake acceptance in lockstep — they share the same identity model. " +
			"auto: discv4 responds to inbound but doesn't drive dialing, legacy RLPx accepted (default, v2.0 transitional posture). " +
			"on: discv4 is a dial source, legacy RLPx accepted (pre-PIP-0006 v1.x compatibility). " +
			"off: no UDP socket, legacy RLPx refused, enode URL becomes diagnostic-only — node is v2-only. " +
			"The addrman and v2 handshake are always on; this flag only controls whether the v1.x surface is exposed alongside them.",
		Value: "auto",
	}
	ProxyFlag = cli.StringFlag{
		Name: "proxy",
		Usage: "SOCKS5 proxy (ip:port) for all outbound P2P connections, including .onion targets. " +
			"DNS seed hostnames stop resolving locally and are fetched through the proxy instead. PIP-0007.",
	}
	OnionFlag = cli.StringFlag{
		Name: "onion",
		Usage: "SOCKS5 proxy (ip:port) used only for .onion targets, overriding --proxy for that network. " +
			"Use 0 to disable onion outbound even when --proxy is set.",
	}
	OnlyNetFlag = cli.StringFlag{
		Name: "onlynet",
		Usage: "Comma-separated networks outbound connections are restricted to (ipv4|ipv6|onion). " +
			"Inbound and operator-initiated dials are unaffected. onion requires --proxy, --onion or --listenonion.",
	}
	ProxyRandomizeFlag = cli.BoolTFlag{
		Name: "proxyrandomize",
		Usage: "Randomize SOCKS5 credentials for every proxy connection (Tor stream isolation, default on). " +
			"--proxyrandomize=false shares one circuit across peers.",
	}
	ListenOnionFlag = cli.BoolTFlag{
		Name: "listenonion",
		Usage: "Create a Tor v3 onion service for the P2P listener via the Tor control port (default on; a no-op " +
			"until the control port answers). Unless --onion is set, the onion proxy is auto-configured from the " +
			"daemon's SOCKS listener, so a local Tor alone yields bidirectional onion connectivity. " +
			"The service key persists in <datadir>/onion_v3_private_key. PIP-0007.",
	}
	TorControlFlag = cli.StringFlag{
		Name:  "torcontrol",
		Usage: "Tor control port to use with --listenonion",
		Value: "127.0.0.1:9051",
	}
	TorPasswordFlag = cli.StringFlag{
		Name:  "torpassword",
		Usage: "Tor control port password (HASHEDPASSWORD auth; cookie auth is used automatically when unset)",
	}

	// ATM the url is left to the user and deployment to
	JSpathFlag = DirectoryFlag{
		Name:  "jspath",
		Usage: "JavaScript root path for `loadScript`",
		Value: DirectoryString("."),
	}

	// Gas price oracle settings
	GpoBlocksFlag = cli.IntFlag{
		Name:  "gpo.blocks",
		Usage: "Number of recent blocks sampled by the legacy percentile gas price oracle (ignored when --gpo.smartfee is enabled)",
		Value: nodeconfig.Defaults.GPO.Blocks,
	}
	GpoPercentileFlag = cli.IntFlag{
		Name:  "gpo.percentile",
		Usage: "Percentile of recent-block transaction gas prices used by the legacy oracle (ignored when --gpo.smartfee is enabled)",
		Value: nodeconfig.Defaults.GPO.Percentile,
	}
	GpoMaxGasPriceFlag = cli.Int64Flag{
		Name:  "gpo.maxprice",
		Usage: "Maximum gas price (in wei) the oracle will ever recommend; caps both the legacy and smart-fee estimators",
		Value: nodeconfig.Defaults.GPO.MaxPrice.Int64(),
	}
	GpoIgnoreGasPriceFlag = cli.Int64Flag{
		Name:  "gpo.ignoreprice",
		Usage: "Gas price (in wei) below which the legacy oracle ignores sampled transactions (ignored when --gpo.smartfee is enabled)",
		Value: nodeconfig.Defaults.GPO.IgnorePrice.Int64(),
	}
	GpoEnableSmartFeeFlag = cli.BoolTFlag{
		Name:  "gpo.smartfee",
		Usage: "Enable the Bitcoin Core-style smart fee estimator (replaces the legacy percentile oracle and exposes eth_estimateSmartFee). Pass --gpo.smartfee=false to use the legacy oracle.",
	}

	// Metrics flags
	MetricsEnabledFlag = cli.BoolFlag{
		Name:  "metrics",
		Usage: "Enable metrics collection and reporting",
	}
	MetricsEnabledExpensiveFlag = cli.BoolFlag{
		Name:  "metrics.expensive",
		Usage: "Enable expensive metrics collection and reporting",
	}

	// MetricsHTTPFlag defines the endpoint for a stand-alone metrics HTTP endpoint.
	// Since the pprof service enables sensitive/vulnerable behavior, this allows a user
	// to enable a public-OK metrics endpoint without having to worry about ALSO exposing
	// other profiling behavior or information.
	MetricsHTTPFlag = cli.StringFlag{
		Name:  "metrics.addr",
		Usage: "Enable stand-alone metrics HTTP server listening interface",
		Value: metrics.DefaultConfig.HTTP,
	}
	MetricsPortFlag = cli.IntFlag{
		Name:  "metrics.port",
		Usage: "Metrics HTTP server listening port",
		Value: metrics.DefaultConfig.Port,
	}
	MetricsEnableInfluxDBFlag = cli.BoolFlag{
		Name:  "metrics.influxdb",
		Usage: "Enable metrics export/push to an external InfluxDB database",
	}
	MetricsInfluxDBEndpointFlag = cli.StringFlag{
		Name:  "metrics.influxdb.endpoint",
		Usage: "InfluxDB API endpoint to report metrics to",
		Value: metrics.DefaultConfig.InfluxDBEndpoint,
	}
	MetricsInfluxDBDatabaseFlag = cli.StringFlag{
		Name:  "metrics.influxdb.database",
		Usage: "InfluxDB database name to push reported metrics to",
		Value: metrics.DefaultConfig.InfluxDBDatabase,
	}
	MetricsInfluxDBUsernameFlag = cli.StringFlag{
		Name:  "metrics.influxdb.username",
		Usage: "Username to authorize access to the database",
		Value: metrics.DefaultConfig.InfluxDBUsername,
	}
	MetricsInfluxDBPasswordFlag = cli.StringFlag{
		Name:  "metrics.influxdb.password",
		Usage: "Password to authorize access to the database",
		Value: metrics.DefaultConfig.InfluxDBPassword,
	}
	// Tags are part of every measurement sent to InfluxDB. Queries on tags are faster in InfluxDB.
	// For example `host` tag could be used so that we can group all nodes and average a measurement
	// across all of them, but also so that we can select a specific node and inspect its measurements.
	// https://docs.influxdata.com/influxdb/v1.4/concepts/key_concepts/#tag-key
	MetricsInfluxDBTagsFlag = cli.StringFlag{
		Name:  "metrics.influxdb.tags",
		Usage: "Comma-separated InfluxDB tags (key/values) attached to all measurements",
		Value: metrics.DefaultConfig.InfluxDBTags,
	}

	MetricsEnableInfluxDBV2Flag = cli.BoolFlag{
		Name:  "metrics.influxdbv2",
		Usage: "Enable metrics export/push to an external InfluxDB v2 database",
	}

	MetricsInfluxDBTokenFlag = cli.StringFlag{
		Name:  "metrics.influxdb.token",
		Usage: "Token to authorize access to the database (v2 only)",
		Value: metrics.DefaultConfig.InfluxDBToken,
	}

	MetricsInfluxDBBucketFlag = cli.StringFlag{
		Name:  "metrics.influxdb.bucket",
		Usage: "InfluxDB bucket name to push reported metrics to (v2 only)",
		Value: metrics.DefaultConfig.InfluxDBBucket,
	}

	MetricsInfluxDBOrganizationFlag = cli.StringFlag{
		Name:  "metrics.influxdb.organization",
		Usage: "InfluxDB organization name (v2 only)",
		Value: metrics.DefaultConfig.InfluxDBOrganization,
	}
)

var (
	// TestnetFlags is the flag group of all built-in supported testnets.
	TestnetFlags = []cli.Flag{
		TestnetFlag,
	}
	// NetworkFlags is the flag group of all built-in supported networks.
	NetworkFlags = append([]cli.Flag{
		MainnetFlag,
	}, TestnetFlags...)

	// DatabasePathFlags is the flag group of all database path flags.
	DatabasePathFlags = []cli.Flag{
		DataDirFlag,
		AncientFlag,
		RemoteDBFlag,
	}
)

// GroupFlags combines the given flag slices together and returns the merged one.
func GroupFlags(groups ...[]cli.Flag) []cli.Flag {
	var ret []cli.Flag
	for _, group := range groups {
		ret = append(ret, group...)
	}
	return ret
}

// MakeDataDir retrieves the currently requested data directory, terminating
// if none (or the empty string) is specified. If the node is starting a testnet,
// then a subdirectory of the specified datadir will be used.
func MakeDataDir(ctx *cli.Context) string {
	if path := ctx.GlobalString(DataDirFlag.Name); path != "" {
		if ctx.GlobalBool(TestnetFlag.Name) {
			return filepath.Join(path, "testnet")
		}
		return path
	}
	Fatalf("Cannot determine default data directory, please set manually (--datadir)")
	return ""
}

// setNodeKey creates a node key from set command line flags, either loading it
// from a file or as a specified hex value. If neither flags were provided, this
// method returns nil and an emphemeral key is to be generated.
func setNodeKey(ctx *cli.Context, cfg *p2p.Config) {
	var (
		hex  = ctx.GlobalString(NodeKeyHexFlag.Name)
		file = ctx.GlobalString(NodeKeyFileFlag.Name)
		key  *ecdsa.PrivateKey
		err  error
	)
	switch {
	case file != "" && hex != "":
		Fatalf("Options %q and %q are mutually exclusive", NodeKeyFileFlag.Name, NodeKeyHexFlag.Name)
	case file != "":
		if key, err = crypto.LoadECDSA(file); err != nil {
			Fatalf("Option %q: %v", NodeKeyFileFlag.Name, err)
		}
		cfg.PrivateKey = key
	case hex != "":
		if key, err = crypto.HexToECDSA(hex); err != nil {
			Fatalf("Option %q: %v", NodeKeyHexFlag.Name, err)
		}
		cfg.PrivateKey = key
	}
}

// setNodeUserIdent creates the user identifier from CLI flags.
func setNodeUserIdent(ctx *cli.Context, cfg *node.Config) {
	if identity := ctx.GlobalString(IdentityFlag.Name); len(identity) > 0 {
		cfg.UserIdent = identity
	}
}

// setBootstrapNodes creates the two bootstrap node slices from the
// command line flags, reverting to pre-configured ones if none have
// been specified.
//
// Entries come in two forms:
//
//   - "enode://…@ip:port" — NodeID-carrying. Seeds discv4's routing
//     table and is ingested into addrman with KeyType=0x01.
//   - "ip:port" — plain endpoint. Used by the Parallax v2.0 BIP324-
//     style handshake (no NodeID on the wire); ingested into addrman
//     with KeyType=0x00.
//
// --bootnodes sniffs per-entry and routes into the right slice.
func setBootstrapNodes(ctx *cli.Context, cfg *p2p.Config) {
	enodeURLs := netparams.MainnetBootnodes
	v2Addrs := netparams.MainnetBootnodesV2
	switch {
	case ctx.GlobalIsSet(BootnodesFlag.Name):
		enodeURLs = nil
		v2Addrs = nil
		for _, raw := range SplitAndTrim(ctx.GlobalString(BootnodesFlag.Name)) {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if strings.HasPrefix(raw, "enode://") || strings.HasPrefix(raw, "enr:") {
				enodeURLs = append(enodeURLs, raw)
			} else {
				v2Addrs = append(v2Addrs, raw)
			}
		}
	case ctx.GlobalBool(TestnetFlag.Name):
		enodeURLs = netparams.TestnetBootnodes
		v2Addrs = netparams.TestnetBootnodesV2
	case cfg.BootstrapNodes != nil || cfg.BootstrapNodesV2 != nil:
		return // already set, don't apply defaults.
	}

	cfg.BootstrapNodes = make([]*enode.Node, 0, len(enodeURLs))
	for _, url := range enodeURLs {
		if url == "" {
			continue
		}
		node, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			logging.Crit("Bootstrap URL invalid", "enode", url, "err", err)
			continue
		}
		cfg.BootstrapNodes = append(cfg.BootstrapNodes, node)
	}

	cfg.BootstrapNodesV2 = make([]addrman.NetAddr, 0, len(v2Addrs))
	for _, raw := range v2Addrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		na, err := addrman.ParseHostPort(raw)
		if err != nil {
			logging.Crit("Bootstrap v2 entry invalid (expected ip:port or <addr>.onion:port)", "entry", raw, "err", err)
			continue
		}
		cfg.BootstrapNodesV2 = append(cfg.BootstrapNodesV2, na)
	}
}

// setDNSSeeds populates cfg.DNSSeeds from --dnsseed, falling back to
// netparams.MainnetDNSSeeds (or testnet equivalent). --nodiscover
// overrides everything and clears the slice. An empty --dnsseed=
// (set to the empty string) also disables — operators who want zero
// DNS lookups but full discovery otherwise have a knob.
func setDNSSeeds(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.GlobalIsSet(NoDiscoverFlag.Name) && ctx.GlobalBool(NoDiscoverFlag.Name) {
		cfg.DNSSeeds = nil
		return
	}
	if ctx.GlobalIsSet(DNSSeedFlag.Name) {
		raw := ctx.GlobalString(DNSSeedFlag.Name)
		if raw == "" {
			cfg.DNSSeeds = nil
			return
		}
		cfg.DNSSeeds = SplitAndTrim(raw)
		return
	}
	if ctx.GlobalBool(TestnetFlag.Name) {
		cfg.DNSSeeds = netparams.TestnetDNSSeeds
		return
	}
	cfg.DNSSeeds = netparams.MainnetDNSSeeds
}

// setListenAddress creates a TCP listening address string from set command
// line flags.
func setListenAddress(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.GlobalIsSet(ListenPortFlag.Name) {
		cfg.ListenAddr = fmt.Sprintf(":%d", ctx.GlobalInt(ListenPortFlag.Name))
	}
}

// setProxy applies the PIP-0007 proxy flags (--proxy, --onion,
// --onlynet, --proxyrandomize). Validation of the resulting policy —
// unknown networks, onion restriction without a route — happens in
// p2p.Server.Start, which fails startup on inconsistent values the way
// Core's InitError does.
func setProxy(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.GlobalIsSet(ProxyFlag.Name) {
		cfg.ProxyAddr = ctx.GlobalString(ProxyFlag.Name)
	}
	if ctx.GlobalIsSet(OnionFlag.Name) {
		cfg.OnionProxyAddr = ctx.GlobalString(OnionFlag.Name)
	}
	if ctx.GlobalIsSet(OnlyNetFlag.Name) {
		cfg.OnlyNet = SplitAndTrim(ctx.GlobalString(OnlyNetFlag.Name))
	}
	// Guarded like every other setter here so a value from a config
	// file survives when the flag is absent. BoolTFlag defaults true,
	// so GlobalBool is false only when --proxyrandomize=false was
	// passed explicitly.
	if ctx.GlobalIsSet(ProxyRandomizeFlag.Name) {
		cfg.ProxyNoRandomize = !ctx.GlobalBool(ProxyRandomizeFlag.Name)
	}

	// Onion service (PIP-0007 §3). Core's -listenonion defaults on:
	// the controller idles on reconnect backoff until a Tor control
	// port answers, so nodes without Tor pay only a periodic local
	// connect attempt.
	if ctx.GlobalIsSet(ListenOnionFlag.Name) {
		cfg.ListenOnion = ctx.GlobalBool(ListenOnionFlag.Name)
	}
	if ctx.GlobalIsSet(TorControlFlag.Name) {
		cfg.TorControlAddr = ctx.GlobalString(TorControlFlag.Name)
	}
	if ctx.GlobalIsSet(TorPasswordFlag.Name) {
		cfg.TorPassword = ctx.GlobalString(TorPasswordFlag.Name)
	}
}

// setNAT creates a port mapper from command line flags.
func setNAT(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.GlobalIsSet(NATFlag.Name) {
		natif, err := nat.Parse(ctx.GlobalString(NATFlag.Name))
		if err != nil {
			Fatalf("Option %s: %v", NATFlag.Name, err)
		}
		cfg.NAT = natif
	}
}

// SplitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func SplitAndTrim(input string) (ret []string) {
	l := strings.Split(input, ",")
	for _, r := range l {
		if r = strings.TrimSpace(r); r != "" {
			ret = append(ret, r)
		}
	}
	return ret
}

// setHTTP creates the HTTP RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setHTTP(ctx *cli.Context, cfg *node.Config) {
	if ctx.GlobalBool(HTTPEnabledFlag.Name) && cfg.HTTPHost == "" {
		cfg.HTTPHost = "127.0.0.1"
		if ctx.GlobalIsSet(HTTPListenAddrFlag.Name) {
			cfg.HTTPHost = ctx.GlobalString(HTTPListenAddrFlag.Name)
		}
	}

	if ctx.GlobalIsSet(HTTPPortFlag.Name) {
		cfg.HTTPPort = ctx.GlobalInt(HTTPPortFlag.Name)
	}

	if ctx.GlobalIsSet(AuthListenFlag.Name) {
		cfg.AuthAddr = ctx.GlobalString(AuthListenFlag.Name)
	}

	if ctx.GlobalIsSet(AuthPortFlag.Name) {
		cfg.AuthPort = ctx.GlobalInt(AuthPortFlag.Name)
	}

	if ctx.GlobalIsSet(AuthVirtualHostsFlag.Name) {
		cfg.AuthVirtualHosts = SplitAndTrim(ctx.GlobalString(AuthVirtualHostsFlag.Name))
	}

	if ctx.GlobalIsSet(HTTPCORSDomainFlag.Name) {
		cfg.HTTPCors = SplitAndTrim(ctx.GlobalString(HTTPCORSDomainFlag.Name))
	}

	if ctx.GlobalIsSet(HTTPApiFlag.Name) {
		cfg.HTTPModules = SplitAndTrim(ctx.GlobalString(HTTPApiFlag.Name))
	}

	if ctx.GlobalIsSet(HTTPVirtualHostsFlag.Name) {
		cfg.HTTPVirtualHosts = SplitAndTrim(ctx.GlobalString(HTTPVirtualHostsFlag.Name))
	}

	if ctx.GlobalIsSet(HTTPPathPrefixFlag.Name) {
		cfg.HTTPPathPrefix = ctx.GlobalString(HTTPPathPrefixFlag.Name)
	}
	if ctx.GlobalIsSet(AllowUnprotectedTxs.Name) {
		cfg.AllowUnprotectedTxs = ctx.GlobalBool(AllowUnprotectedTxs.Name)
	}
}

// setGraphQL creates the GraphQL listener interface string from the set
// command line flags, returning empty if the GraphQL endpoint is disabled.
func setGraphQL(ctx *cli.Context, cfg *node.Config) {
	if ctx.GlobalIsSet(GraphQLCORSDomainFlag.Name) {
		cfg.GraphQLCors = SplitAndTrim(ctx.GlobalString(GraphQLCORSDomainFlag.Name))
	}
	if ctx.GlobalIsSet(GraphQLVirtualHostsFlag.Name) {
		cfg.GraphQLVirtualHosts = SplitAndTrim(ctx.GlobalString(GraphQLVirtualHostsFlag.Name))
	}
}

// setWS creates the WebSocket RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setWS(ctx *cli.Context, cfg *node.Config) {
	if ctx.GlobalBool(WSEnabledFlag.Name) && cfg.WSHost == "" {
		cfg.WSHost = "127.0.0.1"
		if ctx.GlobalIsSet(WSListenAddrFlag.Name) {
			cfg.WSHost = ctx.GlobalString(WSListenAddrFlag.Name)
		}
	}
	if ctx.GlobalIsSet(WSPortFlag.Name) {
		cfg.WSPort = ctx.GlobalInt(WSPortFlag.Name)
	}

	if ctx.GlobalIsSet(WSAllowedOriginsFlag.Name) {
		cfg.WSOrigins = SplitAndTrim(ctx.GlobalString(WSAllowedOriginsFlag.Name))
	}

	if ctx.GlobalIsSet(WSApiFlag.Name) {
		cfg.WSModules = SplitAndTrim(ctx.GlobalString(WSApiFlag.Name))
	}

	if ctx.GlobalIsSet(WSPathPrefixFlag.Name) {
		cfg.WSPathPrefix = ctx.GlobalString(WSPathPrefixFlag.Name)
	}
}

// setIPC creates an IPC path configuration from the set command line flags,
// returning an empty string if IPC was explicitly disabled, or the set path.
func setIPC(ctx *cli.Context, cfg *node.Config) {
	CheckExclusive(ctx, IPCDisabledFlag, IPCPathFlag)
	switch {
	case ctx.GlobalBool(IPCDisabledFlag.Name):
		cfg.IPCPath = ""
	case ctx.GlobalIsSet(IPCPathFlag.Name):
		cfg.IPCPath = ctx.GlobalString(IPCPathFlag.Name)
	}
}

// MakeDatabaseHandles raises out the number of allowed file handles per process
// for Prlx and returns half of the allowance to assign to the database.
func MakeDatabaseHandles(max int) int {
	limit, err := fdlimit.Maximum()
	if err != nil {
		Fatalf("Failed to retrieve file descriptor allowance: %v", err)
	}
	switch {
	case max == 0:
		// User didn't specify a meaningful value, use system limits
	case max < 128:
		// User specified something unhealthy, just use system defaults
		logging.Error("File descriptor limit invalid (<128)", "had", max, "updated", limit)
	case max > limit:
		// User requested more than the OS allows, notify that we can't allocate it
		logging.Warn("Requested file descriptors denied by OS", "req", max, "limit", limit)
	default:
		// User limit is meaningful and within allowed range, use that
		limit = max
	}
	raised, err := fdlimit.Raise(uint64(limit))
	if err != nil {
		Fatalf("Failed to raise file descriptor allowance: %v", err)
	}
	return int(raised / 2) // Leave half for networking and other stuff
}

// MakeAddress converts an account specified directly as a hex encoded string or
// a key index in the key store to an internal account representation.
func MakeAddress(ks *keystore.KeyStore, account string) (wallet.Account, error) {
	// If the specified account is a valid address, return it
	if util.IsHexAddress(account) {
		return wallet.Account{Address: util.HexToAddress(account)}, nil
	}
	// Otherwise try to interpret the account as a keystore index
	index, err := strconv.Atoi(account)
	if err != nil || index < 0 {
		return wallet.Account{}, fmt.Errorf("invalid account address or index %q", account)
	}
	logging.Warn("-------------------------------------------------------------------")
	logging.Warn("Referring to accounts by order in the keystore folder is dangerous!")
	logging.Warn("This functionality is deprecated and will be removed in the future!")
	logging.Warn("Please use explicit addresses! (can search via `parallax account list`)")
	logging.Warn("-------------------------------------------------------------------")

	accs := ks.Accounts()
	if len(accs) <= index {
		return wallet.Account{}, fmt.Errorf("index %d higher than number of accounts %d", index, len(accs))
	}
	return accs[index], nil
}

// setCoinbase retrieves the address either from the directly specified
// command line flags or from the keystore if CLI indexed.
func setCoinbase(ctx *cli.Context, ks *keystore.KeyStore, cfg *nodeconfig.Config) {
	// Extract the current miner address
	var coinbase string
	if ctx.GlobalIsSet(MinerCoinbaseFlag.Name) {
		coinbase = ctx.GlobalString(MinerCoinbaseFlag.Name)
	}
	// Convert the coinbase into an address and configure it
	if coinbase != "" {
		if ks != nil {
			account, err := MakeAddress(ks, coinbase)
			if err != nil {
				Fatalf("Invalid miner coinbase: %v", err)
			}
			cfg.Miner.Coinbase = account.Address
		} else {
			Fatalf("No coinbase configured")
		}
	}
}

// MakePasswordList reads password lines from the file specified by the global --password flag.
func MakePasswordList(ctx *cli.Context) []string {
	path := ctx.GlobalString(PasswordFileFlag.Name)
	if path == "" {
		return nil
	}
	text, err := os.ReadFile(path)
	if err != nil {
		Fatalf("Failed to read password file: %v", err)
	}
	lines := strings.Split(string(text), "\n")
	// Sanitise DOS line endings.
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

func SetP2PConfig(ctx *cli.Context, cfg *p2p.Config) {
	setNodeKey(ctx, cfg)
	setNAT(ctx, cfg)
	setListenAddress(ctx, cfg)
	setBootstrapNodes(ctx, cfg)
	setDNSSeeds(ctx, cfg)
	setProxy(ctx, cfg)

	if ctx.GlobalIsSet(MaxPeersFlag.Name) {
		cfg.MaxPeers = ctx.GlobalInt(MaxPeersFlag.Name)
	}
	logging.Info("Maximum peer count", "total", cfg.MaxPeers)

	if ctx.GlobalIsSet(MaxPendingPeersFlag.Name) {
		cfg.MaxPendingPeers = ctx.GlobalInt(MaxPendingPeersFlag.Name)
	}
	if ctx.GlobalIsSet(NoDiscoverFlag.Name) {
		cfg.NoDiscovery = true
	}
	if ctx.GlobalIsSet(LegacyDiscoveryFlag.Name) {
		cfg.LegacyDiscoveryMode = ctx.GlobalString(LegacyDiscoveryFlag.Name)
	}

	if netrestrict := ctx.GlobalString(NetrestrictFlag.Name); netrestrict != "" {
		list, err := netutil.ParseNetlist(netrestrict)
		if err != nil {
			Fatalf("Option %q: %v", NetrestrictFlag.Name, err)
		}
		cfg.NetRestrict = list
	}

	if ctx.GlobalBool(DeveloperFlag.Name) {
		// --dev mode can't use p2p networking.
		cfg.MaxPeers = 0
		cfg.ListenAddr = ""
		cfg.NoDial = true
		cfg.NoDiscovery = true
	}

	// Filter out non-Parallax nodes from discovery lookups.
	// This only affects the lookup worker path, not ping/pong handling.
	cfg.NodeFilter = parallaxNodeFilter
}

// parallaxNodeFilter checks that a node advertises the "parallax" ENR key.
func parallaxNodeFilter(n *enode.Node) bool {
	var entry parallaxENREntry
	return n.Load(&entry) == nil
}

// parallaxENREntry is used to check for the "parallax" key in ENR records.
type parallaxENREntry struct {
	Rest []rlp.RawValue `rlp:"tail"`
}

func (e parallaxENREntry) ENRKey() string { return "parallax" }

// SetNodeConfig applies node-related command line flags to the config.
func SetNodeConfig(ctx *cli.Context, cfg *node.Config) {
	SetP2PConfig(ctx, &cfg.P2P)
	setIPC(ctx, cfg)
	setHTTP(ctx, cfg)
	setGraphQL(ctx, cfg)
	setWS(ctx, cfg)
	setNodeUserIdent(ctx, cfg)
	setDataDir(ctx, cfg)
	setSmartCard(ctx, cfg)

	// Default the addrbook location to <datadir>/addrbook.rlp. An
	// empty AddrBookPath keeps the addrman in-memory only (fine for
	// ephemeral test nodes without a datadir).
	if cfg.P2P.AddrBookPath == "" && cfg.DataDir != "" {
		cfg.P2P.AddrBookPath = filepath.Join(cfg.DataDir, "addrbook.rlp")
	}
	// Default the anchors location to <datadir>/anchors.dat. An empty
	// AnchorsPath disables block-relay-only anchor persistence (fine
	// for ephemeral tests and nodes with a negative MaxBlockRelayPeers,
	// which disables the block-relay bucket; 0 means "use the default
	// of 2").
	if cfg.P2P.AnchorsPath == "" && cfg.DataDir != "" {
		cfg.P2P.AnchorsPath = filepath.Join(cfg.DataDir, "anchors.dat")
	}
	// Default the banlist location to <datadir>/banlist.json. An empty
	// BanListPath keeps the BanMan in-memory only (fine for ephemeral
	// tests).
	if cfg.P2P.BanListPath == "" && cfg.DataDir != "" {
		cfg.P2P.BanListPath = filepath.Join(cfg.DataDir, "banlist.json")
	}
	// Default the onion service key to <datadir>/onion_v3_private_key
	// (Core's filename). Empty keeps the onion identity ephemeral —
	// a fresh address every restart.
	if cfg.P2P.OnionKeyPath == "" && cfg.DataDir != "" {
		cfg.P2P.OnionKeyPath = filepath.Join(cfg.DataDir, "onion_v3_private_key")
	}

	if ctx.GlobalIsSet(JWTSecretFlag.Name) {
		cfg.JWTSecret = ctx.GlobalString(JWTSecretFlag.Name)
	}

	if ctx.GlobalIsSet(ExternalSignerFlag.Name) {
		cfg.ExternalSigner = ctx.GlobalString(ExternalSignerFlag.Name)
	}

	if ctx.GlobalIsSet(KeyStoreDirFlag.Name) {
		cfg.KeyStoreDir = ctx.GlobalString(KeyStoreDirFlag.Name)
	}
	if ctx.GlobalIsSet(DeveloperFlag.Name) {
		cfg.UseLightweightKDF = true
	}
	if ctx.GlobalIsSet(LightKDFFlag.Name) {
		cfg.UseLightweightKDF = ctx.GlobalBool(LightKDFFlag.Name)
	}
	if ctx.GlobalIsSet(USBFlag.Name) {
		cfg.USB = ctx.GlobalBool(USBFlag.Name)
	}
	if ctx.GlobalIsSet(InsecureUnlockAllowedFlag.Name) {
		cfg.InsecureUnlockAllowed = ctx.GlobalBool(InsecureUnlockAllowedFlag.Name)
	}
}

func setSmartCard(ctx *cli.Context, cfg *node.Config) {
	// Skip enabling smartcards if no path is set
	path := ctx.GlobalString(SmartCardDaemonPathFlag.Name)
	if path == "" {
		return
	}
	// Sanity check that the smartcard path is valid
	fi, err := os.Stat(path)
	if err != nil {
		logging.Info("Smartcard socket not found, disabling", "err", err)
		return
	}
	if fi.Mode()&os.ModeType != os.ModeSocket {
		logging.Error("Invalid smartcard daemon path", "path", path, "type", fi.Mode().String())
		return
	}
	// Smartcard daemon path exists and is a socket, enable it
	cfg.SmartCardDaemonPath = path
}

func setDataDir(ctx *cli.Context, cfg *node.Config) {
	switch {
	case ctx.GlobalIsSet(DataDirFlag.Name):
		cfg.DataDir = ctx.GlobalString(DataDirFlag.Name)
	case ctx.GlobalBool(DeveloperFlag.Name):
		cfg.DataDir = "" // unless explicitly requested, use memory databases
	case ctx.GlobalBool(TestnetFlag.Name) && cfg.DataDir == node.DefaultDataDir():
		cfg.DataDir = filepath.Join(node.DefaultDataDir(), "testnet")
	}
}

func setGPO(ctx *cli.Context, cfg *fees.Config) {
	if ctx.GlobalIsSet(GpoBlocksFlag.Name) {
		cfg.Blocks = ctx.GlobalInt(GpoBlocksFlag.Name)
	}
	if ctx.GlobalIsSet(GpoPercentileFlag.Name) {
		cfg.Percentile = ctx.GlobalInt(GpoPercentileFlag.Name)
	}
	if ctx.GlobalIsSet(GpoMaxGasPriceFlag.Name) {
		cfg.MaxPrice = big.NewInt(ctx.GlobalInt64(GpoMaxGasPriceFlag.Name))
	}
	if ctx.GlobalIsSet(GpoIgnoreGasPriceFlag.Name) {
		cfg.IgnorePrice = big.NewInt(ctx.GlobalInt64(GpoIgnoreGasPriceFlag.Name))
	}
	if ctx.GlobalIsSet(GpoEnableSmartFeeFlag.Name) {
		cfg.EnableSmartFeeEstimator = ctx.GlobalBool(GpoEnableSmartFeeFlag.Name)
	}
}

func setTxPool(ctx *cli.Context, cfg *validation.TxPoolConfig) {
	if ctx.GlobalIsSet(TxPoolLocalsFlag.Name) {
		locals := strings.Split(ctx.GlobalString(TxPoolLocalsFlag.Name), ",")
		for _, account := range locals {
			if trimmed := strings.TrimSpace(account); !util.IsHexAddress(trimmed) {
				Fatalf("Invalid account in --txpool.locals: %s", trimmed)
			} else {
				cfg.Locals = append(cfg.Locals, util.HexToAddress(trimmed))
			}
		}
	}
	if ctx.GlobalIsSet(TxPoolNoLocalsFlag.Name) {
		cfg.NoLocals = ctx.GlobalBool(TxPoolNoLocalsFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolJournalFlag.Name) {
		cfg.Journal = ctx.GlobalString(TxPoolJournalFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolRejournalFlag.Name) {
		cfg.Rejournal = ctx.GlobalDuration(TxPoolRejournalFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolPriceLimitFlag.Name) {
		cfg.PriceLimit = ctx.GlobalUint64(TxPoolPriceLimitFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolPriceBumpFlag.Name) {
		cfg.PriceBump = ctx.GlobalUint64(TxPoolPriceBumpFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolAccountSlotsFlag.Name) {
		cfg.AccountSlots = ctx.GlobalUint64(TxPoolAccountSlotsFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolGlobalSlotsFlag.Name) {
		cfg.GlobalSlots = ctx.GlobalUint64(TxPoolGlobalSlotsFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolAccountQueueFlag.Name) {
		cfg.AccountQueue = ctx.GlobalUint64(TxPoolAccountQueueFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolGlobalQueueFlag.Name) {
		cfg.GlobalQueue = ctx.GlobalUint64(TxPoolGlobalQueueFlag.Name)
	}
	if ctx.GlobalIsSet(TxPoolLifetimeFlag.Name) {
		cfg.Lifetime = ctx.GlobalDuration(TxPoolLifetimeFlag.Name)
	}
}

func setXHash(ctx *cli.Context, cfg *nodeconfig.Config) {
	if ctx.GlobalIsSet(XHashCacheDirFlag.Name) {
		cfg.XHash.CacheDir = ctx.GlobalString(XHashCacheDirFlag.Name)
	}
	if ctx.GlobalIsSet(XHashDatasetDirFlag.Name) {
		cfg.XHash.DatasetDir = ctx.GlobalString(XHashDatasetDirFlag.Name)
	}
	if ctx.GlobalIsSet(XHashCachesInMemoryFlag.Name) {
		cfg.XHash.CachesInMem = ctx.GlobalInt(XHashCachesInMemoryFlag.Name)
	}
	if ctx.GlobalIsSet(XHashCachesOnDiskFlag.Name) {
		cfg.XHash.CachesOnDisk = ctx.GlobalInt(XHashCachesOnDiskFlag.Name)
	}
	if ctx.GlobalIsSet(XHashCachesLockMmapFlag.Name) {
		cfg.XHash.CachesLockMmap = ctx.GlobalBool(XHashCachesLockMmapFlag.Name)
	}
	if ctx.GlobalIsSet(XHashDatasetsInMemoryFlag.Name) {
		cfg.XHash.DatasetsInMem = ctx.GlobalInt(XHashDatasetsInMemoryFlag.Name)
	}
	if ctx.GlobalIsSet(XHashDatasetsOnDiskFlag.Name) {
		cfg.XHash.DatasetsOnDisk = ctx.GlobalInt(XHashDatasetsOnDiskFlag.Name)
	}
	if ctx.GlobalIsSet(XHashDatasetsLockMmapFlag.Name) {
		cfg.XHash.DatasetsLockMmap = ctx.GlobalBool(XHashDatasetsLockMmapFlag.Name)
	}
}

func setMiner(ctx *cli.Context, cfg *miner.Config) {
	if ctx.GlobalIsSet(MinerNotifyFlag.Name) {
		cfg.Notify = strings.Split(ctx.GlobalString(MinerNotifyFlag.Name), ",")
	}
	cfg.NotifyFull = ctx.GlobalBool(MinerNotifyFullFlag.Name)
	if ctx.GlobalIsSet(MinerExtraDataFlag.Name) {
		cfg.ExtraData = []byte(ctx.GlobalString(MinerExtraDataFlag.Name))
	}
	if ctx.GlobalIsSet(MinerGasLimitFlag.Name) {
		cfg.GasCeil = ctx.GlobalUint64(MinerGasLimitFlag.Name)
	}
	if ctx.GlobalIsSet(MinerGasPriceFlag.Name) {
		cfg.GasPrice = GlobalBig(ctx, MinerGasPriceFlag.Name)
	}
	if ctx.GlobalIsSet(MinerRecommitIntervalFlag.Name) {
		cfg.Recommit = ctx.GlobalDuration(MinerRecommitIntervalFlag.Name)
	}
	if ctx.GlobalIsSet(MinerNoVerifyFlag.Name) {
		cfg.Noverify = ctx.GlobalBool(MinerNoVerifyFlag.Name)
	}
}

func setRequiredBlocks(ctx *cli.Context, cfg *nodeconfig.Config) {
	requiredBlocks := ctx.GlobalString(PrlRequiredBlocksFlag.Name)
	if requiredBlocks == "" {
		return
	}
	cfg.RequiredBlocks = make(map[uint64]util.Hash)
	for _, entry := range strings.Split(requiredBlocks, ",") {
		parts := strings.Split(entry, "=")
		if len(parts) != 2 {
			Fatalf("Invalid required block entry: %s", entry)
		}
		number, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			Fatalf("Invalid required block number %s: %v", parts[0], err)
		}
		var hash util.Hash
		if err = hash.UnmarshalText([]byte(parts[1])); err != nil {
			Fatalf("Invalid required block hash %s: %v", parts[1], err)
		}
		cfg.RequiredBlocks[number] = hash
	}
}

// CheckExclusive verifies that only a single instance of the provided flags was
// set by the user. Each flag might optionally be followed by a string type to
// specialize it further.
func CheckExclusive(ctx *cli.Context, args ...any) {
	set := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		// Make sure the next argument is a flag and skip if not set
		flag, ok := args[i].(cli.Flag)
		if !ok {
			panic(fmt.Sprintf("invalid argument, not cli.Flag type: %T", args[i]))
		}
		// Check if next arg extends current and expand its name if so
		name := flag.GetName()

		if i+1 < len(args) {
			switch option := args[i+1].(type) {
			case string:
				// Extended flag check, make sure value set doesn't conflict with passed in option
				if ctx.GlobalString(flag.GetName()) == option {
					name += "=" + option
					set = append(set, "--"+name)
				}
				// shift arguments and continue
				i++
				continue

			case cli.Flag:
			default:
				panic(fmt.Sprintf("invalid argument, not cli.Flag or string extension: %T", args[i+1]))
			}
		}
		// Mark the flag if it's set
		if ctx.GlobalIsSet(flag.GetName()) {
			set = append(set, "--"+name)
		}
	}
	if len(set) > 1 {
		Fatalf("Flags %v can't be used at the same time", strings.Join(set, ", "))
	}
}

// SetPrlConfig applies prl-related command line flags to the config.
func SetPrlConfig(ctx *cli.Context, stack *node.Node, cfg *nodeconfig.Config) {
	// Avoid conflicting network flags
	CheckExclusive(ctx, MainnetFlag, DeveloperFlag, TestnetFlag)
	CheckExclusive(ctx, DeveloperFlag, ExternalSignerFlag) // Can't use both ephemeral unlocked and external signer
	if ctx.GlobalString(GCModeFlag.Name) == "archive" && ctx.GlobalUint64(TxLookupLimitFlag.Name) != 0 {
		ctx.GlobalSet(TxLookupLimitFlag.Name, "0")
		logging.Warn("Disable transaction unindexing for archive node")
	}
	var ks *keystore.KeyStore
	if keystores := stack.AccountManager().Backends(keystore.KeyStoreType); len(keystores) > 0 {
		ks = keystores[0].(*keystore.KeyStore)
	}
	setCoinbase(ctx, ks, cfg)
	setGPO(ctx, &cfg.GPO)
	setTxPool(ctx, &cfg.TxPool)
	setXHash(ctx, cfg)
	setMiner(ctx, &cfg.Miner)
	setRequiredBlocks(ctx, cfg)

	// Cap the cache allowance and tune the garbage collector
	mem, err := gopsutil.VirtualMemory()
	if err == nil && mem.Total > 0 {
		if 32<<(^uintptr(0)>>63) == 32 && mem.Total > 2*1024*1024*1024 {
			logging.Warn("Lowering memory allowance on 32bit arch", "available", mem.Total/1024/1024, "addressable", 2*1024)
			mem.Total = 2 * 1024 * 1024 * 1024
		}
		allowance := int(mem.Total / 1024 / 1024 / 3)
		if cache := ctx.GlobalInt(CacheFlag.Name); cache > allowance {
			logging.Warn("Sanitizing cache to Go's GC limits", "provided", cache, "updated", allowance)
			ctx.GlobalSet(CacheFlag.Name, strconv.Itoa(allowance))
		}
	}
	// Ensure Go's GC ignores the database cache for trigger percentage
	cache := ctx.GlobalInt(CacheFlag.Name)
	gogc := math.Max(20, math.Min(100, 100/(float64(cache)/1024)))

	logging.Debug("Sanitizing Go's GC trigger", "percent", int(gogc))
	godebug.SetGCPercent(int(gogc))

	if ctx.GlobalIsSet(SyncModeFlag.Name) {
		cfg.SyncMode = *GlobalTextMarshaler(ctx, SyncModeFlag.Name).(*downloader.SyncMode)
	}
	if ctx.GlobalIsSet(NetworkIdFlag.Name) {
		cfg.NetworkId = ctx.GlobalUint64(NetworkIdFlag.Name)
	}
	if ctx.GlobalIsSet(CacheFlag.Name) || ctx.GlobalIsSet(CacheDatabaseFlag.Name) {
		cfg.DatabaseCache = ctx.GlobalInt(CacheFlag.Name) * ctx.GlobalInt(CacheDatabaseFlag.Name) / 100
	}
	cfg.DatabaseHandles = MakeDatabaseHandles(ctx.GlobalInt(FDLimitFlag.Name))
	if ctx.GlobalIsSet(AncientFlag.Name) {
		cfg.DatabaseFreezer = ctx.GlobalString(AncientFlag.Name)
	}

	if gcmode := ctx.GlobalString(GCModeFlag.Name); gcmode != "full" && gcmode != "archive" {
		Fatalf("--%s must be either 'full' or 'archive'", GCModeFlag.Name)
	}
	if ctx.GlobalIsSet(GCModeFlag.Name) {
		cfg.NoPruning = ctx.GlobalString(GCModeFlag.Name) == "archive"
	}
	if ctx.GlobalIsSet(CacheNoPrefetchFlag.Name) {
		cfg.NoPrefetch = ctx.GlobalBool(CacheNoPrefetchFlag.Name)
	}
	// Read the value from the flag no matter if it's set or not.
	cfg.Preimages = ctx.GlobalBool(CachePreimagesFlag.Name)
	if cfg.NoPruning && !cfg.Preimages {
		cfg.Preimages = true
		logging.Info("Enabling recording of key preimages since archive mode is used")
	}
	if ctx.GlobalIsSet(TxLookupLimitFlag.Name) {
		cfg.TxLookupLimit = ctx.GlobalUint64(TxLookupLimitFlag.Name)
	}
	if ctx.GlobalIsSet(CacheFlag.Name) || ctx.GlobalIsSet(CacheTrieFlag.Name) {
		cfg.TrieCleanCache = ctx.GlobalInt(CacheFlag.Name) * ctx.GlobalInt(CacheTrieFlag.Name) / 100
	}
	if ctx.GlobalIsSet(CacheTrieJournalFlag.Name) {
		cfg.TrieCleanCacheJournal = ctx.GlobalString(CacheTrieJournalFlag.Name)
	}
	if ctx.GlobalIsSet(CacheTrieRejournalFlag.Name) {
		cfg.TrieCleanCacheRejournal = ctx.GlobalDuration(CacheTrieRejournalFlag.Name)
	}
	if ctx.GlobalIsSet(CacheFlag.Name) || ctx.GlobalIsSet(CacheGCFlag.Name) {
		cfg.TrieDirtyCache = ctx.GlobalInt(CacheFlag.Name) * ctx.GlobalInt(CacheGCFlag.Name) / 100
	}
	if ctx.GlobalIsSet(CacheFlag.Name) || ctx.GlobalIsSet(CacheSnapshotFlag.Name) {
		cfg.SnapshotCache = ctx.GlobalInt(CacheFlag.Name) * ctx.GlobalInt(CacheSnapshotFlag.Name) / 100
	}
	if !ctx.GlobalBool(SnapshotFlag.Name) {
		// If snap-sync is requested, this flag is also required
		if cfg.SyncMode == downloader.SnapSync {
			logging.Info("Snap sync requested, enabling --snapshot")
		} else {
			cfg.TrieCleanCache += cfg.SnapshotCache
			cfg.SnapshotCache = 0 // Disabled
		}
	}
	if ctx.GlobalIsSet(DocRootFlag.Name) {
		cfg.DocRoot = ctx.GlobalString(DocRootFlag.Name)
	}
	if ctx.GlobalIsSet(VMEnableDebugFlag.Name) {
		// TODO(fjl): force-enable this in --dev mode
		cfg.EnablePreimageRecording = ctx.GlobalBool(VMEnableDebugFlag.Name)
	}

	if ctx.GlobalIsSet(RPCGlobalGasCapFlag.Name) {
		cfg.RPCGasCap = ctx.GlobalUint64(RPCGlobalGasCapFlag.Name)
	}
	if cfg.RPCGasCap != 0 {
		logging.Info("Set global gas cap", "cap", cfg.RPCGasCap)
	} else {
		logging.Info("Global gas cap disabled")
	}
	if ctx.GlobalIsSet(RPCGlobalPVMTimeoutFlag.Name) {
		cfg.RPCPVMTimeout = ctx.GlobalDuration(RPCGlobalPVMTimeoutFlag.Name)
	}
	if ctx.GlobalIsSet(RPCGlobalTxFeeCapFlag.Name) {
		cfg.RPCTxFeeCap = ctx.GlobalFloat64(RPCGlobalTxFeeCapFlag.Name)
	}
	if ctx.GlobalIsSet(NoDiscoverFlag.Name) {
		cfg.ParallaxDiscoveryURLs, cfg.SnapDiscoveryURLs = []string{}, []string{}
	} else if ctx.GlobalIsSet(DNSDiscoveryFlag.Name) {
		urls := ctx.GlobalString(DNSDiscoveryFlag.Name)
		if urls == "" {
			cfg.ParallaxDiscoveryURLs = []string{}
		} else {
			cfg.ParallaxDiscoveryURLs = SplitAndTrim(urls)
		}
	}
	// Override any default configs for hard coded networks.
	switch {
	case ctx.GlobalBool(MainnetFlag.Name):
		if !ctx.GlobalIsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 2110
		}
		cfg.Genesis = validation.DefaultGenesisBlock()
		SetDNSDiscoveryDefaults(cfg, chainparams.MainnetGenesisHash)
	case ctx.GlobalBool(TestnetFlag.Name):
		if !ctx.GlobalIsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 2111
		}
		cfg.Genesis = validation.DefaultTestnetGenesisBlock()
		SetDNSDiscoveryDefaults(cfg, chainparams.TestnetGenesisHash)
	case ctx.GlobalBool(DeveloperFlag.Name):
		if !ctx.GlobalIsSet(NetworkIdFlag.Name) {
			cfg.NetworkId = 1337
		}
		cfg.SyncMode = downloader.FullSync
		// Create new developer account or reuse existing one
		var (
			developer  wallet.Account
			passphrase string
			err        error
		)
		if list := MakePasswordList(ctx); len(list) > 0 {
			// Just take the first value. Although the function returns a possible multiple values and
			// some usages iterate through them as attempts, that doesn't make sense in this setting,
			// when we're definitely concerned with only one account.
			passphrase = list[0]
		}
		// setCoinbase has been called above, configuring the miner address from command line flags.
		if cfg.Miner.Coinbase != (util.Address{}) {
			developer = wallet.Account{Address: cfg.Miner.Coinbase}
		} else if accs := ks.Accounts(); len(accs) > 0 {
			developer = ks.Accounts()[0]
		} else {
			developer, err = ks.NewAccount(passphrase)
			if err != nil {
				Fatalf("Failed to create developer account: %v", err)
			}
		}
		if err := ks.Unlock(developer, passphrase); err != nil {
			Fatalf("Failed to unlock developer account: %v", err)
		}
		logging.Info("Using developer account", "address", developer.Address)

		// Create a new developer genesis block or reuse existing one
		cfg.Genesis = validation.DeveloperGenesisBlock(uint64(ctx.GlobalInt(DeveloperPeriodFlag.Name)), ctx.GlobalUint64(DeveloperGasLimitFlag.Name), developer.Address)
		if ctx.GlobalIsSet(DataDirFlag.Name) {
			// If datadir doesn't exist we need to open db in write-mode
			// so leveldb can create files.
			readonly := true
			if !util.FileExist(stack.ResolvePath("chaindata")) {
				readonly = false
			}
			// Check if we have an already initialized chain and fall back to
			// that if so. Otherwise we need to generate a new genesis spec.
			chaindb := MakeChainDatabase(ctx, stack, readonly)
			if rawdb.ReadCanonicalHash(chaindb, 0) != (util.Hash{}) {
				cfg.Genesis = nil // fallback to db content
			}
			chaindb.Close()
		}
		if !ctx.GlobalIsSet(MinerGasPriceFlag.Name) {
			cfg.Miner.GasPrice = big.NewInt(1)
		}
	default:
		if cfg.NetworkId == 2110 {
			SetDNSDiscoveryDefaults(cfg, chainparams.MainnetGenesisHash)
		}
	}
}

// SetDNSDiscoveryDefaults configures DNS discovery with the given URL if
// no URLs are set.
func SetDNSDiscoveryDefaults(cfg *nodeconfig.Config, genesis util.Hash) {
	if cfg.ParallaxDiscoveryURLs != nil {
		return // already set through flags/config
	}
	if url := netparams.KnownDNSNetwork(genesis, "all"); url != "" {
		cfg.ParallaxDiscoveryURLs = []string{url}
		cfg.SnapDiscoveryURLs = cfg.ParallaxDiscoveryURLs
	}
}

// RegisterParallaxService adds a Parallax client to the stack.
func RegisterParallaxService(stack *node.Node, cfg *nodeconfig.Config) (api.Backend, *protocol.Parallax) {
	backend, err := protocol.New(stack, cfg)
	if err != nil {
		Fatalf("Failed to register the Parallax service: %v", err)
	}
	stack.RegisterAPIs(tracers.APIs(backend.APIBackend))
	return backend.APIBackend, backend
}

// RegisterPrlStatsService configures the Parallax Stats daemon and adds it to
// the given node.
func RegisterPrlStatsService(stack *node.Node, backend api.Backend, url string) {
	if err := stats.New(stack, backend, backend.Engine(), url); err != nil {
		Fatalf("Failed to register the Parallax Stats service: %v", err)
	}
}

// RegisterGraphQLService is a utility function to construct a new service and register it against a node.
func RegisterGraphQLService(stack *node.Node, backend api.Backend, cfg node.Config) {
	if err := graphql.New(stack, backend, cfg.GraphQLCors, cfg.GraphQLVirtualHosts); err != nil {
		Fatalf("Failed to register the GraphQL service: %v", err)
	}
}

func SetupMetrics(ctx *cli.Context) {
	if metrics.Enabled {
		logging.Info("Enabling metrics collection")

		var (
			enableExport   = ctx.GlobalBool(MetricsEnableInfluxDBFlag.Name)
			enableExportV2 = ctx.GlobalBool(MetricsEnableInfluxDBV2Flag.Name)
		)

		if enableExport || enableExportV2 {
			CheckExclusive(ctx, MetricsEnableInfluxDBFlag, MetricsEnableInfluxDBV2Flag)

			v1FlagIsSet := ctx.GlobalIsSet(MetricsInfluxDBUsernameFlag.Name) ||
				ctx.GlobalIsSet(MetricsInfluxDBPasswordFlag.Name)

			v2FlagIsSet := ctx.GlobalIsSet(MetricsInfluxDBTokenFlag.Name) ||
				ctx.GlobalIsSet(MetricsInfluxDBOrganizationFlag.Name) ||
				ctx.GlobalIsSet(MetricsInfluxDBBucketFlag.Name)

			if enableExport && v2FlagIsSet {
				Fatalf("Flags --influxdb.metrics.organization, --influxdb.metrics.token, --influxdb.metrics.bucket are only available for influxdb-v2")
			} else if enableExportV2 && v1FlagIsSet {
				Fatalf("Flags --influxdb.metrics.username, --influxdb.metrics.password are only available for influxdb-v1")
			}
		}

		var (
			endpoint = ctx.GlobalString(MetricsInfluxDBEndpointFlag.Name)
			database = ctx.GlobalString(MetricsInfluxDBDatabaseFlag.Name)
			username = ctx.GlobalString(MetricsInfluxDBUsernameFlag.Name)
			password = ctx.GlobalString(MetricsInfluxDBPasswordFlag.Name)

			token        = ctx.GlobalString(MetricsInfluxDBTokenFlag.Name)
			bucket       = ctx.GlobalString(MetricsInfluxDBBucketFlag.Name)
			organization = ctx.GlobalString(MetricsInfluxDBOrganizationFlag.Name)
		)

		if enableExport {
			tagsMap := SplitTagsFlag(ctx.GlobalString(MetricsInfluxDBTagsFlag.Name))

			logging.Info("Enabling metrics export to InfluxDB")

			go influxdb.InfluxDBWithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, database, username, password, "parallax.", tagsMap)
		} else if enableExportV2 {
			tagsMap := SplitTagsFlag(ctx.GlobalString(MetricsInfluxDBTagsFlag.Name))

			logging.Info("Enabling metrics export to InfluxDB (v2)")

			go influxdb.InfluxDBV2WithTags(metrics.DefaultRegistry, 10*time.Second, endpoint, token, bucket, organization, "parallax.", tagsMap)
		}

		if ctx.GlobalIsSet(MetricsHTTPFlag.Name) {
			address := fmt.Sprintf("%s:%d", ctx.GlobalString(MetricsHTTPFlag.Name), ctx.GlobalInt(MetricsPortFlag.Name))
			logging.Info("Enabling stand-alone metrics HTTP endpoint", "address", address)
			exp.Setup(address)
		}
	}
}

func SplitTagsFlag(tagsFlag string) map[string]string {
	tags := strings.Split(tagsFlag, ",")
	tagsMap := map[string]string{}

	for _, t := range tags {
		if t != "" {
			kv := strings.Split(t, "=")

			if len(kv) == 2 {
				tagsMap[kv[0]] = kv[1]
			}
		}
	}

	return tagsMap
}

// MakeChainDatabase open an LevelDB using the flags passed to the client and will hard crash if it fails.
func MakeChainDatabase(ctx *cli.Context, stack *node.Node, readonly bool) dbstore.Database {
	var (
		cache   = ctx.GlobalInt(CacheFlag.Name) * ctx.GlobalInt(CacheDatabaseFlag.Name) / 100
		handles = MakeDatabaseHandles(ctx.GlobalInt(FDLimitFlag.Name))

		err     error
		chainDb dbstore.Database
	)
	switch {
	case ctx.GlobalIsSet(RemoteDBFlag.Name):
		logging.Info("Using remote db", "url", ctx.GlobalString(RemoteDBFlag.Name))
		chainDb, err = remotedb.New(ctx.GlobalString(RemoteDBFlag.Name))
	default:
		chainDb, err = stack.OpenDatabaseWithFreezer("chaindata", cache, handles, ctx.GlobalString(AncientFlag.Name), "", readonly)
	}
	if err != nil {
		Fatalf("Could not open database: %v", err)
	}
	return chainDb
}

func MakeGenesis(ctx *cli.Context) *validation.Genesis {
	var genesis *validation.Genesis
	switch {
	case ctx.GlobalBool(MainnetFlag.Name):
		genesis = validation.DefaultGenesisBlock()
	case ctx.GlobalBool(TestnetFlag.Name):
		genesis = validation.DefaultTestnetGenesisBlock()
	case ctx.GlobalBool(DeveloperFlag.Name):
		Fatalf("Developer chains are ephemeral")
	}
	return genesis
}

// MakeChain creates a chain manager from set command line flags.
func MakeChain(ctx *cli.Context, stack *node.Node) (chain *validation.BlockChain, chainDb dbstore.Database) {
	var err error
	chainDb = MakeChainDatabase(ctx, stack, false) // TODO(rjl493456442) support read-only database
	config, _, err := validation.SetupGenesisBlock(chainDb, MakeGenesis(ctx))
	if err != nil {
		Fatalf("%v", err)
	}

	var engine kernel.Engine
	xhashConf := nodeconfig.Defaults.XHash
	if ctx.GlobalBool(FakePoWFlag.Name) {
		xhashConf.PowMode = xhash.ModeFake
	}
	engine = nodeconfig.CreateConsensusEngine(stack, config, &xhashConf, nil, false, chainDb)
	if gcmode := ctx.GlobalString(GCModeFlag.Name); gcmode != "full" && gcmode != "archive" {
		Fatalf("--%s must be either 'full' or 'archive'", GCModeFlag.Name)
	}
	cache := &validation.CacheConfig{
		TrieCleanLimit:      nodeconfig.Defaults.TrieCleanCache,
		TrieCleanNoPrefetch: ctx.GlobalBool(CacheNoPrefetchFlag.Name),
		TrieDirtyLimit:      nodeconfig.Defaults.TrieDirtyCache,
		TrieDirtyDisabled:   ctx.GlobalString(GCModeFlag.Name) == "archive",
		TrieTimeLimit:       nodeconfig.Defaults.TrieTimeout,
		SnapshotLimit:       nodeconfig.Defaults.SnapshotCache,
		Preimages:           ctx.GlobalBool(CachePreimagesFlag.Name),
	}
	if cache.TrieDirtyDisabled && !cache.Preimages {
		cache.Preimages = true
		logging.Info("Enabling recording of key preimages since archive mode is used")
	}
	if !ctx.GlobalBool(SnapshotFlag.Name) {
		cache.SnapshotLimit = 0 // Disabled
	}
	if ctx.GlobalIsSet(CacheFlag.Name) || ctx.GlobalIsSet(CacheTrieFlag.Name) {
		cache.TrieCleanLimit = ctx.GlobalInt(CacheFlag.Name) * ctx.GlobalInt(CacheTrieFlag.Name) / 100
	}
	if ctx.GlobalIsSet(CacheFlag.Name) || ctx.GlobalIsSet(CacheGCFlag.Name) {
		cache.TrieDirtyLimit = ctx.GlobalInt(CacheFlag.Name) * ctx.GlobalInt(CacheGCFlag.Name) / 100
	}
	vmcfg := script.Config{EnablePreimageRecording: ctx.GlobalBool(VMEnableDebugFlag.Name)}

	// TODO(rjl493456442) disable snapshot generation/wiping if the chain is read only.
	// Disable transaction indexing/unindexing by default.
	chain, err = validation.NewBlockChain(chainDb, cache, config, engine, vmcfg, nil, nil)
	if err != nil {
		Fatalf("Can't create BlockChain: %v", err)
	}
	return chain, chainDb
}

// MakeConsolePreloads retrieves the absolute paths for the console JavaScript
// scripts to preload before starting.
func MakeConsolePreloads(ctx *cli.Context) []string {
	// Skip preloading if there's nothing to preload
	if ctx.GlobalString(PreloadJSFlag.Name) == "" {
		return nil
	}
	// Otherwise resolve absolute paths and return them
	var preloads []string

	for _, file := range strings.Split(ctx.GlobalString(PreloadJSFlag.Name), ",") {
		preloads = append(preloads, strings.TrimSpace(file))
	}
	return preloads
}

// MigrateFlags sets the global flag from a local flag when it's set.
// This is a temporary function used for migrating old command/flags to the
// new format.
//
// e.g. parallax account new --keystore /tmp/mykeystore --lightkdf
//
// is equivalent after calling this method with:
//
// parallax --keystore /tmp/mykeystore --lightkdf account new
//
// This allows the use of the existing configuration functionality.
// When all flags are migrated this function can be removed and the existing
// configuration functionality must be changed that is uses local flags
func MigrateFlags(action func(ctx *cli.Context) error) func(*cli.Context) error {
	return func(ctx *cli.Context) error {
		for _, name := range ctx.FlagNames() {
			if ctx.IsSet(name) {
				ctx.GlobalSet(name, ctx.String(name))
			}
		}
		return action(ctx)
	}
}
