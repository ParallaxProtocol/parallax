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

// Package prlconfig contains the configuration of the Parallax protocol.
package nodeconfig

import (
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ParallaxProtocol/parallax/v2/dbstore"
	"github.com/ParallaxProtocol/parallax/v2/kernel"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/kernel/clique"
	"github.com/ParallaxProtocol/parallax/v2/kernel/xhash"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/node"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/downloader"
	"github.com/ParallaxProtocol/parallax/v2/node/miner"
	"github.com/ParallaxProtocol/parallax/v2/policy/fees"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/validation"
)

// FullNodeGPO contains default gasprice oracle settings for full node.
var FullNodeGPO = fees.Config{
	Blocks:                  20,
	Percentile:              60,
	MaxHeaderHistory:        1024,
	MaxBlockHistory:         1024,
	MaxPrice:                fees.DefaultMaxPrice,
	IgnorePrice:             fees.DefaultIgnorePrice,
	EnableSmartFeeEstimator: true,
}

// Note: The new Bitcoin Core-style fee estimation fields (NumBuckets, BucketMultiplier,
// MinBucketFee, MaxConfTarget, SuccessThreshold, ShortDecay, MediumDecay, LongDecay)
// use sensible defaults defined in the gasprice package when left at zero values.

// Defaults contains default settings for use on the Parallax main net.
var Defaults = Config{
	SyncMode: downloader.SnapSync,
	XHash: xhash.Config{
		CacheDir:         "xhash",
		CachesInMem:      2,
		CachesOnDisk:     3,
		CachesLockMmap:   false,
		DatasetsInMem:    1,
		DatasetsOnDisk:   2,
		DatasetsLockMmap: false,
	},
	NetworkId:               2110,
	TxLookupLimit:           52560,
	DatabaseCache:           512,
	TrieCleanCache:          154,
	TrieCleanCacheJournal:   "triecache",
	TrieCleanCacheRejournal: 60 * time.Minute,
	TrieDirtyCache:          256,
	TrieTimeout:             60 * time.Minute,
	SnapshotCache:           102,
	Miner: miner.Config{
		GasCeil:  600000000,
		GasPrice: big.NewInt(chainparams.GWei),
		Recommit: 20 * time.Second,
	},
	TxPool:        validation.DefaultTxPoolConfig,
	RPCGasCap:     600000000,
	RPCPVMTimeout: 5 * time.Second,
	GPO:           FullNodeGPO,
	RPCTxFeeCap:   1,
	LogQueryLimit: 1000,
}

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
	if runtime.GOOS == "darwin" {
		Defaults.XHash.DatasetDir = filepath.Join(home, "Library", "XHash")
	} else if runtime.GOOS == "windows" {
		localappdata := os.Getenv("LOCALAPPDATA")
		if localappdata != "" {
			Defaults.XHash.DatasetDir = filepath.Join(localappdata, "XHash")
		} else {
			Defaults.XHash.DatasetDir = filepath.Join(home, "AppData", "Local", "XHash")
		}
	} else {
		Defaults.XHash.DatasetDir = filepath.Join(home, ".xhash")
	}
}

//go:generate go run github.com/fjl/gencodec -type Config -formats toml -out gen_config.go

// Config contains configuration options for the Parallax protocol.
type Config struct {
	// The genesis block, which is inserted if the database is empty.
	// If nil, the Parallax main net block is used.
	Genesis *validation.Genesis `toml:",omitempty"`

	// Protocol options
	NetworkId uint64 // Network ID to use for selecting peers to connect to
	SyncMode  downloader.SyncMode

	// This can be set to list of enrtree:// URLs which will be queried for
	// for nodes to connect to.
	ParallaxDiscoveryURLs []string
	SnapDiscoveryURLs     []string

	NoPruning  bool // Whether to disable pruning and flush everything to disk
	NoPrefetch bool // Whether to disable prefetching and only load state on demand

	TxLookupLimit uint64 `toml:",omitempty"` // The maximum number of blocks from head whose tx indices are reserved.

	// RequiredBlocks is a set of block number -> hash mappings which must be in the
	// canonical chain of all remote peers. Setting the option makes geth verify the
	// presence of these blocks for every new peer connection.
	RequiredBlocks map[uint64]util.Hash `toml:"-"`

	// Light client options
	SyncFromCheckpoint bool `toml:",omitempty"` // Whether to sync the header chain from the configured checkpoint

	// Ultra Light client options

	// Database options
	SkipBcVersionCheck bool `toml:"-"`
	DatabaseHandles    int  `toml:"-"`
	DatabaseCache      int
	DatabaseFreezer    string

	TrieCleanCache          int
	TrieCleanCacheJournal   string        `toml:",omitempty"` // Disk journal directory for trie cache to survive node restarts
	TrieCleanCacheRejournal time.Duration `toml:",omitempty"` // Time interval to regenerate the journal for clean cache
	TrieDirtyCache          int
	TrieTimeout             time.Duration
	SnapshotCache           int
	Preimages               bool

	// Mining options
	Miner miner.Config

	// XHash options
	XHash xhash.Config

	// Transaction pool options
	TxPool validation.TxPoolConfig

	// Gas Price Oracle options
	GPO fees.Config

	// Enables tracking of SHA3 preimages in the VM
	EnablePreimageRecording bool

	// Miscellaneous options
	DocRoot string `toml:"-"`

	// RPCGasCap is the global gas cap for eth-call variants.
	RPCGasCap uint64

	// RPCPVMTimeout is the global timeout for eth-call.
	RPCPVMTimeout time.Duration

	// RPCTxFeeCap is the global transaction fee(price * gaslimit) cap for
	// send-transction variants. The unit is laxes.
	RPCTxFeeCap float64

	// LogQueryLimit is the maximum number of addresses or topics allowed per
	// search position in log filter criteria (0 = no cap).
	LogQueryLimit int

	// Checkpoint is a hardcoded checkpoint which can be nil.
	Checkpoint *chainparams.TrustedCheckpoint `toml:",omitempty"`

	// CheckpointOracle is the configuration for checkpoint oracle.
	CheckpointOracle *chainparams.CheckpointOracleConfig `toml:",omitempty"`
}

// CreateConsensusEngine creates a consensus engine for the given chain configuration.
func CreateConsensusEngine(stack *node.Node, chainConfig *chainparams.ChainConfig, config *xhash.Config, notify []string, noverify bool, db dbstore.Database) kernel.Engine {
	// If proof-of-authority is requested, set it up
	var engine kernel.Engine
	if chainConfig.Clique != nil {
		engine = clique.New(chainConfig.Clique, db)
	} else {
		switch config.PowMode {
		case xhash.ModeFake:
			logging.Warn("XHash used in fake mode")
		case xhash.ModeTest:
			logging.Warn("XHash used in test mode")
		case xhash.ModeShared:
			logging.Warn("XHash used in shared mode")
		}
		engine = xhash.New(xhash.Config{
			PowMode:          config.PowMode,
			CacheDir:         stack.ResolvePath(config.CacheDir),
			CachesInMem:      config.CachesInMem,
			CachesOnDisk:     config.CachesOnDisk,
			CachesLockMmap:   config.CachesLockMmap,
			DatasetDir:       config.DatasetDir,
			DatasetsInMem:    config.DatasetsInMem,
			DatasetsOnDisk:   config.DatasetsOnDisk,
			DatasetsLockMmap: config.DatasetsLockMmap,
			NotifyFull:       config.NotifyFull,
		}, notify, noverify)
		engine.(*xhash.XHash).SetThreads(-1) // Disable CPU mining
	}
	return engine
}
