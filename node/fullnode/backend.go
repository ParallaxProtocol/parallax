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

// Package prl implements the Parallax protocol.
package protocol

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	parallax "github.com/ParallaxProtocol/parallax/v2"
	"github.com/ParallaxProtocol/parallax/v2/dbstore"
	"github.com/ParallaxProtocol/parallax/v2/internal/api"
	"github.com/ParallaxProtocol/parallax/v2/internal/shutdowncheck"
	"github.com/ParallaxProtocol/parallax/v2/kernel"
	"github.com/ParallaxProtocol/parallax/v2/kernel/chainparams"
	"github.com/ParallaxProtocol/parallax/v2/kernel/clique"
	"github.com/ParallaxProtocol/parallax/v2/kernel/xhash"
	"github.com/ParallaxProtocol/parallax/v2/logging"
	"github.com/ParallaxProtocol/parallax/v2/node"
	"github.com/ParallaxProtocol/parallax/v2/node/filters"
	"github.com/ParallaxProtocol/parallax/v2/node/fullnode/downloader"
	"github.com/ParallaxProtocol/parallax/v2/node/miner"
	"github.com/ParallaxProtocol/parallax/v2/node/nodeconfig"
	"github.com/ParallaxProtocol/parallax/v2/p2p"
	"github.com/ParallaxProtocol/parallax/v2/p2p/dnsdisc"
	"github.com/ParallaxProtocol/parallax/v2/p2p/enode"
	"github.com/ParallaxProtocol/parallax/v2/p2p/netparams"
	"github.com/ParallaxProtocol/parallax/v2/p2p/protocols/prl"
	"github.com/ParallaxProtocol/parallax/v2/p2p/protocols/snap"
	"github.com/ParallaxProtocol/parallax/v2/policy/fees"
	"github.com/ParallaxProtocol/parallax/v2/primitives/rlp"
	"github.com/ParallaxProtocol/parallax/v2/primitives/types"
	"github.com/ParallaxProtocol/parallax/v2/rpc"
	"github.com/ParallaxProtocol/parallax/v2/script"
	"github.com/ParallaxProtocol/parallax/v2/support/event"
	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/util/hexutil"
	"github.com/ParallaxProtocol/parallax/v2/validation"
	"github.com/ParallaxProtocol/parallax/v2/validation/bloombits"
	"github.com/ParallaxProtocol/parallax/v2/validation/rawdb"
	"github.com/ParallaxProtocol/parallax/v2/validation/state/pruner"
	"github.com/ParallaxProtocol/parallax/v2/wallet"
)

// Config contains the configuration options of the Parallax protocol.
// Deprecated: use prlconfig.Config instead.
type Config = nodeconfig.Config

// Parallax implements the Parallax full node service.
type Parallax struct {
	config *nodeconfig.Config

	// Handlers
	txPool             *validation.TxPool
	blockchain         *validation.BlockChain
	handler            *handler
	prlDialCandidates  enode.Iterator
	snapDialCandidates enode.Iterator

	// DB interfaces
	chainDb dbstore.Database // Block chain database

	eventMux       *event.TypeMux
	engine         kernel.Engine
	accountManager *wallet.Manager

	bloomRequests     chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer      *validation.ChainIndexer       // Bloom indexer operating during block imports
	closeBloomHandler chan struct{}

	APIBackend *PrlAPIBackend

	miner    *miner.Miner
	gasPrice *big.Int
	coinbase util.Address

	networkID     uint64
	netRPCService *api.PublicNetAPI

	p2pServer *p2p.Server

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and coinbase)

	shutdownTracker *shutdowncheck.ShutdownTracker // Tracks if and when the node has shutdown ungracefully
}

// New creates a new Parallax object (including the
// initialisation of the common Parallax object)
func New(stack *node.Node, config *nodeconfig.Config) (*Parallax, error) {
	// Ensure configuration values are compatible and sane
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run Parallax in light sync mode, use LightParallax")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Cmp(util.Big0) <= 0 {
		logging.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", nodeconfig.Defaults.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(nodeconfig.Defaults.Miner.GasPrice)
	}
	if config.NoPruning && config.TrieDirtyCache > 0 {
		if config.SnapshotCache > 0 {
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}
	logging.Info("Allocated trie memory caches", "clean", util.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", util.StorageSize(config.TrieDirtyCache)*1024*1024)

	// Transfer mining-related config to the xhash config.
	xhashConfig := config.XHash
	xhashConfig.NotifyFull = config.Miner.NotifyFull

	// Assemble the Parallax object
	chainDb, err := stack.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "parallax/db/chaindata/", false)
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := validation.SetupGenesisBlockWithOverride(chainDb, config.Genesis)
	if _, ok := genesisErr.(*chainparams.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	logging.Info("Initialised chain configuration", "config", chainConfig)

	if err := pruner.RecoverPruning(stack.ResolvePath(""), chainDb, stack.ResolvePath(config.TrieCleanCacheJournal)); err != nil {
		logging.Error("Failed to recover state", "error", err)
	}
	prl := &Parallax{
		config:            config,
		chainDb:           chainDb,
		eventMux:          stack.EventMux(),
		accountManager:    stack.AccountManager(),
		engine:            nodeconfig.CreateConsensusEngine(stack, chainConfig, &xhashConfig, config.Miner.Notify, config.Miner.Noverify, chainDb),
		closeBloomHandler: make(chan struct{}),
		networkID:         config.NetworkId,
		gasPrice:          config.Miner.GasPrice,
		coinbase:          config.Miner.Coinbase,
		bloomRequests:     make(chan chan *bloombits.Retrieval),
		bloomIndexer:      validation.NewBloomIndexer(chainDb, netparams.BloomBitsBlocks, netparams.BloomConfirms),
		p2pServer:         stack.Server(),
		shutdownTracker:   shutdowncheck.NewShutdownTracker(chainDb),
	}

	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	dbVer := "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	logging.Info("Initialising Parallax protocol", "network", config.NetworkId, "dbversion", dbVer)

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > validation.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Parallax %s only supports v%d", *bcVersion, parallax.VersionWithMeta, validation.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < validation.BlockChainVersion {
			if bcVersion != nil { // only print warning on upgrade, not on init
				logging.Warn("Upgrade blockchain database version", "from", dbVer, "to", validation.BlockChainVersion)
			}
			rawdb.WriteDatabaseVersion(chainDb, validation.BlockChainVersion)
		}
	}
	var (
		vmConfig = script.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
		}
		cacheConfig = &validation.CacheConfig{
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanJournal:    stack.ResolvePath(config.TrieCleanCacheJournal),
			TrieCleanRejournal:  config.TrieCleanCacheRejournal,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieDirtyDisabled:   config.NoPruning,
			TrieTimeLimit:       config.TrieTimeout,
			SnapshotLimit:       config.SnapshotCache,
			Preimages:           config.Preimages,
		}
	)
	prl.blockchain, err = validation.NewBlockChain(chainDb, cacheConfig, chainConfig, prl.engine, vmConfig, prl.shouldPreserve, &config.TxLookupLimit)
	if err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*chainparams.ConfigCompatError); ok {
		logging.Warn("Rewinding chain to upgrade configuration", "err", compat)
		prl.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	prl.bloomIndexer.Start(prl.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = stack.ResolvePath(config.TxPool.Journal)
	}
	prl.txPool = validation.NewTxPool(config.TxPool, chainConfig, prl.blockchain)

	// Permit the downloader to use the trie cache allowance during fast sync
	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit + cacheConfig.SnapshotLimit
	checkpoint := config.Checkpoint
	if checkpoint == nil {
		checkpoint = chainparams.TrustedCheckpoints[genesisHash]
	}
	if prl.handler, err = newHandler(&handlerConfig{
		Database:       chainDb,
		Chain:          prl.blockchain,
		TxPool:         prl.txPool,
		Network:        config.NetworkId,
		Sync:           config.SyncMode,
		BloomCache:     uint64(cacheLimit),
		EventMux:       prl.eventMux,
		Checkpoint:     checkpoint,
		RequiredBlocks: config.RequiredBlocks,
	}); err != nil {
		return nil, err
	}

	prl.miner = miner.New(prl, &config.Miner, chainConfig, prl.EventMux(), prl.engine, prl.isLocalBlock)
	prl.miner.SetExtra(makeExtraData(config.Miner.ExtraData))

	prl.APIBackend = &PrlAPIBackend{stack.Config().ExtRPCEnabled(), stack.Config().AllowUnprotectedTxs, prl, nil}
	if prl.APIBackend.allowUnprotectedTxs {
		logging.Info("Unprotected transactions allowed")
	}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.Miner.GasPrice
	}
	prl.APIBackend.gpo = fees.NewOracle(prl.APIBackend, prl.txPool, gpoParams)

	// Setup DNS discovery iterators.
	dnsclient := dnsdisc.NewClient(dnsdisc.Config{})
	prl.prlDialCandidates, err = dnsclient.NewIterator(prl.config.ParallaxDiscoveryURLs...)
	if err != nil {
		return nil, err
	}
	prl.snapDialCandidates, err = dnsclient.NewIterator(prl.config.SnapDiscoveryURLs...)
	if err != nil {
		return nil, err
	}

	// Start the RPC service
	prl.netRPCService = api.NewPublicNetAPI(prl.p2pServer, config.NetworkId)

	// Register the backend on the node
	stack.RegisterAPIs(prl.APIs())
	stack.RegisterProtocols(prl.Protocols())
	stack.RegisterLifecycle(prl)

	// Successful startup; push a marker and check previous unclean shutdowns.
	prl.shutdownTracker.MarkStartup()

	return prl, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]any{
			uint(parallax.VersionMajor<<16 | parallax.VersionMinor<<8 | parallax.VersionPatch),
			"parallax",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > chainparams.MaximumExtraDataSize {
		logging.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", chainparams.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// APIs return the collection of RPC services the parallax package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Parallax) APIs() []rpc.API {
	apis := api.GetAPIs(s.APIBackend)

	// Append consensus engine APIs based on engine type
	switch e := s.engine.(type) {
	case *xhash.XHash:
		api := xhash.NewAPI(s.BlockChain(), e)
		apis = append(apis, rpc.API{Namespace: "eth", Version: "1.0", Service: api, Public: true})
		apis = append(apis, rpc.API{Namespace: "xhash", Version: "1.0", Service: api, Public: true})
	case *clique.Clique:
		apis = append(apis, rpc.API{Namespace: "clique", Version: "1.0", Service: api.NewCliqueAPI(s.BlockChain(), e), Public: false})
	}

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicParallaxAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.handler.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false, 5*time.Minute, s.config.LogQueryLimit, s.config.RangeLimit),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Parallax) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Parallax) Coinbase() (eb util.Address, err error) {
	s.lock.RLock()
	coinbase := s.coinbase
	s.lock.RUnlock()

	if coinbase != (util.Address{}) {
		return coinbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			coinbase := accounts[0].Address

			s.lock.Lock()
			s.coinbase = coinbase
			s.lock.Unlock()

			logging.Info("Coinbase automatically configured", "address", coinbase)
			return coinbase, nil
		}
	}
	return util.Address{}, fmt.Errorf("coinbase must be explicitly specified")
}

// isLocalBlock checks whether the specified block is mined
// by local miner accounts.
//
// We regard two types of accounts as local miner account: coinbase
// and accounts specified via `txpool.locals` flag.
func (s *Parallax) isLocalBlock(header *types.Header) bool {
	author, err := s.engine.Author(header)
	if err != nil {
		logging.Warn("Failed to retrieve block author", "number", header.Number.Uint64(), "hash", header.Hash(), "err", err)
		return false
	}
	// Check whether the given address is coinbase.
	s.lock.RLock()
	coinbase := s.coinbase
	s.lock.RUnlock()
	if author == coinbase {
		return true
	}
	// Check whether the given address is specified by `txpool.local`
	// CLI flag.
	for _, account := range s.config.TxPool.Locals {
		if account == author {
			return true
		}
	}
	return false
}

// shouldPreserve checks whether we should preserve the given block
// during the chain reorg depending on whether the author of block
// is a local account.
func (s *Parallax) shouldPreserve(header *types.Header) bool {
	// The reason we need to disable the self-reorg preserving for clique
	// is it can be probable to introduce a deadlock.
	//
	// e.g. If there are 7 available signers
	//
	// r1   A
	// r2     B
	// r3       C
	// r4         D
	// r5   A      [X] F G
	// r6    [X]
	//
	// In the round5, the inturn signer E is offline, so the worst case
	// is A, F and G sign the block of round5 and reject the block of opponents
	// and in the round6, the last available signer B is offline, the whole
	// network is stuck.
	if _, ok := s.engine.(*clique.Clique); ok {
		return false
	}
	return s.isLocalBlock(header)
}

// SetCoinbase sets the mining reward address.
func (s *Parallax) SetCoinbase(coinbase util.Address) {
	s.lock.Lock()
	s.coinbase = coinbase
	s.lock.Unlock()

	s.miner.SetCoinbase(coinbase)
}

// StartMining starts the miner with the given number of CPU threads. If mining
// is already running, this method adjust the number of threads allowed to use
// and updates the minimum price required by the transaction pool.
func (s *Parallax) StartMining(threads int) error {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		logging.Info("Updated mining threads", "threads", threads)
		if threads == 0 {
			threads = -1 // Disable the miner from within
		}
		th.SetThreads(threads)
	}
	// If the miner was not running, initialize it
	if !s.IsMining() {
		// Propagate the initial price point to the transaction pool
		s.lock.RLock()
		price := s.gasPrice
		s.lock.RUnlock()
		s.txPool.SetGasPrice(price)

		// Configure the local mining address
		eb, err := s.Coinbase()
		if err != nil {
			logging.Error("Cannot start mining without coinbase", "err", err)
			return fmt.Errorf("coinbase missing: %v", err)
		}
		var cli *clique.Clique
		if c, ok := s.engine.(*clique.Clique); ok {
			cli = c
		}
		if cli != nil {
			w, err := s.accountManager.Find(wallet.Account{Address: eb})
			if w == nil || err != nil {
				logging.Error("Coinbase account unavailable locally", "err", err)
				return fmt.Errorf("signer missing: %v", err)
			}
			cli.Authorize(eb, func(addr util.Address, msg []byte) ([]byte, error) {
				return w.SignData(wallet.Account{Address: addr}, wallet.MimetypeClique, msg)
			})
		}
		// If mining is started, we can disable the transaction rejection mechanism
		// introduced to speed sync times.
		atomic.StoreUint32(&s.handler.acceptTxs, 1)

		go s.miner.Start(eb)
	}
	return nil
}

// StopMining terminates the miner, both at the consensus engine level as well as
// at the block creation level.
func (s *Parallax) StopMining() {
	// Update the thread count within the consensus engine
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := s.engine.(threaded); ok {
		th.SetThreads(-1)
	}
	// Stop the block creating itself
	s.miner.Stop()
}

func (s *Parallax) IsMining() bool      { return s.miner.Mining() }
func (s *Parallax) Miner() *miner.Miner { return s.miner }

func (s *Parallax) AccountManager() *wallet.Manager        { return s.accountManager }
func (s *Parallax) BlockChain() *validation.BlockChain     { return s.blockchain }
func (s *Parallax) TxPool() *validation.TxPool             { return s.txPool }
func (s *Parallax) EventMux() *event.TypeMux               { return s.eventMux }
func (s *Parallax) Engine() kernel.Engine                  { return s.engine }
func (s *Parallax) ChainDb() dbstore.Database              { return s.chainDb }
func (s *Parallax) IsListening() bool                      { return true } // Always listening
func (s *Parallax) Downloader() *downloader.Downloader     { return s.handler.downloader }
func (s *Parallax) Synced() bool                           { return atomic.LoadUint32(&s.handler.acceptTxs) == 1 }
func (s *Parallax) SetSynced()                             { atomic.StoreUint32(&s.handler.acceptTxs, 1) }
func (s *Parallax) ArchiveMode() bool                      { return s.config.NoPruning }
func (s *Parallax) BloomIndexer() *validation.ChainIndexer { return s.bloomIndexer }
func (s *Parallax) SyncMode() downloader.SyncMode {
	mode, _ := s.handler.chainSync.modeAndLocalHead()
	return mode
}

// Protocols returns all the currently configured
// network protocols to start.
func (s *Parallax) Protocols() []p2p.Protocol {
	protos := prl.MakeProtocols((*prlHandler)(s.handler), s.networkID, s.prlDialCandidates)
	if s.config.SnapshotCache > 0 {
		protos = append(protos, snap.MakeProtocols((*snapHandler)(s.handler), s.snapDialCandidates)...)
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Parallax protocol implementation.
func (s *Parallax) Start() error {
	prl.StartENRUpdater(s.blockchain, s.p2pServer.LocalNode())

	// Start the bloom bits servicing goroutines
	s.startBloomHandlers(netparams.BloomBitsBlocks)

	// Regularly update shutdown marker
	s.shutdownTracker.Start()

	// Start the networking layer
	s.handler.Start(s.p2pServer.MaxPeers)
	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Parallax protocol.
func (s *Parallax) Stop() error {
	// Stop all the peer-related stuff first.
	s.prlDialCandidates.Close()
	s.snapDialCandidates.Close()
	s.handler.Stop()

	// Then stop everything else.
	s.APIBackend.gpo.Close()
	s.bloomIndexer.Close()
	close(s.closeBloomHandler)
	s.txPool.Stop()
	s.miner.Close()
	s.blockchain.Stop()
	s.engine.Close()

	// Clean shutdown marker as the last thing before closing db
	s.shutdownTracker.Stop()

	s.chainDb.Close()
	s.eventMux.Stop()

	return nil
}
