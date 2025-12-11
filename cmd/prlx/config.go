// Copyright 2017 The go-ethereum Authors
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
	"bufio"
	"errors"
	"fmt"
	"os"
	"reflect"
	"unicode"

	"gopkg.in/urfave/cli.v1"

	"github.com/ParallaxProtocol/parallax/accounts/external"
	"github.com/ParallaxProtocol/parallax/accounts/keystore"
	"github.com/ParallaxProtocol/parallax/accounts/scwallet"
	"github.com/ParallaxProtocol/parallax/accounts/usbwallet"
	"github.com/ParallaxProtocol/parallax/cmd/utils"
	"github.com/ParallaxProtocol/parallax/core/rawdb"
	"github.com/ParallaxProtocol/parallax/internal/prlapi"
	"github.com/ParallaxProtocol/parallax/log"
	"github.com/ParallaxProtocol/parallax/metrics"
	"github.com/ParallaxProtocol/parallax/node"
	"github.com/ParallaxProtocol/parallax/params"
	"github.com/ParallaxProtocol/parallax/prl/prlconfig"
	"github.com/naoina/toml"
)

var (
	dumpConfigCommand = cli.Command{
		Action:      utils.MigrateFlags(dumpConfig),
		Name:        "dumpconfig",
		Usage:       "Show configuration values",
		ArgsUsage:   "",
		Flags:       utils.GroupFlags(nodeFlags, rpcFlags),
		Category:    "MISCELLANEOUS COMMANDS",
		Description: `The dumpconfig command shows configuration values.`,
	}

	configFileFlag = cli.StringFlag{
		Name:  "config",
		Usage: "TOML configuration file",
	}
)

// These settings ensure that TOML keys use the same names as Go struct fields.
var tomlSettings = toml.Config{
	NormFieldName: func(rt reflect.Type, key string) string {
		return key
	},
	FieldToKey: func(rt reflect.Type, field string) string {
		return field
	},
	MissingField: func(rt reflect.Type, field string) error {
		id := fmt.Sprintf("%s.%s", rt.String(), field)
		if deprecated(id) {
			log.Warn("Config field is deprecated and won't have an effect", "name", id)
			return nil
		}
		var link string
		if unicode.IsUpper(rune(rt.Name()[0])) && rt.PkgPath() != "main" {
			link = fmt.Sprintf(", see https://godoc.org/%s#%s for available fields", rt.PkgPath(), rt.Name())
		}
		return fmt.Errorf("field '%s' is not defined in %s%s", field, rt.String(), link)
	},
}

type prlstatsConfig struct {
	URL string `toml:",omitempty"`
}

type prlxConfig struct {
	Parallax      prlconfig.Config
	Node          node.Config
	ParallaxStats prlstatsConfig
	Metrics       metrics.Config
}

func loadConfig(file string, cfg *prlxConfig) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	err = tomlSettings.NewDecoder(bufio.NewReader(f)).Decode(cfg)
	// Add file name to errors that have a line number.
	if _, ok := err.(*toml.LineError); ok {
		err = errors.New(file + ", " + err.Error())
	}
	return err
}

func defaultNodeConfig() node.Config {
	cfg := node.DefaultConfig
	cfg.Name = clientIdentifier
	cfg.Version = params.VersionWithCommit(gitCommit, gitDate)
	cfg.HTTPModules = append(cfg.HTTPModules, "eth")
	cfg.WSModules = append(cfg.WSModules, "eth")
	cfg.IPCPath = "prlx.ipc"
	return cfg
}

// makeConfigNode loads geth configuration and creates a blank node instance.
func makeConfigNode(ctx *cli.Context) (*node.Node, prlxConfig) {
	// Load defaults.
	cfg := prlxConfig{
		Parallax: prlconfig.Defaults,
		Node:     defaultNodeConfig(),
		Metrics:  metrics.DefaultConfig,
	}

	// Load config file.
	if file := ctx.GlobalString(configFileFlag.Name); file != "" {
		if err := loadConfig(file, &cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}

	// Apply flags.
	utils.SetNodeConfig(ctx, &cfg.Node)
	stack, err := node.New(&cfg.Node)
	if err != nil {
		utils.Fatalf("Failed to create the protocol stack: %v", err)
	}
	// Node doesn't by default populate account manager backends
	if err := setAccountManagerBackends(stack); err != nil {
		utils.Fatalf("Failed to set account manager backends: %v", err)
	}

	utils.SetPrlConfig(ctx, stack, &cfg.Parallax)
	if ctx.GlobalIsSet(utils.PrlStatsURLFlag.Name) {
		cfg.ParallaxStats.URL = ctx.GlobalString(utils.PrlStatsURLFlag.Name)
	}
	applyMetricConfig(ctx, &cfg)

	return stack, cfg
}

// makeFullNode loads geth configuration and creates the Parallax backend.
func makeFullNode(ctx *cli.Context) (*node.Node, prlapi.Backend) {
	stack, cfg := makeConfigNode(ctx)
	backend, parallax := utils.RegisterParallaxService(stack, &cfg.Parallax)
	// Warn users to migrate if they have a legacy freezer format.
	if parallax != nil {
		firstIdx := uint64(0)
		// Hack to speed up check for mainnet because we know
		// the first non-empty block.
		ghash := rawdb.ReadCanonicalHash(parallax.ChainDb(), 0)
		if cfg.Parallax.NetworkId == 2110 && ghash == params.MainnetGenesisHash {
			firstIdx = 7661
		}
		isLegacy, _, err := dbHasLegacyReceipts(parallax.ChainDb(), firstIdx)
		if err != nil {
			log.Error("Failed to check db for legacy receipts", "err", err)
		} else if isLegacy {
			log.Warn("Database has receipts with a legacy format. Please run `prlx db freezer-migrate`.")
		}
	}

	// Configure GraphQL if requested
	if ctx.GlobalIsSet(utils.GraphQLEnabledFlag.Name) {
		utils.RegisterGraphQLService(stack, backend, cfg.Node)
	}
	// Add the Parallax Stats daemon if requested.
	if cfg.ParallaxStats.URL != "" {
		utils.RegisterPrlStatsService(stack, backend, cfg.ParallaxStats.URL)
	}
	return stack, backend
}

// dumpConfig is the dumpconfig command.
func dumpConfig(ctx *cli.Context) error {
	_, cfg := makeConfigNode(ctx)
	comment := ""

	if cfg.Parallax.Genesis != nil {
		cfg.Parallax.Genesis = nil
		comment += "# Note: this config doesn't contain the genesis block.\n\n"
	}

	out, err := tomlSettings.Marshal(&cfg)
	if err != nil {
		return err
	}

	dump := os.Stdout
	if ctx.NArg() > 0 {
		dump, err = os.OpenFile(ctx.Args().Get(0), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		defer dump.Close()
	}
	dump.WriteString(comment)
	dump.Write(out)

	return nil
}

func applyMetricConfig(ctx *cli.Context, cfg *prlxConfig) {
	if ctx.GlobalIsSet(utils.MetricsEnabledFlag.Name) {
		cfg.Metrics.Enabled = ctx.GlobalBool(utils.MetricsEnabledFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsEnabledExpensiveFlag.Name) {
		cfg.Metrics.EnabledExpensive = ctx.GlobalBool(utils.MetricsEnabledExpensiveFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsHTTPFlag.Name) {
		cfg.Metrics.HTTP = ctx.GlobalString(utils.MetricsHTTPFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsPortFlag.Name) {
		cfg.Metrics.Port = ctx.GlobalInt(utils.MetricsPortFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsEnableInfluxDBFlag.Name) {
		cfg.Metrics.EnableInfluxDB = ctx.GlobalBool(utils.MetricsEnableInfluxDBFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBEndpointFlag.Name) {
		cfg.Metrics.InfluxDBEndpoint = ctx.GlobalString(utils.MetricsInfluxDBEndpointFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBDatabaseFlag.Name) {
		cfg.Metrics.InfluxDBDatabase = ctx.GlobalString(utils.MetricsInfluxDBDatabaseFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBUsernameFlag.Name) {
		cfg.Metrics.InfluxDBUsername = ctx.GlobalString(utils.MetricsInfluxDBUsernameFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBPasswordFlag.Name) {
		cfg.Metrics.InfluxDBPassword = ctx.GlobalString(utils.MetricsInfluxDBPasswordFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBTagsFlag.Name) {
		cfg.Metrics.InfluxDBTags = ctx.GlobalString(utils.MetricsInfluxDBTagsFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsEnableInfluxDBV2Flag.Name) {
		cfg.Metrics.EnableInfluxDBV2 = ctx.GlobalBool(utils.MetricsEnableInfluxDBV2Flag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBTokenFlag.Name) {
		cfg.Metrics.InfluxDBToken = ctx.GlobalString(utils.MetricsInfluxDBTokenFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBBucketFlag.Name) {
		cfg.Metrics.InfluxDBBucket = ctx.GlobalString(utils.MetricsInfluxDBBucketFlag.Name)
	}
	if ctx.GlobalIsSet(utils.MetricsInfluxDBOrganizationFlag.Name) {
		cfg.Metrics.InfluxDBOrganization = ctx.GlobalString(utils.MetricsInfluxDBOrganizationFlag.Name)
	}
}

func deprecated(field string) bool {
	switch field {
	case "prlconfig.Config.PVMInterpreter":
		return true
	case "prlconfig.Config.EWASMInterpreter":
		return true
	default:
		return false
	}
}

func setAccountManagerBackends(stack *node.Node) error {
	conf := stack.Config()
	am := stack.AccountManager()
	keydir := stack.KeyStoreDir()
	scryptN := keystore.StandardScryptN
	scryptP := keystore.StandardScryptP
	if conf.UseLightweightKDF {
		scryptN = keystore.LightScryptN
		scryptP = keystore.LightScryptP
	}

	// Assemble the supported backends
	if len(conf.ExternalSigner) > 0 {
		log.Info("Using external signer", "url", conf.ExternalSigner)
		if extapi, err := external.NewExternalBackend(conf.ExternalSigner); err == nil {
			am.AddBackend(extapi)
			return nil
		} else {
			return fmt.Errorf("error connecting to external signer: %v", err)
		}
	}

	// For now, we're using EITHER external signer OR local signers.
	// If/when we implement some form of lockfile for USB and keystore wallets,
	// we can have both, but it's very confusing for the user to see the same
	// accounts in both externally and locally, plus very racey.
	am.AddBackend(keystore.NewKeyStore(keydir, scryptN, scryptP))
	if conf.USB {
		// Start a USB hub for Ledger hardware wallets
		if ledgerhub, err := usbwallet.NewLedgerHub(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start Ledger hub, disabling: %v", err))
		} else {
			am.AddBackend(ledgerhub)
		}
		// Start a USB hub for Trezor hardware wallets (HID version)
		if trezorhub, err := usbwallet.NewTrezorHubWithHID(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start HID Trezor hub, disabling: %v", err))
		} else {
			am.AddBackend(trezorhub)
		}
		// Start a USB hub for Trezor hardware wallets (WebUSB version)
		if trezorhub, err := usbwallet.NewTrezorHubWithWebUSB(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start WebUSB Trezor hub, disabling: %v", err))
		} else {
			am.AddBackend(trezorhub)
		}
	}
	if len(conf.SmartCardDaemonPath) > 0 {
		// Start a smart card hub
		if schub, err := scwallet.NewHub(conf.SmartCardDaemonPath, scwallet.Scheme, keydir); err != nil {
			log.Warn(fmt.Sprintf("Failed to start smart card hub, disabling: %v", err))
		} else {
			am.AddBackend(schub)
		}
	}

	return nil
}
