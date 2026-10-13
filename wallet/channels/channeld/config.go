// Package channeld composes the channel subsystem — proof store, protocol
// engine, relay pool, transmitter, chain watchers — into one runnable node
// shared by the wallet CLI verbs and the headless daemons (Part 3 §1).
package channeld

import (
	"fmt"
	"math/big"
	"os"

	"github.com/naoina/toml"

	"github.com/ParallaxProtocol/parallax/v2/util"
	"github.com/ParallaxProtocol/parallax/v2/wallet/channels/protocol"
)

// Config is the TOML configuration (Part 3 §11).
type Config struct {
	Node struct {
		RPC           string `toml:"rpc"`
		Confirmations uint64 `toml:"confirmations"`
	} `toml:"node"`

	// Registries maps a version label ("v1", …) to deployments; multiple
	// entries mean registry versions coexist (Part 1 §14).
	Registries map[string][]RegistryEntry `toml:"registries"`

	Nostr struct {
		Relays       []string `toml:"relays"`
		Use10050     bool     `toml:"use_10050"`
		Publish10050 bool     `toml:"publish_10050"`
	} `toml:"nostr"`

	Channels struct {
		DefaultChallengePeriod   uint32 `toml:"default_challenge_period"`
		AcceptChallengePeriodMin uint32 `toml:"accept_challenge_period_min"`
		AcceptChallengePeriodMax uint32 `toml:"accept_challenge_period_max"`
		CoopCloseValidityBlocks  uint64 `toml:"coop_close_validity_blocks"`
		CoopCloseHorizonBlocks   uint64 `toml:"coop_close_horizon_blocks"`
		WithdrawValidityBlocks   uint64 `toml:"withdraw_validity_blocks"`
		MaxInflightPaymentWei    string `toml:"max_inflight_payment_wei"` // "0" = unlimited

		// Towers to delegate every completed state to (client side).
		Towers struct {
			Npubs []string `toml:"npubs"`
		} `toml:"towers"`
	} `toml:"channels"`

	Backup struct {
		Enabled bool     `toml:"enabled"`
		Relays  []string `toml:"relays"`
	} `toml:"backup"`

	Merchant struct {
		Listen            string `toml:"listen"`
		AuthTokenFile     string `toml:"auth_token_file"`
		WebhookURL        string `toml:"webhook_url"`
		PushPayments      bool   `toml:"push_payments"`
		SweepThresholdWei string `toml:"sweep_threshold_wei"`
	} `toml:"merchant"`

	Tower struct {
		Enabled               bool     `toml:"enabled"`
		Delegators            []string `toml:"delegators"`
		OpenRegistration      bool     `toml:"open_registration"`
		MinDiscrepancyWei     string   `toml:"min_discrepancy_wei"`
		MaxDelegationsPerNpub int      `toml:"max_delegations_per_npub"`
	} `toml:"tower"`
}

// RegistryEntry names one registry deployment.
type RegistryEntry struct {
	Address string `toml:"address"`
	ChainID uint64 `toml:"chain_id"`
}

// Defaults per Part 3 §11.
func DefaultConfig() Config {
	var cfg Config
	cfg.Node.Confirmations = 3
	cfg.Channels.DefaultChallengePeriod = 144
	cfg.Channels.AcceptChallengePeriodMin = 36
	cfg.Channels.AcceptChallengePeriodMax = 1008
	cfg.Channels.CoopCloseValidityBlocks = 18
	cfg.Channels.CoopCloseHorizonBlocks = protocol.DefaultCoopCloseHorizonBlocks
	cfg.Channels.WithdrawValidityBlocks = 18
	cfg.Channels.MaxInflightPaymentWei = "0"
	cfg.Backup.Enabled = true
	cfg.Tower.MaxDelegationsPerNpub = 1000
	return cfg
}

// LoadConfig reads a TOML file over the defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	if err := toml.NewDecoder(f).Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("channeld: parsing %s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate checks internal consistency.
func (c *Config) Validate() error {
	if len(c.Registries) == 0 {
		return fmt.Errorf("channeld: no registries configured")
	}
	for label, entries := range c.Registries {
		for _, e := range entries {
			if !util.IsHexAddress(e.Address) {
				return fmt.Errorf("channeld: registry %s: bad address %q", label, e.Address)
			}
			if e.ChainID == 0 {
				return fmt.Errorf("channeld: registry %s: missing chain_id", label)
			}
		}
	}
	if _, ok := c.MaxInflight(); !ok {
		return fmt.Errorf("channeld: bad max_inflight_payment_wei %q", c.Channels.MaxInflightPaymentWei)
	}
	// The engine refuses a cooperative close or withdraw whose expiry lies
	// beyond coop_close_horizon_blocks, and the node derives those expiries
	// from the validity windows: a window wider than the horizon would make
	// every close or withdraw fail at the proposer. Zero is the engine's
	// default horizon, so validate against that.
	horizon := c.Channels.CoopCloseHorizonBlocks
	if horizon == 0 {
		horizon = protocol.DefaultCoopCloseHorizonBlocks
	}
	for name, v := range map[string]uint64{
		"coop_close_validity_blocks": c.Channels.CoopCloseValidityBlocks,
		"withdraw_validity_blocks":   c.Channels.WithdrawValidityBlocks,
	} {
		if v == 0 {
			return fmt.Errorf("channeld: %s must be positive", name)
		}
		if v > horizon {
			return fmt.Errorf("channeld: %s (%d) exceeds coop_close_horizon_blocks (%d)", name, v, horizon)
		}
	}
	if len(c.Nostr.Relays) == 0 {
		return fmt.Errorf("channeld: no nostr relays configured")
	}
	return nil
}

// MaxInflight parses the poisoned-exposure cap; nil means unlimited.
func (c *Config) MaxInflight() (*big.Int, bool) {
	s := c.Channels.MaxInflightPaymentWei
	if s == "" || s == "0" {
		return nil, true
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return nil, false
	}
	return v, true
}

// AllRelays merges payment and backup relays, deduplicated, payment relays
// first.
func (c *Config) AllRelays() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range append(append([]string{}, c.Nostr.Relays...), c.Backup.Relays...) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
