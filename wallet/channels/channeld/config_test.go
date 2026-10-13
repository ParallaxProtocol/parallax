package channeld

import (
	"strings"
	"testing"
)

func validTestConfig() Config {
	cfg := DefaultConfig()
	cfg.Registries = map[string][]RegistryEntry{
		"v1": {{Address: e2eKey.Registry.Hex(), ChainID: 2110}},
	}
	cfg.Nostr.Relays = []string{"wss://hub"}
	return cfg
}

// TestConfigValidateWindowsWithinHorizon: the engine rejects close and
// withdraw expiries beyond coop_close_horizon_blocks, and the node derives
// those expiries from the validity windows, so a window wider than the
// horizon must be refused at load time rather than failing every verb.
func TestConfigValidateWindowsWithinHorizon(t *testing.T) {
	if err := func() error { c := validTestConfig(); return c.Validate() }(); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"withdraw window beyond horizon", func(c *Config) { c.Channels.WithdrawValidityBlocks = 2000 },
			"withdraw_validity_blocks (2000) exceeds coop_close_horizon_blocks (1008)"},
		{"close window beyond horizon", func(c *Config) { c.Channels.CoopCloseValidityBlocks = 1009 },
			"coop_close_validity_blocks (1009) exceeds coop_close_horizon_blocks (1008)"},
		{"zero withdraw window", func(c *Config) { c.Channels.WithdrawValidityBlocks = 0 },
			"withdraw_validity_blocks must be positive"},
		{"zero close window", func(c *Config) { c.Channels.CoopCloseValidityBlocks = 0 },
			"coop_close_validity_blocks must be positive"},
		{"window beyond the default horizon", func(c *Config) {
			c.Channels.CoopCloseHorizonBlocks = 0
			c.Channels.CoopCloseValidityBlocks = 1009
		}, "coop_close_validity_blocks (1009) exceeds coop_close_horizon_blocks (1008)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validTestConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
	// Zero is the engine's default horizon, not an invalid one.
	zero := validTestConfig()
	zero.Channels.CoopCloseHorizonBlocks = 0
	if err := zero.Validate(); err != nil {
		t.Fatalf("zero (default) horizon rejected: %v", err)
	}
	// A wider horizon admits the wider window.
	cfg := validTestConfig()
	cfg.Channels.CoopCloseHorizonBlocks = 20_000
	cfg.Channels.WithdrawValidityBlocks = 10_000
	if err := cfg.Validate(); err != nil {
		t.Fatalf("window within a raised horizon rejected: %v", err)
	}
}
