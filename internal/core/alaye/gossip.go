package alaye

import (
	"fmt"
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Gossip struct {
	Enabled     Enabled     `hcl:"enabled,optional" json:"enabled"`
	Port        int         `hcl:"port,optional" json:"port"`
	SecretKey   Value       `hcl:"secret_key,optional" json:"secret-key"` // Memberlist encryption key (16, 24, or 32 bytes)
	Seeds       []string    `hcl:"seeds,optional" json:"seeds"`           // Initial cluster peers
	TTL         int         `hcl:"ttl,optional" json:"ttl"`               // how long since I last heard from you before I assume you’re dead
	SharedState SharedState `hcl:"shared_state,block" json:"shared_state"`
}

type SharedState struct {
	Enabled Enabled     `hcl:"enabled,optional" json:"enabled"`
	Driver  string      `hcl:"driver,optional" json:"driver"` // "memory" (default) or "redis"
	Redis   *RedisState `hcl:"redis,block" json:"redis,omitempty"`
}

type RedisState struct {
	Host      string `hcl:"host,optional" json:"host"`
	Port      int    `hcl:"port,optional" json:"port"`
	Password  string `hcl:"password,optional" json:"password"`
	DB        int    `hcl:"db,optional" json:"db"`
	KeyPrefix string `hcl:"key_prefix,optional" json:"key_prefix"`
}

// Validate verifies the constraints of the gossip configuration.
// It checks ports, secret keys, and normalizes optional drivers.
func (g *Gossip) Validate() error {
	if g.Enabled.NotActive() {
		return nil
	}

	if g.Port < MinPort || g.Port > MaxPort {
		return errors.Newf("%w: port must be between 0 and 65535", ErrInvalidPort)
	}
	if g.Port == 0 {
		g.Port = DefaultGossipPort
	}

	if g.SecretKey != "" {
		keyLen := len(g.SecretKey)
		if keyLen != SecretKeyLen16 && keyLen != SecretKeyLen24 && keyLen != SecretKeyLen32 {
			return ErrInvalidSecretKey
		}
	}

	for i, seed := range g.Seeds {
		if seed == "" {
			return errors.Newf("seeds[%d]: %w", i, ErrSeedEmpty)
		}
		if _, _, err := net.SplitHostPort(seed); err != nil {
			if _, _, err := net.SplitHostPort(fmt.Sprintf("%s:%d", seed, DefaultGossipPort)); err != nil {
				return errors.Newf("%w: seeds[%d]: %q is not a valid host:port", ErrInvalidSeedFormat, i, seed)
			}
		}
	}

	if g.SharedState.Enabled.Active() {
		driver := strings.ToLower(g.SharedState.Driver)
		if driver == "" {
			g.SharedState.Driver = "memory"
		} else if driver != "memory" && driver != "redis" {
			return errors.Newf("unsupported shared_state driver: %s", driver)
		}
	}

	return nil
}
