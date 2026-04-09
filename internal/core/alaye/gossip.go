package alaye

import (
	"fmt"
	"net"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Gossip struct {
	Enabled     expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Port        int           `hcl:"port,attr" json:"port"`
	SecretKey   expect.Value  `hcl:"secret_key,attr" json:"secret-key"`
	Seeds       []string      `hcl:"seeds,attr" json:"seeds"`
	TTL         int           `hcl:"ttl,attr" json:"ttl"`
	SharedState SharedState   `hcl:"shared_state,block" json:"shared_state"`
}

type SharedState struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Driver  string        `hcl:"driver,attr" json:"driver"`
	Redis   *RedisState   `hcl:"redis,block" json:"redis,omitempty"`
}

type RedisState struct {
	Host      string `hcl:"host,attr" json:"host"`
	Port      int    `hcl:"port,attr" json:"port"`
	Password  string `hcl:"password,attr" json:"password"`
	DB        int    `hcl:"db,attr" json:"db"`
	KeyPrefix string `hcl:"key_prefix,attr" json:"key_prefix"`
}

// Validate checks port range, secret key length, seed formats, and shared state driver.
// It does not set defaults — all defaults are applied by woos.defaultGossip.
func (g *Gossip) Validate() error {
	if g.Enabled.NotActive() {
		return nil
	}

	if g.Port < MinPort || g.Port > MaxPort {
		return errors.Newf("%w: port must be between 0 and 65535", ErrInvalidPort)
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
		if g.SharedState.Driver != "memory" && g.SharedState.Driver != "redis" {
			return errors.Newf("unsupported shared_state driver: %s", g.SharedState.Driver)
		}
	}

	return nil
}
