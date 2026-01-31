package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Gossip struct {
	Enabled        bool     `hcl:"enabled"`
	Port           int      `hcl:"port,optional"`
	SecretKey      Value    `hcl:"secret_key,optional"`       // Memberlist encryption key (16, 24, or 32 bytes)
	Seeds          []string `hcl:"seeds,optional"`            // Initial cluster peers
	PrivateKeyFile string   `hcl:"private_key_file,optional"` // Path to Ed25519 private key for app auth
	TTL            int      `hcl:"ttl,optional"`              // how long since I last heard from you before I assume you’re dead
}

func (g *Gossip) Validate() error {
	if !g.Enabled {
		return nil // Nothing to validate if not enabled
	}

	// Port validation
	if g.Port < MinPort || g.Port > MaxPort {
		return errors.Newf("%w: port must be between 0 and 65535", ErrInvalidPort)
	}
	if g.Port == 0 {
		g.Port = DefaultGossipPort // Default memberlist port
	}

	// Secret key validation (if provided)
	if g.SecretKey != "" {
		keyLen := len(g.SecretKey)
		if keyLen != SecretKeyLen16 && keyLen != SecretKeyLen24 && keyLen != SecretKeyLen32 {
			return ErrInvalidSecretKey
		}
	}

	// Seeds validation
	for i, seed := range g.Seeds {
		if seed == "" {
			return errors.Newf("seeds[%d]: %w", i, ErrSeedEmpty)
		}
		// Basic host:port validation
		if _, _, err := net.SplitHostPort(seed); err != nil {
			// Try adding default port
			if _, _, err := net.SplitHostPort(seed + ":7946"); err != nil {
				return errors.Newf("%w: seeds[%d]: %q is not a valid host:port", ErrInvalidSeedFormat, i, seed)
			}
		}
	}

	// Private key file validation (if provided)
	if g.PrivateKeyFile != "" && !strings.HasPrefix(g.PrivateKeyFile, "/") {
		return ErrPrivateKeyAbsolute
	}

	return nil
}
