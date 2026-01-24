package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Gossip struct {
	Enabled        bool     `hcl:"enabled"`
	Port           int      `hcl:"port,optional"`
	SecretKey      string   `hcl:"secret_key,optional"`       // Memberlist encryption key (16, 24, or 32 bytes)
	Seeds          []string `hcl:"seeds,optional"`            // Initial cluster peers
	PrivateKeyFile string   `hcl:"private_key_file,optional"` // Path to Ed25519 private key for app auth
}

func (g *Gossip) Validate() error {
	if !g.Enabled {
		return nil // Nothing to validate if not enabled
	}

	// Port validation
	if g.Port < 0 || g.Port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	if g.Port == 0 {
		g.Port = 7946 // Default memberlist port
	}

	// Secret key validation (if provided)
	if g.SecretKey != "" {
		keyLen := len(g.SecretKey)
		if keyLen != 16 && keyLen != 24 && keyLen != 32 {
			return errors.New("secret_key must be 16, 24, or 32 bytes")
		}
	}

	// Seeds validation
	for i, seed := range g.Seeds {
		if seed == "" {
			return errors.Newf("seeds[%d]: cannot be empty", i)
		}
		// Basic host:port validation
		if _, _, err := net.SplitHostPort(seed); err != nil {
			// Try adding default port
			if _, _, err := net.SplitHostPort(seed + ":7946"); err != nil {
				return errors.Newf("seeds[%d]: %q is not a valid host:port", i, seed)
			}
		}
	}

	// Private key file validation (if provided)
	if g.PrivateKeyFile != "" && !strings.HasPrefix(g.PrivateKeyFile, "/") {
		return errors.New("private_key_file must be an absolute path")
	}

	return nil
}
