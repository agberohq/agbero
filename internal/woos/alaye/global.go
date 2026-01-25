package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Global struct {
	Development bool `hcl:"development,optional"`

	Bind        Bind        `hcl:"bind,block"`
	Logging     Logging     `hcl:"logging,block"`
	Gossip      Gossip      `hcl:"gossip,block"`
	Timeouts    Timeout     `hcl:"timeouts,block"`
	RateLimits  Rate        `hcl:"rate_limits,block"`
	Storage     Storage     `hcl:"storage,block"`
	Security    Security    `hcl:"security,block"`
	General     General     `hcl:"general,block"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block"`
}

type Security struct {
	TrustedProxies []string  `hcl:"trusted_proxies,optional"`
	Firewall       *Firewall `hcl:"firewall,block"`
}

type Firewall struct {
	Enabled       bool   `hcl:"enabled"`
	BlockList     string `hcl:"block_list_file,optional"`
	RemoteCheck   string `hcl:"remote_check_url,optional"`
	RemoteTimeout int    `hcl:"remote_timeout,optional"` // Seconds
}

func (s Security) Validate() error {
	for i, proxy := range s.TrustedProxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			if ip := net.ParseIP(proxy); ip == nil {
				return errors.Newf("trusted_proxies[%d]: %q is not a valid CIDR or IP address", i, proxy)
			}
		}
	}
	return nil
}

func (g *Global) Validate() error {
	// Bind config validation
	if err := g.Bind.Validate(); err != nil {
		return errors.Newf("bind: %w", err)
	}

	// Timeouts validation
	if err := g.Timeouts.Validate(); err != nil {
		return errors.Newf("timeouts: %w", err)
	}

	// Rate limits validation
	if err := g.RateLimits.Validate(); err != nil {
		return errors.Newf("rate_limits: %w", err)
	}

	// Gossip config validation (if enabled)
	if &g.Gossip != nil {
		if err := g.Gossip.Validate(); err != nil {
			return errors.Newf("gossip: %w", err)
		}
	}

	if err := g.Security.Validate(); err != nil {
		return errors.Newf("security: %w", err)
	}

	if err := g.General.Validate(); err != nil {
		return errors.Newf("general: %w", err)
	}

	if err := g.LetsEncrypt.Validate(); err != nil {
		return errors.Newf("letsencrypt: %w", err)
	}

	if err := g.Storage.Validate(); err != nil {
		return errors.Newf("storage: %w", err)
	}
	return nil
}

type Logging struct {
	Level    string   `hcl:"level,optional"` // debug, info, warn, error
	File     string   `hcl:"file,optional"`  // /var/log/agbero.log
	Victoria Victoria `hcl:"victoria,block"`
}

type Victoria struct {
	Enabled   bool   `hcl:"enabled,optional"`
	URL       string `hcl:"url,optional"` // http://victoria-logs:9428/insert/jsonline
	BatchSize int    `hcl:"batch_size,optional"`
}

type General struct {
	MaxHeaderBytes int `hcl:"max_header_bytes,optional"`
}

func (g *General) Validate() error {
	if g.MaxHeaderBytes < 0 {
		return errors.New("max_header_bytes cannot be negative")
	}
	return nil
}

type Storage struct {
	HostsDir string `hcl:"hosts_dir,optional"`
	CertsDir string `hcl:"certs_dir,optional"`
	DataDir  string `hcl:"data_dir,optional"`
}

func (s Storage) Validate() error {
	return nil
}
