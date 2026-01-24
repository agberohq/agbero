package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Global struct {
	Bind Bind `hcl:"bind,block"`

	// directories
	HostsDir string `hcl:"hosts_dir"`
	CertsDir string `hcl:"certs_dir,optional"`

	LEEmail        string   `hcl:"le_email,optional"`
	Development    bool     `hcl:"development,optional"`
	TrustedProxies []string `hcl:"trusted_proxies,optional"`

	// NEW: Logging Configuration
	Logging Logging `hcl:"logging,block"`

	Gossip     Gossip  `hcl:"gossip,block"`
	Timeouts   Timeout `hcl:"timeouts,block"`
	RateLimits Rate    `hcl:"rate_limits,block"`

	MaxHeaderBytes int    `hcl:"max_header_bytes,optional"`
	TLSStorageDir  string `hcl:"tls_storage_dir,optional"`
}

func (g *Global) Validate() error {
	// Bind config validation
	if err := g.Bind.Validate(); err != nil {
		return errors.Newf("bind: %w", err)
	}

	// Hosts directory
	if g.HostsDir == "" {
		return errors.New("hosts_dir is required")
	}

	// Email validation for Let's Encrypt (if provided)
	if g.LEEmail != "" {
		if !strings.Contains(g.LEEmail, "@") {
			return errors.New("le_email must be a valid email address")
		}
	}

	// Timeouts validation
	if err := g.Timeouts.Validate(); err != nil {
		return errors.Newf("timeouts: %w", err)
	}

	// Rate limits validation
	if err := g.RateLimits.Validate(); err != nil {
		return errors.Newf("rate_limits: %w", err)
	}

	// TLS storage directory (if provided)
	if g.TLSStorageDir != "" && !strings.HasPrefix(g.TLSStorageDir, "/") {
		return errors.New("tls_storage_dir must be an absolute path")
	}

	// Max header bytes validation
	if g.MaxHeaderBytes <= 0 {
		return errors.New("max_header_bytes must be positive")
	}

	// Gossip config validation (if enabled)
	if &g.Gossip != nil {
		if err := g.Gossip.Validate(); err != nil {
			return errors.Newf("gossip: %w", err)
		}
	}

	// Trusted proxies validation
	for i, proxy := range g.TrustedProxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}
		// Check if it's a valid CIDR or IP
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			if ip := net.ParseIP(proxy); ip == nil {
				return errors.Newf("trusted_proxies[%d]: %q is not a valid CIDR or IP address", i, proxy)
			}
		}
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
