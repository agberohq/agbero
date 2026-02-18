package alaye

import (
	"github.com/olekukonko/errors"
)

type Global struct {
	// Default Fields
	Version     int    `hcl:"version,optional" json:"version"`
	Build       string `hcl:"-,optional" json:"build"`
	Development bool   `hcl:"development,optional" json:"development"`

	// Compulsory Fields
	Bind     Bind    `hcl:"bind,block" json:"bind"`
	Timeouts Timeout `hcl:"timeouts,block" json:"timeouts"`
	Storage  Storage `hcl:"storage,block" json:"storage"`
	General  General `hcl:"general,block" json:"general"`

	// Fields that require you to enable it
	Admin       Admin       `hcl:"admin,block" json:"admin,omitempty"`
	Logging     Logging     `hcl:"logging,block" json:"logging,omitempty"`
	Security    Security    `hcl:"security,block" json:"security,omitempty"`
	RateLimits  GlobalRate  `hcl:"rate_limits,block" json:"rateLimits,omitempty"`
	Gossip      Gossip      `hcl:"gossip,block" json:"gossip,omitempty"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block" json:"lets_encrypt,omitempty"`
	Fallback    Fallback    `hcl:"fallback,block" json:"fallback,omitempty"`
}

func (g *Global) Validate() error {
	if err := g.Bind.Validate(); err != nil {
		return errors.Newf("bind: %w", err)
	}

	if err := g.Admin.Validate(); err != nil {
		return errors.Newf("admin: %w", err)
	}

	if err := g.Timeouts.Validate(); err != nil {
		return errors.Newf("timeouts: %w", err)
	}

	if err := g.RateLimits.Validate(); err != nil {
		return errors.Newf("rate_limits: %w", err)
	}

	if err := g.Gossip.Validate(); err != nil {
		return errors.Newf("gossip: %w", err)
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

	if err := g.Fallback.Validate(); err != nil {
		return errors.Newf("fallback: %w", err)
	}

	return nil
}

type General struct {
	MaxHeaderBytes int `hcl:"max_header_bytes,optional" json:"max_header_bytes"`
}

func (g *General) Validate() error {
	if g.MaxHeaderBytes < 0 {
		return ErrNegativeMaxHeaderBytes
	}
	return nil
}

type Storage struct {
	HostsDir string `hcl:"hosts_dir,optional" json:"hosts_dir"`
	CertsDir string `hcl:"certs_dir,optional" json:"certs_dir"`
	DataDir  string `hcl:"data_dir,optional" json:"data_dir"`
}

func (s Storage) Validate() error {
	return nil
}
