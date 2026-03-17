package alaye

import "github.com/olekukonko/errors"

type Global struct {
	Version     int    `hcl:"version,attr" json:"version"`
	Build       string `hcl:"-" json:"build"`
	Development bool   `hcl:"development,attr" json:"development"`

	Bind     Bind    `hcl:"bind,block" json:"bind"`
	Timeouts Timeout `hcl:"timeouts,block" json:"timeouts"`
	Storage  Storage `hcl:"storage,block" json:"storage"`
	General  General `hcl:"general,block" json:"general"`

	Admin       Admin       `hcl:"admin,block" json:"admin"`
	Pprof       Pprof       `hcl:"pprof,block" json:"pprof"`
	API         API         `hcl:"api,block" json:"api"`
	Logging     Logging     `hcl:"logging,block" json:"logging"`
	Security    Security    `hcl:"security,block" json:"security"`
	RateLimits  GlobalRate  `hcl:"rate_limits,block" json:"rateLimits"`
	Gossip      Gossip      `hcl:"gossip,block" json:"gossip"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block" json:"lets_encrypt"`
	Fallback    Fallback    `hcl:"fallback,block" json:"fallback"`
	ErrorPages  ErrorPages  `hcl:"error_pages,block" json:"error_pages"`
}

// Validate checks all nested blocks in the global configuration.
// It does not set any defaults — call woos.DefaultApply before Validate.
func (g *Global) Validate() error {
	if err := g.Bind.Validate(); err != nil {
		return errors.Newf("bind: %w", err)
	}
	if err := g.Admin.Validate(); err != nil {
		return errors.Newf("admin: %w", err)
	}
	if err := g.Pprof.Validate(); err != nil {
		return errors.Newf("pprof: %w", err)
	}
	if err := g.API.Validate(); err != nil {
		return errors.Newf("api: %w", err)
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
	if err := g.ErrorPages.Validate(); err != nil {
		return errors.Newf("global error_pages: %w", err)
	}
	return nil
}

type General struct {
	MaxHeaderBytes int `hcl:"max_header_bytes,attr" json:"max_header_bytes"`
}

// Validate checks that max_header_bytes is not negative.
func (g *General) Validate() error {
	if g.MaxHeaderBytes < 0 {
		return ErrNegativeMaxHeaderBytes
	}
	return nil
}

type Storage struct {
	HostsDir string `hcl:"hosts_dir,attr" json:"hosts_dir"`
	CertsDir string `hcl:"certs_dir,attr" json:"certs_dir"`
	DataDir  string `hcl:"data_dir,attr" json:"data_dir"`
	WorkDir  string `hcl:"work_dir,attr" json:"work_dir"`
}

// Validate is a no-op — storage paths are resolved and defaulted by woos.defaultStorage.
func (s Storage) Validate() error {
	return nil
}

// Pprof configures the standalone pprof listener. It binds a raw net/http/pprof
// server with no middleware so profiles reflect the proxy hot path, not admin overhead.
type Pprof struct {
	Enabled Enabled `hcl:"enabled,attr" json:"enabled"`
	Bind    string  `hcl:"bind,attr" json:"bind"`
}

// Validate checks that port is non-empty when the pprof block is enabled.
func (p *Pprof) Validate() error {
	if p.Enabled.NotActive() {
		return nil
	}
	if p.Bind == "" {
		return ErrPprofPortRequired
	}
	return nil
}
