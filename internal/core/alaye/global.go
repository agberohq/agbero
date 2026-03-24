package alaye

import (
	"net"

	"github.com/olekukonko/errors"
)

// Global represents the root configuration of Agbero.
// It contains system-wide settings, storage paths, and global environment variables.
type Global struct {
	Version     int    `hcl:"version,attr" json:"version"`
	Build       string `hcl:"-" json:"build"`
	Development bool   `hcl:"development,attr" json:"development"`

	Env map[string]Value `hcl:"env,attr" json:"env"`

	Bind     Bind    `hcl:"bind,block" json:"bind"`
	Timeouts Timeout `hcl:"timeouts,block" json:"timeouts"`
	Storage  Storage `hcl:"storage,block" json:"storage"`
	General  General `hcl:"general,block" json:"general"`

	Admin Admin `hcl:"admin,block" json:"admin"`

	API         API         `hcl:"api,block" json:"api"`
	Logging     Logging     `hcl:"logging,block" json:"logging"`
	Security    Security    `hcl:"security,block" json:"security"`
	RateLimits  GlobalRate  `hcl:"rate_limits,block" json:"rateLimits"`
	Gossip      Gossip      `hcl:"gossip,block" json:"gossip"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block" json:"lets_encrypt"`
	Fallback    Fallback    `hcl:"fallback,block" json:"fallback"`
	ErrorPages  ErrorPages  `hcl:"error_pages,block" json:"error_pages"`
}

// Validate ensures the global configuration is consistent and all required blocks are valid.
// It cascades validation to sub-structures including networking, security, and storage.
func (g *Global) Validate() error {
	if err := g.Bind.Validate(); err != nil {
		return errors.Newf("bind: %w", err)
	}
	if err := g.Admin.Validate(); err != nil {
		return errors.Newf("admin: %w", err)
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

// General contains tuning parameters for the server core.
// It handles limits such as maximum header sizes for incoming requests.
type General struct {
	MaxHeaderBytes int `hcl:"max_header_bytes,attr" json:"max_header_bytes"`
}

// Validate checks the general settings for logical errors.
// It ensures that header limits are non-negative.
func (g *General) Validate() error {
	if g.MaxHeaderBytes < 0 {
		return ErrNegativeMaxHeaderBytes
	}
	return nil
}

// Storage defines the directory structure for Agbero's data persistence.
// It points to where hosts, certificates, and internal data are stored.
type Storage struct {
	HostsDir string `hcl:"hosts_dir,attr" json:"hosts_dir"`
	CertsDir string `hcl:"certs_dir,attr" json:"certs_dir"`
	DataDir  string `hcl:"data_dir,attr" json:"data_dir"`
	WorkDir  string `hcl:"work_dir,attr" json:"work_dir"`
}

// Validate is a placeholder for future storage logic.
// Currently returns nil as paths are resolved during runtime.
func (s Storage) Validate() error {
	return nil
}

// Pprof enables the standard Go profiling endpoints.
// It should only be used in internal or development environments.
type Pprof struct {
	Enabled Enabled `hcl:"enabled,attr" json:"enabled"`
	Bind    string  `hcl:"bind,attr" json:"bind"`
}

// Validate ensures the pprof configuration has a valid bind address.
// It only performs checks if pprof is explicitly enabled.
func (p *Pprof) Validate() error {
	if p.Enabled.NotActive() {
		return nil
	}
	if p.Bind == "" {
		return ErrPprofPortRequired
	}
	host, _, err := net.SplitHostPort(p.Bind)
	if err != nil {
		host = p.Bind
	}
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsLoopback() && host != "localhost") {
		return ErrPprofLoopbackOnly
	}
	return nil
}
