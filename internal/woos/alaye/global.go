package alaye

import (
	"github.com/olekukonko/errors"
)

type Global struct {
	Version     int         `hcl:"version,optional" json:"version"`
	Build       string      `hcl:"-,optional" json:"build"`
	Development bool        `hcl:"development,optional" json:"development"`
	Bind        Bind        `hcl:"bind,block" json:"bind"`
	Logging     Logging     `hcl:"logging,block" json:"logging"`
	Gossip      Gossip      `hcl:"gossip,block" json:"gossip"`
	Timeouts    Timeout     `hcl:"timeouts,block" json:"timeouts"`
	RateLimits  GlobalRate  `hcl:"rate_limits,block" json:"rateLimits"`
	Storage     Storage     `hcl:"storage,block" json:"storage"`
	Security    Security    `hcl:"security,block" json:"security"`
	General     General     `hcl:"general,block" json:"general"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block" json:"lets_encrypt"`
	Admin       *Admin      `hcl:"admin,block" json:"admin,omitempty"`
}

//type Security struct {
//	TrustedProxies []string  `hcl:"trusted_proxies,optional" json:"trusted_proxies"`
//	Firewall       *Firewall `hcl:"firewall,block" json:"firewall,omitempty"`
//}
//
//type Firewall struct {
//	Enabled       bool   `hcl:"enabled" json:"enabled"`
//	BlockList     string `hcl:"block_list_file,optional" json:"blockList"`
//	RemoteCheck   string `hcl:"remote_check_url,optional" json:"remote_check"`
//	RemoteTimeout int    `hcl:"remote_timeout,optional" json:"remote_timeout"`
//}

//func (s Security) Validate() error {
//	for i, proxy := range s.TrustedProxies {
//		proxy = strings.TrimSpace(proxy)
//		if proxy == "" {
//			continue
//		}
//		if _, _, err := net.ParseCIDR(proxy); err != nil {
//			if ip := net.ParseIP(proxy); ip == nil {
//				return errors.Newf("%w: trusted_proxies[%d]=%q", ErrInvalidProxy, i, proxy)
//			}
//		}
//	}
//	return nil
//}

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
	Level    string   `hcl:"level,optional" json:"level"`
	File     string   `hcl:"file,optional" json:"file"`
	Skip     []string `hcl:"skip,optional"`
	Victoria Victoria `hcl:"victoria,block" json:"victoria"`
	Include  []string `hcl:"include,optional" json:"include"`
}

type Victoria struct {
	Enabled   bool   `hcl:"enabled,optional" json:"enabled"`
	URL       string `hcl:"url,optional" json:"URL"`
	BatchSize int    `hcl:"batch_size,optional" json:"batch_size"`
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
