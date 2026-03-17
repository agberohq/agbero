package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type ForwardAuth struct {
	Enabled   Enabled  `hcl:"enabled,attr" json:"enabled"`
	Name      string   `hcl:"name,label" json:"name"`
	URL       string   `hcl:"url,attr" json:"url"`
	OnFailure string   `hcl:"on_failure,attr" json:"on_failure"`
	Timeout   Duration `hcl:"timeout,attr" json:"timeout"`

	TLS      ForwardTLS          `hcl:"tls,block" json:"tls,omitempty"`
	Request  ForwardAuthRequest  `hcl:"request,block" json:"request"`
	Response ForwardAuthResponse `hcl:"response,block" json:"response"`
}

type ForwardTLS struct {
	Enabled            Enabled `hcl:"enabled,attr" json:"enabled"`
	InsecureSkipVerify bool    `hcl:"insecure_skip_verify,attr" json:"insecure_skip_verify"`
	ClientCert         Value   `hcl:"client_cert,attr" json:"client_cert"`
	ClientKey          Value   `hcl:"client_key,attr" json:"client_key"`
	CA                 Value   `hcl:"ca,attr" json:"ca"`
}

type ForwardAuthRequest struct {
	Enabled       Enabled  `hcl:"enabled,attr" json:"enabled"`
	Headers       []string `hcl:"headers,attr" json:"headers"`
	Method        string   `hcl:"method,attr" json:"method"`
	ForwardMethod bool     `hcl:"forward_method,attr" json:"forward_method"`
	ForwardURI    bool     `hcl:"forward_uri,attr" json:"forward_uri"`
	ForwardIP     bool     `hcl:"forward_ip,attr" json:"forward_ip"`
	BodyMode      string   `hcl:"body_mode,attr" json:"body_mode"`
	MaxBody       int64    `hcl:"max_body,attr" json:"max_body"`
	CacheKey      []string `hcl:"cache_key,attr" json:"cache_key"`
}

type ForwardAuthResponse struct {
	Enabled     Enabled  `hcl:"enabled,attr" json:"enabled"`
	CopyHeaders []string `hcl:"copy_headers,attr" json:"copy_headers"`
	CacheTTL    Duration `hcl:"cache_ttl,attr" json:"cache_ttl"`
}

// Validate checks forward auth URL, on_failure policy, body_mode, and mTLS config.
// It does not set defaults — all defaults are applied by woos.defaultForwardAuth.
func (f *ForwardAuth) Validate() error {
	if f.Enabled.NotActive() {
		return nil
	}

	if f.URL == "" {
		return ErrForwardAuthURLRequired
	}

	if !strings.HasPrefix(f.URL, "http://") && !strings.HasPrefix(f.URL, "https://") {
		return errors.New("forward_auth: url must start with http:// or https://")
	}

	if f.OnFailure != "allow" && f.OnFailure != "deny" {
		return errors.New("forward_auth: on_failure must be 'allow' or 'deny'")
	}

	switch f.Request.BodyMode {
	case "none", "metadata", "limited":
	default:
		return errors.New("forward_auth: body_mode must be 'none', 'metadata', or 'limited'")
	}

	if f.Timeout <= 0 {
		return errors.New("forward_auth: timeout must be positive")
	}

	if f.TLS.Enabled.Active() {
		if (f.TLS.ClientCert != "" && f.TLS.ClientKey == "") || (f.TLS.ClientCert == "" && f.TLS.ClientKey != "") {
			return errors.New("forward_auth: both client_cert and client_key required for mTLS")
		}
	}

	return nil
}
