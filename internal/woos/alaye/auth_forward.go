package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type ForwardAuth struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	Name    string  `hcl:"name,label" json:"name"`
	URL     string  `hcl:"url" json:"url"`

	TLS *ForwardTLS `hcl:"tls,block" json:"tls,omitempty"`

	Request  ForwardAuthRequest  `hcl:"request,block" json:"request"`
	Response ForwardAuthResponse `hcl:"response,block" json:"response"`

	OnFailure string        `hcl:"on_failure,optional" json:"on_failure"`
	Timeout   time.Duration `hcl:"timeout,optional" json:"timeout"`
}

type ForwardTLS struct {
	Enabled            Enabled `hcl:"enabled,optional" json:"enabled"`
	InsecureSkipVerify bool    `hcl:"insecure_skip_verify,optional" json:"insecure_skip_verify"`
	ClientCert         Value   `hcl:"client_cert,optional" json:"client_cert"`
	ClientKey          Value   `hcl:"client_key,optional" json:"client_key"`
	CA                 Value   `hcl:"ca,optional" json:"ca"`
}

type ForwardAuthRequest struct {
	Enabled       Enabled  `hcl:"enabled,optional" json:"enabled"` // ADDED
	Headers       []string `hcl:"headers,optional" json:"headers"`
	Method        string   `hcl:"method,optional" json:"method"`
	ForwardMethod bool     `hcl:"forward_method,optional" json:"forward_method"`
	ForwardURI    bool     `hcl:"forward_uri,optional" json:"forward_uri"`
	ForwardIP     bool     `hcl:"forward_ip,optional" json:"forward_ip"`

	BodyMode string `hcl:"body_mode,optional" json:"body_mode"`
	MaxBody  int64  `hcl:"max_body,optional" json:"max_body"`

	CacheKey []string `hcl:"cache_key,optional" json:"cache_key"`
}

type ForwardAuthResponse struct {
	Enabled     Enabled       `hcl:"enabled,optional" json:"enabled"` // ADDED
	CopyHeaders []string      `hcl:"copy_headers,optional" json:"copy_headers"`
	CacheTTL    time.Duration `hcl:"cache_ttl,optional" json:"cache_ttl"`
}

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

	f.Request.BodyMode = strings.ToLower(f.Request.BodyMode)
	if f.Request.BodyMode == "" {
		f.Request.BodyMode = "none"
	}
	switch f.Request.BodyMode {
	case "none", "metadata", "limited":
	default:
		return errors.New("forward_auth: body_mode must be 'none', 'metadata', or 'limited'")
	}

	if f.Timeout <= 0 {
		f.Timeout = 5 * time.Second
	}

	f.OnFailure = strings.ToLower(f.OnFailure)
	if f.OnFailure == "" {
		f.OnFailure = "deny"
	}
	if f.OnFailure != "allow" && f.OnFailure != "deny" {
		return errors.New("forward_auth: on_failure must be 'allow' or 'deny'")
	}

	if f.TLS != nil && f.TLS.Enabled.Active() {
		if (f.TLS.ClientCert != "" && f.TLS.ClientKey == "") || (f.TLS.ClientCert == "" && f.TLS.ClientKey != "") {
			return errors.New("forward_auth: both client_cert and client_key required for mTLS")
		}
	}

	return nil
}
