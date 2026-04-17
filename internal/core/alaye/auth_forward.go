package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type ForwardAuth struct {
	Enabled      expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Name         string          `hcl:"name,label" json:"name"`
	URL          string          `hcl:"url,attr" json:"url"`
	OnFailure    string          `hcl:"on_failure,attr" json:"on_failure"`
	Timeout      expect.Duration `hcl:"timeout,attr" json:"timeout"`
	AllowPrivate bool            `hcl:"allow_private,attr" json:"allow_private"`

	TLS      ForwardTLS          `hcl:"tls,block" json:"tls,omitempty"`
	Request  ForwardAuthRequest  `hcl:"request,block" json:"request"`
	Response ForwardAuthResponse `hcl:"response,block" json:"response"`
}

func (f ForwardAuth) IsZero() bool {
	return f.Enabled.IsZero() &&
		f.Name == "" &&
		f.URL == "" &&
		f.OnFailure == "" &&
		f.Timeout == 0 &&
		!f.AllowPrivate &&
		f.TLS.IsZero() &&
		f.Request.IsZero() &&
		f.Response.IsZero()
}

type ForwardTLS struct {
	Enabled            expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	InsecureSkipVerify bool          `hcl:"insecure_skip_verify,attr" json:"insecure_skip_verify"`
	ClientCert         expect.Value  `hcl:"client_cert,attr" json:"client_cert"`
	ClientKey          expect.Value  `hcl:"client_key,attr" json:"client_key"`
	CA                 expect.Value  `hcl:"ca,attr" json:"ca"`
}

func (f ForwardTLS) IsZero() bool {
	return f.Enabled.IsZero() &&
		!f.InsecureSkipVerify &&
		f.ClientCert == "" &&
		f.ClientKey == "" &&
		f.CA == ""
}

type ForwardAuthRequest struct {
	Enabled       expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Headers       []string      `hcl:"headers,attr" json:"headers"`
	Method        string        `hcl:"method,attr" json:"method"`
	ForwardMethod bool          `hcl:"forward_method,attr" json:"forward_method"`
	ForwardURI    bool          `hcl:"forward_uri,attr" json:"forward_uri"`
	ForwardIP     bool          `hcl:"forward_ip,attr" json:"forward_ip"`
	BodyMode      string        `hcl:"body_mode,attr" json:"body_mode"`
	MaxBody       int64         `hcl:"max_body,attr" json:"max_body"`
	CacheKey      []string      `hcl:"cache_key,attr" json:"cache_key"`
}

func (f ForwardAuthRequest) IsZero() bool {
	return f.Enabled.IsZero() &&
		len(f.Headers) == 0 &&
		f.Method == "" &&
		!f.ForwardMethod &&
		!f.ForwardURI &&
		!f.ForwardIP &&
		f.BodyMode == "" &&
		f.MaxBody == 0 &&
		len(f.CacheKey) == 0
}

type ForwardAuthResponse struct {
	Enabled     expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	CopyHeaders []string        `hcl:"copy_headers,attr" json:"copy_headers"`
	CacheTTL    expect.Duration `hcl:"cache_ttl,attr" json:"cache_ttl"`
}

func (f ForwardAuthResponse) IsZero() bool {
	return f.Enabled.IsZero() && len(f.CopyHeaders) == 0 && f.CacheTTL == 0
}

// Validate checks that the forward_auth block is correctly configured.
// When allow_private is false (the default), the target URL is checked against
// RFC-1918, loopback, and link-local ranges to prevent SSRF attacks.
func (f *ForwardAuth) Validate() error {
	if f.Enabled.NotActive() {
		return nil
	}

	if f.URL == "" {
		return def.ErrForwardAuthURLRequired
	}

	if !strings.HasPrefix(f.URL, "http://") && !strings.HasPrefix(f.URL, "https://") {
		return errors.New("forward_auth: url must start with http:// or https://")
	}

	if !f.AllowPrivate {
		if err := rejectPrivateURL(f.URL); err != nil {
			return errors.Newf("forward_auth: SSRF risk — %w. Set allow_private = true to allow internal targets", err)
		}
	}

	if f.OnFailure != "allow" && f.OnFailure != "deny" {
		return errors.New("forward_auth: on_failure must be 'allow' or 'deny'")
	}

	if f.Request.Enabled.Active() {
		switch f.Request.BodyMode {
		case "none", "metadata", "limited", "":
		default:
			return errors.New("forward_auth: body_mode must be 'none', 'metadata', or 'limited'")
		}
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
