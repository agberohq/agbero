package alaye

import (
	"net/url"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Fallback struct {
	Enabled     expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Type        string        `hcl:"type,attr" json:"type"`
	StatusCode  int           `hcl:"status_code,attr" json:"status_code"`
	Body        string        `hcl:"body,attr" json:"body"`
	ContentType string        `hcl:"content_type,attr" json:"content_type"`
	RedirectURL string        `hcl:"redirect_url,attr" json:"redirect_url"`
	ProxyURL    string        `hcl:"proxy_url,attr" json:"proxy_url"`
	CacheTTL    int           `hcl:"cache_ttl,attr" json:"cache_ttl"`
}

// Validate checks that the fallback type is valid and required fields are present.
// It does not set defaults — all defaults are applied by woos.defaultFallback.
func (f *Fallback) Validate() error {
	if f.Enabled.NotActive() {
		return nil
	}

	switch f.Type {
	case "static":
		if f.Body == "" {
			return def.ErrFallbackBodyRequired
		}
	case "redirect":
		if f.RedirectURL == "" {
			return def.ErrFallbackRedirectURLRequired
		}
		if _, err := url.Parse(f.RedirectURL); err != nil {
			return errors.Newf("fallback: invalid redirect_url: %w", err)
		}
	case "proxy":
		if f.ProxyURL == "" {
			return def.ErrFallbackProxyURLRequired
		}
		if _, err := url.Parse(f.ProxyURL); err != nil {
			return errors.Newf("fallback: invalid proxy_url: %w", err)
		}
		if err := rejectPrivateURL(f.ProxyURL); err != nil {
			return errors.Newf("fallback: proxy_url SSRF protection: %w", err)
		}
	default:
		return def.ErrFallbackTypeInvalid
	}

	if f.CacheTTL < 0 {
		return errors.New("fallback: cache_ttl cannot be negative")
	}
	return nil
}

// IsActive returns true if fallback is enabled and a type has been configured.
func (f *Fallback) IsActive() bool {
	return f.Enabled.Active() && f.Type != ""
}

func (f Fallback) IsZero() bool {
	return f.Enabled.IsZero() &&
		f.Type == "" &&
		f.StatusCode == 0 &&
		f.Body == "" &&
		f.ContentType == "" &&
		f.RedirectURL == "" &&
		f.ProxyURL == "" &&
		f.CacheTTL == 0
}
