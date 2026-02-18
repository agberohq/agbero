package alaye

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/olekukonko/errors"
)

// Fallback defines a fallback response when all backends are unavailable
type Fallback struct {
	Enabled     Enabled `hcl:"enabled,optional" json:"enabled"`
	Type        string  `hcl:"type,optional" json:"type"` // "static", "redirect", "proxy"
	StatusCode  int     `hcl:"status_code,optional" json:"status_code"`
	Body        string  `hcl:"body,optional" json:"body"`
	ContentType string  `hcl:"content_type,optional" json:"content_type"`
	// For redirect type
	RedirectURL string `hcl:"redirect_url,optional" json:"redirect_url"`
	// For proxy type
	ProxyURL string `hcl:"proxy_url,optional" json:"proxy_url"`
	// Cache fallback response (0 = no cache)
	CacheTTL int `hcl:"cache_ttl,optional" json:"cache_ttl"` // seconds
}

// Validate checks fallback configuration
func (f *Fallback) Validate() error {
	if f.Enabled.NotActive() {
		return nil
	}
	if f.Type == "" {
		f.Type = "static"
	}
	switch strings.ToLower(f.Type) {
	case "static":
		if f.StatusCode == 0 {
			f.StatusCode = http.StatusServiceUnavailable
		}
		if f.ContentType == "" {
			f.ContentType = "application/json"
		}
		if f.Body == "" {
			return ErrFallbackBodyRequired
		}
	case "redirect":
		if f.RedirectURL == "" {
			return ErrFallbackRedirectURLRequired
		}
		if _, err := url.Parse(f.RedirectURL); err != nil {
			return errors.Newf("fallback: invalid redirect_url: %w", err)
		}
		if f.StatusCode == 0 {
			f.StatusCode = http.StatusTemporaryRedirect
		}
	case "proxy":
		if f.ProxyURL == "" {
			return ErrFallbackProxyURLRequired
		}
		if _, err := url.Parse(f.ProxyURL); err != nil {
			return errors.Newf("fallback: invalid proxy_url: %w", err)
		}
		if f.StatusCode == 0 {
			f.StatusCode = http.StatusOK
		}
	default:
		return ErrFallbackTypeInvalid
	}
	if f.CacheTTL < 0 {
		return errors.New("fallback: cache_ttl cannot be negative")
	}
	return nil
}

// IsActive returns true if fallback is enabled and configured
func (f *Fallback) IsActive() bool {
	return f.Enabled.Active() && f.Type != ""
}
