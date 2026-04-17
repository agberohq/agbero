package alaye

import (
	"net/http"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type TTLPolicy struct {
	Enabled expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Default expect.Duration `hcl:"default,attr" json:"default,omitempty"`

	// Content-aware TTL overrides (prefix match on Content-Type)
	ContentType map[string]expect.Duration `hcl:"content_type,attr" json:"content_type,omitempty"`

	// Extension-based fallbacks (e.g., .rss, .pdf)
	Extension map[string]expect.Duration `hcl:"extension,attr" json:"extension,omitempty"`

	// Cache key scoping: include query params, headers, or auth context
	KeyScope []string `hcl:"key_scope,attr" json:"key_scope,omitempty"`
}

// GetTTL determines TTL based on policy and content type
func (p *TTLPolicy) GetTTL(defaultTTL time.Duration, contentType string) time.Duration {
	if p == nil || !p.Enabled.Active() {
		return defaultTTL
	}

	// Check content-type specific TTL (prefix match)
	for pattern, ttl := range p.ContentType {
		if strings.HasPrefix(contentType, pattern) {
			return ttl.StdDuration() // This can be 0
		}
	}

	// Fallback to policy default (this can also be 0)
	return p.Default.StdDuration()
}

// GetTTLWithExtension determines TTL based on policy, content type, and extension
func (p *TTLPolicy) GetTTLWithExtension(defaultTTL time.Duration, contentType, extension string) time.Duration {
	if p == nil || !p.Enabled.Active() {
		return defaultTTL
	}

	// Check extension first (highest priority)
	if extension != "" {
		if ttl, ok := p.Extension[extension]; ok {
			if ttl.StdDuration() > 0 {
				return ttl.StdDuration()
			}
		}
	}

	// Check content-type specific TTL
	for pattern, ttl := range p.ContentType {
		if strings.HasPrefix(contentType, pattern) {
			if ttl.StdDuration() > 0 {
				return ttl.StdDuration()
			}
		}
	}

	// Fallback to policy default
	if p.Default.StdDuration() > 0 {
		return p.Default.StdDuration()
	}

	return defaultTTL
}

// ShouldCacheResponse checks if response should be cached based on policy
func (p *TTLPolicy) ShouldCacheResponse(status int, hdr http.Header) bool {
	// Cache 2xx and 3xx status codes (except 300, 304 is special)
	if status < 200 || status >= 400 {
		return false
	}

	// 300 Multiple Choices is not cacheable
	if status == http.StatusMultipleChoices {
		return false
	}

	// 304 Not Modified is cacheable but handled separately
	if status == http.StatusNotModified {
		return true
	}

	// 302 Found and 301 Moved Permanently are cacheable
	if status == http.StatusMovedPermanently || status == http.StatusFound {
		// Check Cache-Control headers
		cc := hdr.Get("Cache-Control")
		if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
			return false
		}
		return true
	}

	cc := hdr.Get("Cache-Control")
	if strings.Contains(cc, "no-store") ||
		strings.Contains(cc, "private") ||
		strings.Contains(cc, "no-cache") {
		return false
	}

	if hdr.Get("WWW-Authenticate") != "" {
		return false
	}

	return true
}

// IsEnabled returns true if the policy is active
func (p *TTLPolicy) IsEnabled() bool {
	return p != nil && p.Enabled.Active()
}

// Validate checks that the TTL policy is valid
func (p *TTLPolicy) Validate() error {
	if p == nil || !p.Enabled.Active() {
		return nil
	}
	if p.Default.StdDuration() <= 0 && len(p.ContentType) == 0 && len(p.Extension) == 0 {
		return errors.New("ttl_policy: default TTL must be positive when no overrides provided")
	}
	return nil
}

func (p TTLPolicy) IsZero() bool {
	return p.Enabled.IsZero() &&
		p.Default == 0 &&
		len(p.ContentType) == 0 &&
		len(p.Extension) == 0 &&
		len(p.KeyScope) == 0
}
