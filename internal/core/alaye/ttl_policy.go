package alaye

import (
	"net/http"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type TTLPolicy struct {
	Enabled expect.Toggle   `hcl:"enabled,attr"  json:"enabled"`
	Default expect.Duration `hcl:"default,attr"  json:"default,omitempty"`

	// Content-aware TTL overrides (prefix match on Content-Type)
	ContentType map[string]expect.Duration `hcl:"content_type,attr" json:"content_type,omitempty"`
	Extension   map[string]expect.Duration `hcl:"extension,attr"    json:"extension,omitempty"`
	KeyScope    []string                   `hcl:"key_scope,attr"    json:"key_scope,omitempty"`

	// CDN stale fields
	StaleWhileRevalidate expect.Duration `hcl:"stale_while_revalidate,attr" json:"stale_while_revalidate,omitempty"`
	StaleIfError         expect.Duration `hcl:"stale_if_error,attr"         json:"stale_if_error,omitempty"`
}

// GetTTL determines TTL based on policy and content type.
// When the policy is active but returns 0 (either no content-type match and
// Default=0, or an explicit zero override), the caller (SetWithPolicy) treats
// 0 as "do not cache" — this is the correct signal for an operator who
// intentionally disables caching via the policy.
// The defaultTTL parameter is used only when the policy is nil or inactive,
// preserving the upstream's Cache-Control: max-age directive in that case.
func (p *TTLPolicy) GetTTL(defaultTTL time.Duration, contentType string) time.Duration {
	if p == nil || !p.Enabled.Active() {
		return defaultTTL
	}

	// Check content-type specific TTL (prefix match)
	for pattern, ttl := range p.ContentType {
		if strings.HasPrefix(contentType, pattern) {
			return ttl.StdDuration()
		}
	}

	// Fallback to policy default (0 means "do not cache" — intentional operator choice)
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

// IsStaleWhileRevalidate returns true when the stale-while-revalidate window is set.
func (p *TTLPolicy) IsStaleWhileRevalidate() bool {
	return p != nil && p.StaleWhileRevalidate.StdDuration() > 0
}

// StaleWindow returns the stale-while-revalidate duration (0 if not set).
func (p *TTLPolicy) StaleWindow() time.Duration {
	if p == nil {
		return 0
	}
	return p.StaleWhileRevalidate.StdDuration()
}

// ErrorWindow returns the stale-if-error duration (0 if not set).
func (p *TTLPolicy) ErrorWindow() time.Duration {
	if p == nil {
		return 0
	}
	return p.StaleIfError.StdDuration()
}

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
		len(p.KeyScope) == 0 &&
		p.StaleWhileRevalidate == 0 &&
		p.StaleIfError == 0
}
