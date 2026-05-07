package woos

import (
	"net/http"
	"strings"
)

// DangerousFastCGIHeaders is the set of normalised (lowercase, dashes only)
// HTTP header names that must be stripped before forwarding a request to any
// FastCGI backend.
//
// All entries use dashes, never underscores. SanitizeFastCGIHeaders normalises
// both dashes and underscores to dashes before lookup, so "X_Forwarded_Host"
// and "X-Forwarded-Host" both map to "x-forwarded-host" and are caught.
//
// These headers are dangerous because gofast.MapHeader blindly converts every
// incoming HTTP header to an uppercase CGI environment variable by prepending
// "HTTP_" and replacing dashes with underscores. An attacker-supplied header
// can therefore overwrite critical CGI parameters that the proxy is supposed
// to control authoritatively.
//
// The most critical entry is "proxy" (→ HTTP_PROXY), which is the root cause
// of CVE-2016-5385 (HTTPoxy): many runtimes (PHP, Python, Go) treat HTTP_PROXY
// as the outbound proxy, allowing an unauthenticated client to intercept all
// backend outbound traffic.
//
// Any header whose name, after the HTTP_ prefix is applied, would collide with
// a CGI variable that the proxy sets authoritatively should be listed here.
var DangerousFastCGIHeaders = map[string]bool{
	// HTTPoxy (CVE-2016-5385) — the canonical reason this list exists.
	"proxy": true,

	// Forwarding headers — set authoritatively by the proxy; a client
	// supplying these would let it spoof its own origin.
	"x-forwarded-host":   true,
	"x-forwarded-proto":  true,
	"x-forwarded-for":    true,
	"x-forwarded-server": true,
	"x-forwarded-port":   true,
	"x-real-ip":          true,

	// CGI meta-variables — must come from the proxy or the filesystem, not
	// from an arbitrary client header. All use dashes; normalisation handles
	// underscore variants transparently.
	"script-filename":   true,
	"document-root":     true,
	"script-name":       true,
	"request-uri":       true,
	"query-string":      true,
	"request-method":    true,
	"server-protocol":   true,
	"gateway-interface": true,
	"redirect-status":   true,
	"remote-addr":       true,
	"remote-port":       true,
	"server-addr":       true,
	"server-name":       true,
	"server-port":       true,
	"server-software":   true,
	"path-translated":   true,
	"path-info":         true,

	// PHP-specific auth variables — prevent credential injection.
	"php-auth-user": true,
	"php-auth-pw":   true,
	"auth-type":     true,

	// PHP rewrite aliases.
	"orig-path-info":       true,
	"orig-script-name":     true,
	"orig-script-filename": true,

	// HTTP_HOST is injected by BasicParamsMap from r.Host; a client-supplied
	// Host header override would let tenants forge the SERVER_NAME seen by the
	// backend application. Stored as "http-host" since lookup normalises to dashes.
	"http-host": true,
}

// SanitizeFastCGIHeaders returns a copy of r.Header with all entries from
// DangerousFastCGIHeaders removed, plus any header whose lowercase name starts
// with "http_" (which would collide with the HTTP_ CGI namespace and allow
// variable injection).
//
// Critically, the lookup normalises both dashes and underscores to dashes
// before checking the blocklist. gofast.MapHeader collapses all dashes AND
// underscores to underscores when constructing the CGI variable name, so a
// client-supplied header "X_Forwarded_Host" is functionally identical to
// "X-Forwarded-Host" from gofast's perspective. Without normalisation an
// attacker can bypass the blocklist by substituting underscores for dashes
// in any protected header name (e.g. X_Forwarded_Host → HTTP_X_FORWARDED_HOST),
// enabling IP spoofing, Host injection, and HTTPoxy-style attacks.
//
// Call this on the incoming *http.Request before invoking any gofast session
// chain. The returned Header is a fresh map; r.Header is not modified.
func SanitizeFastCGIHeaders(r *http.Request) http.Header {
	safe := make(http.Header, len(r.Header))
	for key, values := range r.Header {
		lower := strings.ToLower(key)

		// Normalise underscores to dashes so the blocklist lookup is
		// bypass-proof. gofast.MapHeader treats dashes and underscores
		// identically (both become "_" in the CGI variable name), so
		// "X_Forwarded_Host" and "X-Forwarded-Host" are the same threat.
		normalised := strings.ReplaceAll(lower, "_", "-")

		if DangerousFastCGIHeaders[normalised] {
			continue
		}

		// Drop anything that would produce an HTTP_HTTP_* collision in the
		// CGI environment — a client cannot be allowed to inject arbitrary
		// HTTP_ variables by prefixing its own header with "http_" or "http-".
		if strings.HasPrefix(normalised, "http-") {
			continue
		}

		safe[key] = values
	}
	return safe
}
