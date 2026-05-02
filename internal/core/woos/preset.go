package woos

import (
	"net/http"
	"strings"
)

// DangerousFastCGIHeaders is the set of lowercase HTTP header names that must
// be stripped before forwarding a request to any FastCGI backend.
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
	// from an arbitrary client header.
	"script_filename":   true,
	"document_root":     true,
	"script_name":       true,
	"request_uri":       true,
	"query_string":      true,
	"request_method":    true,
	"server_protocol":   true,
	"gateway_interface": true,
	"redirect_status":   true,
	"content_length":    true,
	"content_type":      true,
	"remote_addr":       true,
	"remote_port":       true,
	"server_addr":       true,
	"server_name":       true,
	"server_port":       true,
	"server_software":   true,
	"path_translated":   true,
	"path_info":         true,

	// PHP-specific auth variables — prevent credential injection.
	"php_auth_user": true,
	"php_auth_pw":   true,
	"auth_type":     true,

	// PHP rewrite aliases.
	"orig_path_info":       true,
	"orig_script_name":     true,
	"orig_script_filename": true,

	// HTTP_HOST is injected by BasicParamsMap from r.Host; a client-supplied
	// Host header override would let tenants forge the SERVER_NAME seen by the
	// backend application.
	"http_host": true,
}

// SanitizeFastCGIHeaders returns a copy of r.Header with all entries from
// DangerousFastCGIHeaders removed, plus any header whose lowercase name starts
// with "http_" (which would collide with the HTTP_ CGI namespace and allow
// variable injection).
//
// Call this on the incoming *http.Request before invoking any gofast session
// chain. The returned Header is a fresh map; r.Header is not modified.
func SanitizeFastCGIHeaders(r *http.Request) http.Header {
	safe := make(http.Header, len(r.Header))
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if DangerousFastCGIHeaders[lower] {
			continue
		}
		// Drop anything that would produce an HTTP_HTTP_* collision in the
		// CGI environment — a client cannot be allowed to inject arbitrary
		// HTTP_ variables by prefixing its own header with "http_".
		if strings.HasPrefix(lower, "http_") {
			continue
		}
		safe[key] = values
	}
	return safe
}
