package alaye

import (
	"net"
	"net/url"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type ForwardAuth struct {
	Enabled      expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Name         string        `hcl:"name,label" json:"name"`
	URL          string        `hcl:"url,attr" json:"url"`
	OnFailure    string        `hcl:"on_failure,attr" json:"on_failure"`
	Timeout      Duration      `hcl:"timeout,attr" json:"timeout"`
	AllowPrivate bool          `hcl:"allow_private,attr" json:"allow_private"`

	TLS      ForwardTLS          `hcl:"tls,block" json:"tls,omitempty"`
	Request  ForwardAuthRequest  `hcl:"request,block" json:"request"`
	Response ForwardAuthResponse `hcl:"response,block" json:"response"`
}

type ForwardTLS struct {
	Enabled            expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	InsecureSkipVerify bool          `hcl:"insecure_skip_verify,attr" json:"insecure_skip_verify"`
	ClientCert         expect.Value  `hcl:"client_cert,attr" json:"client_cert"`
	ClientKey          expect.Value  `hcl:"client_key,attr" json:"client_key"`
	CA                 expect.Value  `hcl:"ca,attr" json:"ca"`
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

type ForwardAuthResponse struct {
	Enabled     expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	CopyHeaders []string      `hcl:"copy_headers,attr" json:"copy_headers"`
	CacheTTL    Duration      `hcl:"cache_ttl,attr" json:"cache_ttl"`
}

// Validate checks that the forward_auth block is correctly configured.
// When allow_private is false (the default), the target URL is checked against
// RFC-1918, loopback, and link-local ranges to prevent SSRF attacks.
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

	if !f.AllowPrivate {
		if err := RejectPrivateURL(f.URL); err != nil {
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

// rejectPrivateURL resolves the host in rawURL and returns an error if any
// resolved address falls within RFC-1918, loopback, or link-local ranges.
// DNS resolution is attempted first; if that fails the host is parsed as a
// literal IP. This provides config-time SSRF protection — a second runtime
// check in the middleware handles TOCTOU cases where DNS changes after startup.
func RejectPrivateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.Newf("invalid URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return errors.New("URL has no host")
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		// Treat unresolvable hosts as potentially safe at config time;
		// the runtime check in the middleware will catch them on first use.
		if ip := net.ParseIP(host); ip != nil {
			addrs = []string{ip.String()}
		} else {
			return nil
		}
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return errors.Newf("host %q resolves to private/loopback address %s", host, ip)
		}
	}
	return nil
}

// isPrivateIP reports whether ip falls within a private, loopback, or
// link-local range that must not be reachable from a forward_auth target
// unless allow_private = true is explicitly set.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}

	for _, cidr := range private {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
