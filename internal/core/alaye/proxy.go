package alaye

import (
	"net"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Proxy struct {
	Enabled        expect.Toggle       `hcl:"enabled,attr" json:"enabled"`
	Name           string              `hcl:"name,label" json:"name"`
	Listen         string              `hcl:"listen,attr" json:"listen"`
	SNI            string              `hcl:"sni,attr,omitempty" json:"sni,omitempty"`
	Strategy       string              `hcl:"strategy,attr,omitempty" json:"strategy,omitempty"`
	ProxyProtocol  bool                `hcl:"proxy_protocol,attr,omitempty" json:"proxy_protocol,omitempty"`
	MaxConnections int64               `hcl:"max_connections,attr,omitempty" json:"max_connections,omitempty"`
	Backends       []Server            `hcl:"backend,block,omitempty" json:"backends,omitempty"`
	HealthCheck    HealthCheckProtocol `hcl:"health_check,block,omitempty" json:"health_check,omitempty"`

	Protocol    string          `hcl:"protocol,attr,omitempty" json:"protocol,omitempty"`
	Matcher     string          `hcl:"matcher,attr,omitempty" json:"matcher,omitempty"`
	SessionTTL  expect.Duration `hcl:"session_ttl,attr,omitempty" json:"session_ttl,omitempty"`
	MaxSessions int64           `hcl:"max_sessions,attr,omitempty" json:"max_sessions,omitempty"`

	// DNSBlock configures domain-level blocking for UDP DNS proxy routes.
	// Only evaluated when Protocol = "udp" and Matcher = "dns".
	// Blocked queries receive a synthesised NXDOMAIN response without
	// forwarding to any upstream resolver.
	DNSBlock DNSBlock `hcl:"dns_block,block,omitempty" json:"dns_block,omitempty"`
}

// DNSBlock configures the DNS domain blocklist for a UDP proxy route.
type DNSBlock struct {
	Enabled expect.Toggle   `hcl:"enabled,attr"          json:"enabled"`
	Domains []string        `hcl:"domains,attr"          json:"domains,omitempty"`  // inline domain list
	Files   []string        `hcl:"files,attr,omitempty"  json:"files,omitempty"`    // local file paths (hosts-file or bare-domain format)
	URLs    []string        `hcl:"urls,attr,omitempty"   json:"urls,omitempty"`     // remote blocklist URLs (Pi-hole / StevenBlack compatible)
	Refresh expect.Duration `hcl:"refresh,attr,omitempty" json:"refresh,omitempty"` // URL refresh interval (default 24h)
	Mode    string          `hcl:"mode,attr,omitempty"   json:"mode,omitempty"`     // "nxdomain" (default) | "drop"
}

// Validate checks DNSBlock configuration.
// It does not set defaults — all defaults are applied by woos.defaultDNSBlock.
func (d *DNSBlock) Validate() error {
	if d.Enabled.NotActive() {
		return nil
	}
	if d.Mode != "" && d.Mode != "nxdomain" && d.Mode != "drop" {
		return errors.New("dns_block: mode must be \"nxdomain\" or \"drop\"")
	}
	if d.Refresh < 0 {
		return errors.New("dns_block: refresh interval cannot be negative")
	}
	return nil
}

// IsZero reports whether this DNSBlock is unconfigured.
func (d DNSBlock) IsZero() bool {
	return d.Enabled.IsZero() &&
		len(d.Domains) == 0 &&
		len(d.Files) == 0 &&
		len(d.URLs) == 0 &&
		d.Refresh == 0 &&
		d.Mode == ""
}

// Validate checks listen address, SNI pattern, strategy, and backends.
// It does not set defaults — all defaults are applied by woos.defaultTCPRoute.
func (t *Proxy) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}

	switch {
	case t.Name == "":
		return errors.New("route name required")
	case t.Listen == "":
		return errors.New("listen address required")
	case len(t.Backends) == 0:
		return errors.New("at least one backend required")
	}

	if _, _, err := net.SplitHostPort(t.Listen); err != nil {
		return errors.Newf("invalid listen address %q: %w", t.Listen, err)
	}

	if t.SNI != "" {
		if strings.Contains(t.SNI, "..") ||
			strings.HasPrefix(t.SNI, ".") ||
			strings.HasSuffix(t.SNI, ".") {
			return errors.Newf("invalid SNI pattern %q", t.SNI)
		}
		if strings.Contains(t.SNI, "*") && !strings.HasPrefix(t.SNI, "*.") {
			return errors.Newf("invalid wildcard in SNI %q: only leading *. allowed", t.SNI)
		}
	}

	if t.Strategy != "" && !ValidateStrategy(t.Strategy) {
		return errors.Newf("invalid strategy %q", t.Strategy)
	}

	if t.MaxConnections < 0 {
		return errors.New("max_connections cannot be negative")
	}

	if t.ProxyProtocol && t.IsUDP() {
		return errors.New("proxy_protocol is not supported for UDP — PROXY protocol requires a TCP connection")
	}

	for i := range t.Backends {
		if err := t.Backends[i].Validate(); err != nil {
			return errors.Newf("backend[%d]: %w", i, err)
		}
	}

	if err := t.DNSBlock.Validate(); err != nil {
		return errors.Newf("dns_block: %w", err)
	}

	return t.HealthCheck.Validate()
}

// IsUDP returns true when this proxy is configured for UDP transport.
func (t *Proxy) IsUDP() bool {
	return strings.EqualFold(t.Protocol, "udp")
}

func (t *Proxy) IsTCP() bool {
	return !t.IsUDP()
}

func (t *Proxy) IsZero() bool {
	return t.Enabled.IsZero() &&
		t.Name == "" &&
		t.Listen == "" &&
		t.SNI == "" &&
		t.Strategy == "" &&
		t.ProxyProtocol == false &&
		t.MaxConnections == 0 &&
		len(t.Backends) == 0 &&
		t.HealthCheck.IsZero() &&
		t.DNSBlock.IsZero()
}

func (t *Proxy) BackendKey(backendAddr string) Key {
	if t.IsUDP() {
		return Key{
			Protocol: "udp",
			Domain:   t.Listen,
			Path:     t.Name,
			Addr:     backendAddr,
		}
	}
	sni := t.SNI
	if sni == "" {
		sni = "*"
	}
	return Key{
		Protocol: "tcp",
		Domain:   t.Listen,
		Path:     sni,
		Addr:     backendAddr,
	}
}
