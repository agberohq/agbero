package alaye

import (
	"net"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Proxy struct {
	Enabled        expect.Toggle  `hcl:"enabled,attr" json:"enabled"`
	Name           string         `hcl:"name,label" json:"name"`
	Listen         string         `hcl:"listen,attr" json:"listen"`
	SNI            string         `hcl:"sni,attr" json:"sni"`
	Strategy       string         `hcl:"strategy,attr" json:"strategy"`
	ProxyProtocol  bool           `hcl:"proxy_protocol,attr" json:"proxy_protocol"`
	MaxConnections int64          `hcl:"max_connections,attr" json:"max_connections"`
	Backends       []Server       `hcl:"backend,block" json:"backends"`
	HealthCheck    TCPHealthCheck `hcl:"health_check,block" json:"health_check"`

	// UDP-specific fields. Ignored when Protocol is "tcp" (default).
	Protocol    string   `hcl:"protocol,attr"    json:"protocol"`      // "tcp" (default) or "udp"
	Matcher     string   `hcl:"matcher,attr"     json:"matcher"`       // "stun", "dns", "sip", "" (src:port)
	SessionTTL  Duration `hcl:"session_ttl,attr" json:"session_ttl"`   // UDP session idle timeout
	MaxSessions int64    `hcl:"max_sessions,attr" json:"max_sessions"` // max concurrent UDP sessions
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

	for i := range t.Backends {
		if err := t.Backends[i].Validate(); err != nil {
			return errors.Newf("backend[%d]: %w", i, err)
		}
	}

	return t.HealthCheck.Validate()
}

type TCPHealthCheck struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Interval Duration      `hcl:"interval,attr" json:"interval"`
	Timeout  Duration      `hcl:"timeout,attr" json:"timeout"`
	Send     string        `hcl:"send,attr" json:"send"`
	Expect   string        `hcl:"expect,attr" json:"expect"`
}

func (t *TCPHealthCheck) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}
	switch {
	case t.Interval < 0:
		return errors.New("health_check.interval cannot be negative")
	case t.Timeout < 0:
		return errors.New("health_check.timeout cannot be negative")
	}
	return nil
}

// IsUDP returns true when this proxy is configured for UDP transport.
func (t *Proxy) IsUDP() bool {
	return strings.EqualFold(t.Protocol, "udp")
}

func (t *Proxy) BackendKey(backendAddr string) BackendKey {
	if t.IsUDP() {
		return BackendKey{
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
	return BackendKey{
		Protocol: "tcp",
		Domain:   t.Listen,
		Path:     sni,
		Addr:     backendAddr,
	}
}
