package alaye

import (
	"net"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Server struct {
	Enabled        expect.Toggle  `hcl:"enabled,attr" json:"enabled"`
	Address        expect.Address `hcl:"address,attr" json:"address"`
	Weight         int            `hcl:"weight,attr,omitempty" json:"weight,omitempty"`
	MaxConnections int64          `hcl:"max_connections,attr,omitempty" json:"max_connections,omitempty"`
	Criteria       Criteria       `hcl:"criteria,block,omitempty" json:"criteria,omitempty"`
	Streaming      Streaming      `hcl:"streaming,block,omitempty" json:"streaming,omitempty"`
}

// NewServer constructs a Server with the given address and a default weight of zero.
func NewServer(address string) Server {
	return Server{Address: expect.Address(address)}
}

// NewServers constructs a slice of Servers from a list of addresses.
func NewServers(address ...string) []Server {
	servers := make([]Server, len(address))
	for i, addr := range address {
		servers[i] = Server{Address: expect.Address(addr)}
	}
	return servers
}

// IsHTTP reports whether the server address uses the HTTP scheme or no scheme.
func (b Server) IsHTTP() bool {
	return b.Address.Scheme() == "http" || b.Address.Scheme() == ""
}

// IsHTTPS reports whether the server address uses the HTTPS scheme.
func (b Server) IsHTTPS() bool {
	return b.Address.Scheme() == "https"
}

// IsTCP reports whether the server address uses the TCP scheme.
func (b Server) IsTCP() bool {
	return b.Address.Scheme() == "tcp"
}

// IsFastCGI reports whether the server address uses the cgi:// scheme.
//
// cgi:// backends communicate with the upstream over the FastCGI wire protocol
// instead of HTTP, eliminating request-smuggling risks and providing structural
// separation between proxy-injected parameters (REMOTE_ADDR, HTTPS, etc.) and
// client-supplied HTTP headers (always transmitted with an HTTP_ prefix by the
// FastCGI protocol).
//
// Two address forms are accepted:
//
//	cgi://127.0.0.1:9001          — TCP
//	cgi://unix:/var/run/app.sock  — UNIX domain socket
//
// Note: WebSocket upgrades are not supported on cgi:// backends. The FastCGI
// protocol predates WebSockets and has no mechanism to tunnel them.
func (b Server) IsFastCGI() bool {
	return b.Address.Scheme() == def.FastCGI
}

// FastCGINetwork returns the network type and dialing address for a cgi:// server.
//
// For TCP backends:
//
//	cgi://127.0.0.1:9001  ->  ("tcp", "127.0.0.1:9001")
//
// For UNIX socket backends:
//
//	cgi://unix:/var/run/app.sock  ->  ("unix", "/var/run/app.sock")
//
// Returns ("", "") if the server is not a FastCGI backend.
func (b Server) FastCGINetwork() (network, address string) {
	if !b.IsFastCGI() {
		return "", ""
	}
	// HostPort strips the leading "cgi://" prefix.
	raw := b.Address.HostPort()
	if after, ok := strings.CutPrefix(raw, "unix:"); ok {
		return "unix", after
	}
	return "tcp", raw
}

// String returns the string form of the server address.
func (b Server) String() string {
	return b.Address.String()
}

// Validate checks that the address is non-empty, weight is non-negative, and source IPs are valid.
func (b *Server) Validate() error {
	if err := b.Address.Validate(); err != nil {
		return def.ErrBackendAddressRequired
	}
	if b.Weight < 0 {
		return def.ErrBackendNegativeWeight
	}
	if b.Weight == 0 {
		b.Weight = 1
	}
	if b.IsFastCGI() {
		network, addr := b.FastCGINetwork()
		if network == "" || strings.TrimSpace(addr) == "" {
			return def.ErrFastCGIMissingHost
		}
	}
	for _, ip := range b.Criteria.SourceIPs {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			if net.ParseIP(ip) == nil {
				return errors.Newf("%w: %s", def.ErrBackendInvalidSourceIP, ip)
			}
		}
	}
	return nil
}

type Criteria struct {
	SourceIPs []string          `hcl:"source_ips,attr" json:"source_ips"`
	Headers   map[string]string `hcl:"headers,attr" json:"headers"`
}

func (c Criteria) IsZero() bool { return len(c.SourceIPs) == 0 && len(c.Headers) == 0 }

type Streaming struct {
	Enabled       expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	FlushInterval time.Duration `hcl:"flush_interval,attr" json:"flush_interval"`
}

func (s Streaming) IsZero() bool { return s.Enabled.IsZero() && s.FlushInterval == 0 }

// EffectiveFlushInterval returns the configured flush interval or the default.
// Returns -1 when streaming is disabled to signal buffered mode to the transport.
func (s *Streaming) EffectiveFlushInterval() time.Duration {
	if s == nil || !s.Enabled.Active() {
		return -1
	}
	if s.FlushInterval <= 0 {
		return def.DefaultProxyFlushInterval
	}
	return s.FlushInterval
}
