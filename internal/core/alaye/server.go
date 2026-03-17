package alaye

import (
	"net"
	"time"

	"github.com/olekukonko/errors"
)

type Criteria struct {
	SourceIPs []string          `hcl:"source_ips,attr" json:"source_ips"`
	Headers   map[string]string `hcl:"headers,attr" json:"headers"`
}

type Server struct {
	Address        Address   `hcl:"address,attr" json:"address"`
	Weight         int       `hcl:"weight,attr" json:"weight"`
	MaxConnections int64     `hcl:"max_connections,attr" json:"max_connections"`
	Criteria       Criteria  `hcl:"criteria,block" json:"criteria"`
	Streaming      Streaming `hcl:"streaming,block" json:"streaming"`
}

type Streaming struct {
	Enabled       Enabled       `hcl:"enabled,attr" json:"enabled"`
	FlushInterval time.Duration `hcl:"flush_interval,attr" json:"flush_interval"`
}

// EffectiveFlushInterval returns the configured flush interval or the default.
// Returns -1 when streaming is disabled to signal buffered mode to the transport.
func (s *Streaming) EffectiveFlushInterval() time.Duration {
	if s == nil || !s.Enabled.Active() {
		return -1
	}
	if s.FlushInterval <= 0 {
		return DefaultProxyFlushInterval
	}
	return s.FlushInterval
}

// NewServer constructs a Server with the given address and a default weight of zero.
func NewServer(address string) Server {
	return Server{Address: Address(address)}
}

// NewServers constructs a slice of Servers from a list of addresses.
func NewServers(address ...string) []Server {
	servers := make([]Server, len(address))
	for i, addr := range address {
		servers[i] = Server{Address: Address(addr)}
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

// String returns the string form of the server address.
func (b Server) String() string {
	return b.Address.String()
}

// Validate checks that the address is non-empty, weight is non-negative, and source IPs are valid.
func (b *Server) Validate() error {
	if err := b.Address.Validate(); err != nil {
		return ErrBackendAddressRequired
	}
	if b.Weight < 0 {
		return ErrBackendNegativeWeight
	}
	if b.Weight == 0 {
		b.Weight = 1
	}
	for _, ip := range b.Criteria.SourceIPs {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			if net.ParseIP(ip) == nil {
				return errors.Newf("%w: %s", ErrBackendInvalidSourceIP, ip)
			}
		}
	}
	return nil
}
