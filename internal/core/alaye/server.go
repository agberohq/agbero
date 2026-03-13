// internal/core/alaye/server.go
package alaye

import (
	"net"
	"time"

	"github.com/olekukonko/errors"
)

type Criteria struct {
	SourceIPs []string          `hcl:"source_ips,optional" json:"source_ips"`
	Headers   map[string]string `hcl:"headers,optional" json:"headers"`
}

// Server represents an upstream server configuration
type Server struct {
	Address        Address   `hcl:"address" json:"address"` // Upgraded to alaye.Address
	Weight         int       `hcl:"weight,optional" json:"weight"`
	Criteria       Criteria  `hcl:"criteria,block" json:"criteria"`
	Streaming      Streaming `hcl:"streaming,block" json:"streaming"`
	MaxConnections int64     `hcl:"max_connections,optional" json:"max_connections"`
}

type Streaming struct {
	Enabled       Enabled       `hcl:"enabled,optional" json:"enabled"`
	FlushInterval time.Duration `hcl:"flush_interval,optional" json:"flush_interval"`
}

func (s *Streaming) EffectiveFlushInterval() time.Duration {
	if s == nil || !s.Enabled.Active() {
		return -1
	}
	if s.FlushInterval <= 0 {
		return DefaultProxyFlushInterval
	}
	return s.FlushInterval
}

func NewServer(address string) Server {
	return Server{Address: Address(address)}
}

func NewServers(address ...string) []Server {
	servers := make([]Server, len(address))
	for i, addr := range address {
		servers[i] = Server{Address: Address(addr)}
	}
	return servers
}

func (b Server) IsHTTP() bool {
	return b.Address.Scheme() == "http" || b.Address.Scheme() == ""
}

func (b Server) IsHTTPS() bool {
	return b.Address.Scheme() == "https"
}

func (b Server) IsTCP() bool {
	return b.Address.Scheme() == "tcp"
}

func (b Server) String() string {
	return b.Address.String()
}

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
