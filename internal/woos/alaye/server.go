package alaye

import (
	"net"
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Criteria struct {
	SourceIPs []string          `hcl:"source_ips,optional" json:"source_ips"`
	Headers   map[string]string `hcl:"headers,optional" json:"headers"`
}

// Server represents an upstream server configuration
type Server struct {
	Address        string    `hcl:"address" json:"address"`
	Weight         int       `hcl:"weight,optional" json:"weight"`
	Criteria       Criteria  `hcl:"criteria,block" json:"criteria"`
	Streaming      Streaming `hcl:"streaming,block" json:"streaming"` // optional by nature when pointer
	MaxConnections int64     `hcl:"max_connections,optional" json:"max_connections"`
}

type Streaming struct {
	Status        Enabled       `hcl:"enabled,optional" json:"enabled"`
	FlushInterval time.Duration `hcl:"flush_interval,optional" json:"flush_interval"`
}

func (s *Streaming) EffectiveFlushInterval() time.Duration {
	if s == nil || !s.Status.Yes() {
		return -1
	}
	if s.FlushInterval <= 0 {
		return DefaultProxyFlushInterval
	}
	return s.FlushInterval
}

func NewServer(address string) Server {
	return Server{Address: address}
}

func NewServers(address ...string) []Server {
	servers := make([]Server, len(address))
	for i, addr := range address {
		servers[i] = Server{Address: addr}
	}
	return servers
}

func (b Server) IsHTTP() bool {
	return strings.HasPrefix(b.Address, HTTPPrefix)
}

func (b Server) IsHTTPS() bool {
	return strings.HasPrefix(b.Address, HTTPSPrefix)
}

func (b Server) IsTCP() bool {
	return strings.HasPrefix(b.Address, TCPPrefix)
}

func (b Server) String() string {
	return b.Address
}

func (b *Server) Validate() error {
	if b.Address == "" {
		return ErrBackendAddressRequired
	}

	if !b.IsHTTP() && !b.IsHTTPS() {
		// We can allow TCP later, but strictly speaking httputil needs http/s
		return errors.Newf("%w: backend %q must start with http:// or https://", ErrBackendInvalidScheme, b.Address)
	}

	if b.Weight < 0 {
		return ErrBackendNegativeWeight
	}

	// Default weight
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
