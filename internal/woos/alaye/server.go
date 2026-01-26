package alaye

import (
	"net"
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Conditions struct {
	SourceIPs []string          `hcl:"source_ips,optional"`
	Headers   map[string]string `hcl:"headers,optional"`
}

// Server represents an upstream server configuration
type Server struct {
	Address    string      `hcl:"address"`
	Weight     int         `hcl:"weight,optional"`
	Conditions *Conditions `hcl:"conditions,block"`
	Streaming  *Streaming  `hcl:"streaming,block"` // optional by nature when pointer
}

type Streaming struct {
	Enabled       bool          `hcl:"enabled,optional"`
	FlushInterval time.Duration `hcl:"flush_interval,optional"`
}

func (s *Streaming) EffectiveFlushInterval() time.Duration {
	if s == nil || !s.Enabled {
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
	return strings.HasPrefix(b.Address, "http://")
}

func (b Server) IsHTTPS() bool {
	return strings.HasPrefix(b.Address, "https://")
}

func (b Server) IsTCP() bool {
	return strings.HasPrefix(b.Address, "tcp://")
}

func (b Server) String() string {
	return b.Address
}

func (b *Server) Validate() error {
	if b.Address == "" {
		return errors.New("backend address is required")
	}

	if !b.IsHTTP() && !b.IsHTTPS() {
		// We can allow TCP later, but strictly speaking httputil needs http/s
		return errors.Newf("backend %q must start with http:// or https://", b.Address)
	}

	if b.Weight < 0 {
		return errors.New("backend weight cannot be negative")
	}

	// Default weight
	if b.Weight == 0 {
		b.Weight = 1
	}

	if b.Conditions != nil {
		for _, ip := range b.Conditions.SourceIPs {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				if net.ParseIP(ip) == nil {
					return errors.Newf("invalid source ip/cidr condition: %s", ip)
				}
			}
		}
	}

	return nil
}
