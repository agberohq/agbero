package alaye

import (
	"fmt"
	"net"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

// Tunnel defines a named outbound tunnel pool for routing backend connections
// through SOCKS5 proxies. Tunnels are declared at global config level and
// referenced by backend blocks via the `via` attribute.
//
// Example — two Tor circuits in round-robin:
//
//	tunnel "tor" {
//	  enabled  = true
//	  protocol = "socks5"
//	  servers  = ["127.0.0.1:9050", "127.0.0.1:9051"]
//	  strategy = "round_robin"
//	}
//
// Example — authenticated VPS exit node:
//
//	tunnel "vpn-exit" {
//	  enabled  = true
//	  protocol = "socks5"
//	  servers  = ["vpn.example.com:1080"]
//	  username = "myuser"
//	  password = "secret"
//	}
type Tunnel struct {
	Enabled  expect.Toggle   `hcl:"enabled,attr"            json:"enabled"`
	Name     string          `hcl:"name,label"              json:"name"`
	Protocol string          `hcl:"protocol,attr"           json:"protocol"`
	Servers  []string        `hcl:"servers,attr"            json:"servers"`
	Username expect.Value    `hcl:"username,attr,omitempty" json:"username,omitempty"`
	Password expect.Value    `hcl:"password,attr,omitempty" json:"password,omitempty"`
	Strategy string          `hcl:"strategy,attr,omitempty" json:"strategy,omitempty"`
	Timeout  expect.Duration `hcl:"timeout,attr,omitempty"  json:"timeout,omitempty"`
}

// Validate checks that the tunnel configuration is complete and consistent.
// It does not set defaults — call woos.DefaultTunnel before Validate.
func (t *Tunnel) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}
	if t.Name == "" {
		return errors.New("tunnel: name is required")
	}
	if t.Protocol == "" {
		return errors.Newf("tunnel %q: protocol is required (use \"socks5\")", t.Name)
	}
	if t.Protocol != def.SOCKS5 {
		return errors.Newf("tunnel %q: protocol %q is not supported — only \"socks5\" is accepted", t.Name, t.Protocol)
	}
	if len(t.Servers) == 0 {
		return errors.Newf("tunnel %q: at least one server is required", t.Name)
	}
	for i, s := range t.Servers {
		if err := validateTunnelServer(t.Name, i, s); err != nil {
			return err
		}
	}
	if t.Strategy != "" &&
		t.Strategy != def.TunnelStrategyRoundRobin &&
		t.Strategy != def.TunnelStrategyRandom {
		return errors.Newf(
			"tunnel %q: strategy %q is not supported — use \"round_robin\" or \"random\"",
			t.Name, t.Strategy,
		)
	}
	if t.Timeout < 0 {
		return errors.Newf("tunnel %q: timeout cannot be negative", t.Name)
	}
	return nil
}

// validateTunnelServer checks that a single server entry is a valid host:port pair.
func validateTunnelServer(tunnelName string, idx int, server string) error {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return errors.Newf(
			"tunnel %q: servers[%d] %q is not a valid host:port — %w",
			tunnelName, idx, server, err,
		)
	}
	if host == "" {
		return errors.Newf("tunnel %q: servers[%d] %q: host cannot be empty", tunnelName, idx, server)
	}
	if port == "" {
		return errors.Newf("tunnel %q: servers[%d] %q: port cannot be empty", tunnelName, idx, server)
	}
	return nil
}

// IsZero reports whether this Tunnel is empty (all zero values).
func (t *Tunnel) IsZero() bool {
	return t.Enabled.IsZero() &&
		t.Name == "" &&
		t.Protocol == "" &&
		len(t.Servers) == 0 &&
		t.Username == "" &&
		t.Password == "" &&
		t.Strategy == "" &&
		t.Timeout == 0
}

// DisplayAddr returns a loggable, credential-free representation of the
// tunnel's server list. Passwords are never included.
func (t *Tunnel) DisplayAddr() string {
	if len(t.Servers) == 1 {
		if t.Username != "" {
			return fmt.Sprintf("socks5://%s@%s", t.Username, t.Servers[0])
		}
		return fmt.Sprintf("socks5://%s", t.Servers[0])
	}
	return fmt.Sprintf("socks5://[%d servers, strategy=%s]", len(t.Servers), t.Strategy)
}
