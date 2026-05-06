package alaye

import (
	"github.com/agberohq/agbero/internal/core/expect"
)

type Backend struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Strategy string        `hcl:"strategy,attr,omitempty" json:"strategy,omitempty"`
	Keys     []string      `hcl:"keys,attr,omitempty" json:"keys,omitempty"`

	Servers []Server `hcl:"server,block" json:"servers"`

	// Via references a named tunnel block defined in the global config.
	// All backends in this block will route outbound connections through
	// the named tunnel. Mutually exclusive with Tunnel.
	//
	// Example:
	//   via = "tor"
	Via string `hcl:"via,attr,omitempty" json:"via,omitempty"`

	// Tunnel is the inline shorthand for a single-server SOCKS5 tunnel.
	// Use the full `tunnel {}` block with `via` for multi-server pools
	// or when the same tunnel is shared across multiple routes.
	// Mutually exclusive with Via.
	//
	// Example:
	//   tunnel = "socks5://127.0.0.1:9050"
	//   tunnel = "socks5://user:pass@vpn.example.com:1080"
	Tunnel string `hcl:"tunnel,attr,omitempty" json:"tunnel,omitempty"`
}

func (b Backend) IsZero() bool {
	return b.Enabled.IsZero() &&
		b.Strategy == "" &&
		len(b.Keys) == 0 &&
		len(b.Servers) == 0 &&
		b.Via == "" &&
		b.Tunnel == ""
}

// HasTunnel reports whether this backend routes through a tunnel (either
// inline or via a named reference).
func (b Backend) HasTunnel() bool {
	return b.Via != "" || b.Tunnel != ""
}
