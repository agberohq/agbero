package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type TunnelConfig struct {
	Client  *TunnelClient  `hcl:"client,block" json:"client,omitempty"`
	Gateway *TunnelGateway `hcl:"gateway,block" json:"gateway,omitempty"`
}

// TunnelClient configures Agbero to act as an FRP Client (frpc).
// Use Case: Exposing a local dev server to the internet.
type TunnelClient struct {
	Enabled    bool              `hcl:"enabled" json:"enabled"`
	ServerAddr string            `hcl:"server_addr" json:"server_addr"` // e.g. "connect.agbero.com:443"
	Subdomain  string            `hcl:"subdomain" json:"subdomain"`     // e.g. "blog"
	RemotePort int               `hcl:"remote_port,optional" json:"remote_port"`
	Auth       map[string]string `hcl:"auth,optional" json:"auth"`         // User/Token
	Protocol   string            `hcl:"protocol,optional" json:"protocol"` // "tcp", "kcp", "websocket", "wss"
}

// TunnelGateway configures Agbero to act as a secure ingress for FRP connections.
// Use Case: Hosting the tunnel server securely behind Agbero.
type TunnelGateway struct {
	Enabled  bool   `hcl:"enabled" json:"enabled"`
	Upstream string `hcl:"upstream" json:"upstream"` // Address of the internal frps, e.g. "127.0.0.1:7000"
}

func (tc *TunnelConfig) Validate() error {
	if tc == nil {
		return nil
	}

	if tc.Client != nil && tc.Client.Enabled {
		if tc.Client.ServerAddr == "" {
			return errors.New("tunnel.client: server_addr is required")
		}
		// Default protocol to wss (secure websocket) if 443, else tcp
		if tc.Client.Protocol == "" {
			if strings.HasSuffix(tc.Client.ServerAddr, ":443") {
				tc.Client.Protocol = "wss"
			} else {
				tc.Client.Protocol = "tcp"
			}
		}
	}

	if tc.Gateway != nil && tc.Gateway.Enabled {
		if tc.Gateway.Upstream == "" {
			return errors.New("tunnel.gateway: upstream address is required")
		}
	}

	return nil
}
