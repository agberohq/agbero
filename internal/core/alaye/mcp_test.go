package alaye

import (
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

func validMCP() MCP {
	return MCP{
		Enabled:    expect.Active,
		Transport:  "stdio",
		RateLimit:  "60/m",
		AllowedIPs: []string{"127.0.0.1/32", "::1/128"},
		Read: MCPRead{
			Enabled: expect.Active,
			Allow:   []string{"status", "config.hosts"},
			Hosts:   []string{"app.example.com"},
		},
		Plan: MCPPlan{
			Enabled:       expect.Active,
			Allow:         []string{"config.plan", "config.validate"},
			Hosts:         []string{"app.example.com"},
			MaxInputBytes: def.HostConfigMaxBytes,
		},
	}
}

func TestMCPValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*MCP)
		wantErr string
	}{
		{name: "valid", mutate: func(*MCP) {}},
		{name: "disabled with class on", mutate: func(m *MCP) {
			m.Enabled = expect.Inactive
		}, wantErr: "cannot be enabled while mcp.enabled is off"},
		{name: "no class enabled", mutate: func(m *MCP) {
			m.Read.Enabled = expect.Inactive
			m.Plan.Enabled = expect.Inactive
		}, wantErr: "no class"},
		{name: "empty read allow", mutate: func(m *MCP) {
			m.Read.Allow = nil
		}, wantErr: "read.allow is empty"},
		{name: "unknown capability", mutate: func(m *MCP) {
			m.Read.Allow = []string{"config.secrets"}
		}, wantErr: "unknown capability"},
		{name: "wildcard capability", mutate: func(m *MCP) {
			m.Read.Allow = []string{"*"}
		}, wantErr: "wildcard capabilities"},
		{name: "duplicate capability", mutate: func(m *MCP) {
			m.Read.Allow = []string{"status", "status"}
		}, wantErr: "duplicate capability"},
		{name: "plan cap in read", mutate: func(m *MCP) {
			m.Read.Allow = []string{"config.plan"}
		}, wantErr: "unknown capability"},
		{name: "apply reserved", mutate: func(m *MCP) {
			m.Apply.Enabled = expect.Active
		}, wantErr: "apply is reserved"},
		{name: "tcp transport", mutate: func(m *MCP) {
			m.Transport = "tcp"
		}, wantErr: "not supported"},
		{name: "invalid rate", mutate: func(m *MCP) {
			m.RateLimit = "60"
		}, wantErr: "invalid rate_limit"},
		{name: "oversize candidate", mutate: func(m *MCP) {
			m.Plan.MaxInputBytes = def.HostConfigMaxBytes + 1
		}, wantErr: "exceeds HostConfigMaxBytes"},
		{name: "invalid host", mutate: func(m *MCP) {
			m.Read.Hosts = []string{"bad host"}
		}, wantErr: "read.hosts[0]"},
		{name: "wildcard host read", mutate: func(m *MCP) {
			m.Read.Hosts = []string{"*", "*.internal.example.com"}
		}},
		{name: "lan allowlist", mutate: func(m *MCP) {
			m.AllowedIPs = []string{"127.0.0.1/32", "192.168.0.0/16"}
		}},
		{name: "localhost allowlist", mutate: func(m *MCP) {
			m.AllowedIPs = []string{"localhost"}
		}},
		{name: "invalid allowlist", mutate: func(m *MCP) {
			m.AllowedIPs = []string{"999.1.1.1"}
		}, wantErr: "allowed_ips[0]"},
		{name: "allow every address", mutate: func(m *MCP) {
			m.AllowedIPs = []string{"0.0.0.0/0"}
		}, wantErr: "allows every address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validMCP()
			tt.mutate(&m)
			err := m.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
