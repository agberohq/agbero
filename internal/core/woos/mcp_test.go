package woos

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestDefaultMCP(t *testing.T) {
	var m alaye.MCP
	D.MCP(&m)

	if m.Enabled != expect.Inactive {
		t.Errorf("Enabled = %v, want Inactive", m.Enabled)
	}
	if m.Transport != "stdio" {
		t.Errorf("Transport = %q, want stdio", m.Transport)
	}
	if m.RateLimit != "60/m" {
		t.Errorf("RateLimit = %q, want 60/m", m.RateLimit)
	}
	if m.Plan.MaxInputBytes != def.HostConfigMaxBytes {
		t.Errorf("MaxInputBytes = %d, want %d", m.Plan.MaxInputBytes, def.HostConfigMaxBytes)
	}
	if len(m.AllowedIPs) != 2 || m.AllowedIPs[0] != "127.0.0.1/32" || m.AllowedIPs[1] != "::1/128" {
		t.Errorf("AllowedIPs = %v, want loopback default", m.AllowedIPs)
	}
	if m.Read.Enabled != expect.Inactive || m.Plan.Enabled != expect.Inactive {
		t.Error("read/plan must default to inactive")
	}
}

func TestDefaultMCPRouteEnablesSessionAffinityAndDisablesBuffering(t *testing.T) {
	r := &alaye.Route{
		Path:     "/mcp",
		Protocol: def.RouteProtocolMCP,
		Backends: alaye.Backend{
			Enabled: expect.Active,
			Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:9000")},
		},
	}
	D.Route(r)

	if r.Backends.Strategy != def.StrategySticky {
		t.Fatalf("strategy = %q, want sticky", r.Backends.Strategy)
	}
	found := false
	for _, k := range r.Backends.Keys {
		if k == def.MCPSessionKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("keys = %v, want %s", r.Backends.Keys, def.MCPSessionKey)
	}
	if r.Compression.Enabled.Active() {
		t.Fatal("compression must be off for MCP")
	}
	if r.Cache.Enabled.Active() {
		t.Fatal("cache must be off for MCP")
	}
}
