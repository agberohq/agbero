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
