package parser

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestUnmarshalGlobal_mcp(t *testing.T) {
	path := writeTemp(t, `
version = 1

bind {
  http = [":8080"]
}

mcp {
  enabled      = "on"
  transport    = "stdio"
  rate_limit   = "60/m"

  read {
    enabled = "on"
    allow   = ["status", "config.host"]
    hosts   = ["app.example.com"]
  }

  plan {
    enabled         = "on"
    allow           = ["config.plan", "config.validate"]
    hosts           = ["app.example.com"]
    max_input_bytes = 4194304
  }
}
`)

	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !g.MCP.Enabled.Active() {
		t.Fatal("mcp.enabled was not decoded")
	}
	if g.MCP.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", g.MCP.Transport)
	}
	if !g.MCP.Read.Enabled.Active() || len(g.MCP.Read.Allow) != 2 {
		t.Errorf("read block not decoded: %+v", g.MCP.Read)
	}
	if !g.MCP.Plan.Enabled.Active() || g.MCP.Plan.MaxInputBytes != 4194304 {
		t.Errorf("plan block not decoded: %+v", g.MCP.Plan)
	}
	if g.MCP.Apply.Enabled != expect.Unknown {
		t.Errorf("apply.enabled = %v, want Unknown", g.MCP.Apply.Enabled)
	}
}
