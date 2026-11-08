package mcp

import (
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

func TestAdminBackendURL(t *testing.T) {
	cases := map[string]string{
		":9090":          "http://127.0.0.1:9090/mcp/",
		"0.0.0.0:9090":   "http://127.0.0.1:9090/mcp/",
		"127.0.0.1:9090": "http://127.0.0.1:9090/mcp/",
		"[::1]:9090":     "http://[::1]:9090/mcp/",
		"localhost:9090": "http://localhost:9090/mcp/",
		"not-an-address": "http://127.0.0.1:9090/mcp/",
	}
	for in, want := range cases {
		if got := AdminBackendURL(in); got != want {
			t.Errorf("AdminBackendURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMCPLocalhostConfig(t *testing.T) {
	cfg := string(MCPLocalhostConfig(":9090", []string{"localhost", "192.168.0.0/16"}))
	for _, want := range []string{
		`domains = ["mcp.localhost"]`,
		`protocol = "mcp"`,
		`address = "http://127.0.0.1:9090/mcp/"`,
		`"127.0.0.1/32"`,
		`"::1/128"`,
		`"192.168.0.0/16"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}

func TestWriteMCPLocalhostIsIdempotent(t *testing.T) {
	dir := expect.NewFolder(t.TempDir())
	path, created, err := WriteMCPLocalhost(dir, ":9090", nil)
	if err != nil || !created {
		t.Fatalf("first write: created=%v err=%v", created, err)
	}
	if _, err := parser.ParseHostConfig(path); err != nil {
		t.Fatalf("generated host does not parse: %v", err)
	}
	_, created, err = WriteMCPLocalhost(dir, ":9090", nil)
	if err != nil || created {
		t.Fatalf("second write must not recreate: created=%v err=%v", created, err)
	}
	exists, managed, err := MCPLocalhostManaged(dir)
	if err != nil || !exists || !managed {
		t.Fatalf("managed check: exists=%v managed=%v err=%v", exists, managed, err)
	}
	if removed, err := RemoveMCPLocalhost(dir); err != nil || !removed {
		t.Fatalf("remove: removed=%v err=%v", removed, err)
	}
}
