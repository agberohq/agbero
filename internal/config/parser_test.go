package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParser_GlobalConfig(t *testing.T) {
	content := `
		bind = ":8080"
		hosts_dir = "./custom_hosts"
		le_email = "test@example.com"
		development = true
	`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.hcl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	var global GlobalConfig
	p := NewParser(path)
	if err := p.Unmarshal(&global); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if global.Bind != ":8080" {
		t.Errorf("expected bind :8080, got %s", global.Bind)
	}
	if global.Development != true {
		t.Error("expected development true")
	}
}

func TestParser_HostConfig(t *testing.T) {
	// FIX: server_names -> domains
	content := `
		domains = ["app.com"]
		
		route "/api" {
			backends = ["http://localhost:3000"]
			strip_prefixes = ["/api"]
		}
	`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "app.hcl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	host, err := ParseHostConfig(path)
	if err != nil {
		t.Fatalf("ParseHostConfig failed: %v", err)
	}

	if len(host.Domains) != 1 || host.Domains[0] != "app.com" {
		t.Errorf("unexpected domains: %v", host.Domains)
	}
	if len(host.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(host.Routes))
	}
	if host.Routes[0].Path != "/api" {
		t.Errorf("expected path /api, got %s", host.Routes[0].Path)
	}
}
