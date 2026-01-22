package woos

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

		timeouts {
			read = "1s"
		}

		rate_limits {
			ttl = "10m"
			max_entries = 123

			global { requests = 5 window = "1s" burst = 9 }
			auth   { requests = 1 window = "1m" burst = 1 }
		}
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
	if global.HostsDir != "./custom_hosts" {
		t.Errorf("expected hosts_dir ./custom_hosts, got %s", global.HostsDir)
	}
	if global.LEEmail != "test@example.com" {
		t.Errorf("expected le_email test@example.com, got %s", global.LEEmail)
	}
	if global.Development != true {
		t.Error("expected development true")
	}

	if global.Timeouts.Read != "1s" {
		t.Errorf("expected timeouts.read 1s, got %q", global.Timeouts.Read)
	}

	if global.RateLimits.TTL != "10m" {
		t.Errorf("expected rate_limits.ttl 10m, got %q", global.RateLimits.TTL)
	}
	if global.RateLimits.MaxEntries != 123 {
		t.Errorf("expected max_entries 123, got %d", global.RateLimits.MaxEntries)
	}
	if global.RateLimits.Global.Requests != 5 || global.RateLimits.Global.Window != "1s" || global.RateLimits.Global.Burst != 9 {
		t.Errorf("unexpected global policy: %+v", global.RateLimits.Global)
	}
	if global.RateLimits.Auth.Requests != 1 || global.RateLimits.Auth.Window != "1m" || global.RateLimits.Auth.Burst != 1 {
		t.Errorf("unexpected auth policy: %+v", global.RateLimits.Auth)
	}
}

func TestParser_HostConfig(t *testing.T) {
	content := `
		domains = ["app.com"]

		web { root = "." index = "index.html" }

		route "/api" {
			backends = ["http://localhost:3000"]
			strip_prefixes = ["/api"]
			lb_strategy = "leastconn"
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
	if host.Web == nil {
		t.Fatalf("expected web block")
	}
	if host.Web.Root.String() != "." {
		t.Errorf("expected web.root '.', got %q", host.Web.Root.String())
	}
	if host.Web.Index != "index.html" {
		t.Errorf("expected web.index index.html, got %q", host.Web.Index)
	}

	if len(host.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(host.Routes))
	}
	if host.Routes[0].Path != "/api" {
		t.Errorf("expected path /api, got %s", host.Routes[0].Path)
	}
	if host.Routes[0].LBStrategy != "leastconn" {
		t.Errorf("expected lb_strategy leastconn, got %q", host.Routes[0].LBStrategy)
	}
}
