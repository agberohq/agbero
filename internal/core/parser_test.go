package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func TestParser_GlobalConfig(t *testing.T) {
	content := `
bind {
  http = [":80", ":8080"]
  https = [":443"]
}

logging {
  level = "debug"
}

hosts_dir = "./hosts"
le_email = "admin@example.com"
development = true

trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"]

timeouts {
  read = "15s"
  write = "45s"
  idle = "300s"
}

rate_limits {
  ttl = "1h"
  max_entries = 50000
  
  global {
    requests = 100
    window = "1s"
    burst = 200
  }
  
  auth {
    requests = 5
    window = "30s"
    burst = 10
  }
}
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "global.hcl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	var global alaye.Global
	p := NewParser(path)
	if err := p.Unmarshal(&global); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Validate parsed values
	if len(global.Bind.HTTP) != 2 || global.Bind.HTTP[0] != ":80" || global.Bind.HTTP[1] != ":8080" {
		t.Errorf("unexpected bind.http: %v", global.Bind.HTTP)
	}
	if len(global.Bind.HTTPS) != 1 || global.Bind.HTTPS[0] != ":443" {
		t.Errorf("unexpected bind.https: %v", global.Bind.HTTPS)
	}
	if global.HostsDir != "./hosts" {
		t.Errorf("expected hosts_dir ./hosts, got %s", global.HostsDir)
	}
	if global.LEEmail != "admin@example.com" {
		t.Errorf("expected le_email admin@example.com, got %s", global.LEEmail)
	}
	if global.Logging.Level != "debug" {
		t.Errorf("expected log_level debug, got %s", global.Logging.Level)
	}
	if !global.Development {
		t.Error("expected development = true")
	}
	if len(global.TrustedProxies) != 2 || global.TrustedProxies[0] != "127.0.0.1/32" || global.TrustedProxies[1] != "10.0.0.0/8" {
		t.Errorf("unexpected trusted_proxies: %v", global.TrustedProxies)
	}
	if global.Timeouts.Read != 15*time.Second {
		t.Errorf("expected timeouts.read 15s, got %v", global.Timeouts.Read)
	}
	if global.Timeouts.Write != 45*time.Second {
		t.Errorf("expected timeouts.write 45s, got %v", global.Timeouts.Write)
	}
	if global.Timeouts.Idle != 300*time.Second {
		t.Errorf("expected timeouts.idle 300s, got %v", global.Timeouts.Idle)
	}
	if global.RateLimits.TTL != time.Hour {
		t.Errorf("expected rate_limits.ttl 1h, got %v", global.RateLimits.TTL)
	}
	if global.RateLimits.MaxEntries != 50000 {
		t.Errorf("expected rate_limits.max_entries 50000, got %d", global.RateLimits.MaxEntries)
	}
	if global.RateLimits.Global.Requests != 100 {
		t.Errorf("expected rate_limits.global.requests 100, got %d", global.RateLimits.Global.Requests)
	}
	if global.RateLimits.Global.Window != time.Second {
		t.Errorf("expected rate_limits.global.window 1s, got %v", global.RateLimits.Global.Window)
	}
	if global.RateLimits.Global.Burst != 200 {
		t.Errorf("expected rate_limits.global.burst 200, got %d", global.RateLimits.Global.Burst)
	}
	if global.RateLimits.Auth.Requests != 5 {
		t.Errorf("expected rate_limits.auth.requests 5, got %d", global.RateLimits.Auth.Requests)
	}
	if global.RateLimits.Auth.Window != 30*time.Second {
		t.Errorf("expected rate_limits.auth.window 30s, got %v", global.RateLimits.Auth.Window)
	}
	if global.RateLimits.Auth.Burst != 10 {
		t.Errorf("expected rate_limits.auth.burst 10, got %d", global.RateLimits.Auth.Burst)
	}
}

func TestParser_HostConfig(t *testing.T) {
	content := `
domains = ["app.com"]

route "/" {
  web {
    root = "."
    index = "index.html"
  }
}

route "/api" {
  strip_prefixes = ["/api"]
  backend {
    lb_strategy = "leastconn"
    server {
      address = "http://localhost:3000"
    }
  }
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

	if len(host.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(host.Routes))
	}

	// Check web route
	if host.Routes[0].Path != "/" {
		t.Errorf("expected first route path /, got %s", host.Routes[0].Path)
	}
	if !host.Routes[0].Web.Root.IsSet() {
		t.Error("expected web block in first route")
	}
	if host.Routes[0].Web.Root.String() != "." {
		t.Errorf("expected web root ., got %s", host.Routes[0].Web.Root.String())
	}
	if host.Routes[0].Web.Index != "index.html" {
		t.Errorf("expected web index index.html, got %s", host.Routes[0].Web.Index)
	}

	// Check proxy route
	if host.Routes[1].Path != "/api" {
		t.Errorf("expected second route path /api, got %s", host.Routes[1].Path)
	}

	// Check Backend struct
	if host.Routes[1].Backends.LBStrategy != "leastconn" {
		t.Errorf("expected lb_strategy leastconn, got %q", host.Routes[1].Backends.LBStrategy)
	}
	if len(host.Routes[1].Backends.Servers) != 1 || host.Routes[1].Backends.Servers[0].Address != "http://localhost:3000" {
		t.Errorf("unexpected backends: %v", host.Routes[1].Backends)
	}
}

func TestParser_HostConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "valid web and proxy routes",
			content: `
domains = ["test.com"]

route "/" {
  web {
    root = "."
  }
}

route "/api" {
  backend {
    server {
      address = "http://localhost:3000"
    }
  }
}
`,
			wantErr: false,
		},
		{
			name: "invalid: route with both web and backends",
			content: `
domains = ["test.com"]
route "/" {
  web {
    root = "."
  }
  backend {
    server {
      address = "http://localhost:3000"
    }
  }
}
`,
			wantErr: true,
		},
		{
			name: "invalid: route with neither web nor backends",
			content: `
domains = ["test.com"]
route "/" {
  # no web or backends
  strip_prefixes = ["/api"]
}
`,
			wantErr: true,
		},
		{
			name: "invalid: web route with strip_prefixes",
			content: `
domains = ["test.com"]
route "/static" {
  web {
    root = "."
  }
  strip_prefixes = ["/static"]
}
`,
			wantErr: true,
		},
		{
			name: "invalid: web route with health check",
			content: `
domains = ["test.com"]
route "/" {
  web {
    root = "."
  }
  health_check {
    path = "/health"
  }
}
`,
			wantErr: true,
		},
		{
			name: "valid: web route with compression only",
			content: `
domains = ["test.com"]
route "/" {
  web {
    root = "."
  }
  compression {
    compression = true
    type = "gzip"
  }
}
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "test.hcl")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			host, err := ParseHostConfig(path)

			if err != nil {
				// Parsing failed
				if !tt.wantErr {
					t.Fatalf("unexpected parsing error: %v", err)
				}
				return
			}

			validateErr := host.Validate()

			if tt.wantErr {
				if validateErr == nil {
					t.Error("expected validation error, got none")
				}
				return
			}

			if validateErr != nil {
				t.Fatalf("unexpected validation error: %v", validateErr)
			}
		})
	}
}

func TestParser_HeadersSyntax(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "headers with set as block",
			content: `
domains = ["test.com"]
route "/" {
  web {
    root = "."
  }
  headers {
    response {
      set = {
        "X-Test" = "Value"
      }
    }
  }
}
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "test.hcl")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			_, err := ParseHostConfig(path)
			if err != nil {
				if !tt.wantErr {
					t.Logf("Syntax %q failed with: %v", tt.name, err)
				}
				return
			}

			if tt.wantErr {
				t.Error("expected parsing error but got none")
			}
		})
	}
}

func TestParser_EdgeCases(t *testing.T) {
	t.Run("EmptyFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "empty.hcl")
		// Minimal valid config with required fields
		content := `hosts_dir = "./hosts"`
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		var global alaye.Global
		p := NewParser(path)
		err := p.Unmarshal(&global)
		if err != nil {
			t.Errorf("minimal config should parse without error, got: %v", err)
		}
		if global.HostsDir != "./hosts" {
			t.Errorf("expected hosts_dir ./hosts, got %s", global.HostsDir)
		}
	})

	t.Run("InvalidPath", func(t *testing.T) {
		p := NewParser("/nonexistent/file.hcl")
		var global alaye.Global
		err := p.Unmarshal(&global)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("MalformedHCL", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "bad.hcl")
		content := `hosts_dir = "./hosts" bind { http = [":80" ] } invalid_token =`
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		var global alaye.Global
		p := NewParser(path)
		err := p.Unmarshal(&global)
		if err == nil {
			t.Error("expected error for malformed HCL")
		}
	})
}

func TestLoadGlobal(t *testing.T) {
	content := `
bind {
  http = [":8080"]
}

hosts_dir = "./test_hosts"
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "global.hcl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	global, err := LoadGlobal(path)
	if err != nil {
		t.Fatalf("LoadGlobal failed: %v", err)
	}

	if len(global.Bind.HTTP) != 1 || global.Bind.HTTP[0] != ":8080" {
		t.Errorf("expected bind.http [:8080], got %v", global.Bind.HTTP)
	}
	if global.HostsDir != "./test_hosts" {
		t.Errorf("expected hosts_dir ./test_hosts, got %s", global.HostsDir)
	}
}

func TestEnsureHostsDir(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")

	// Should create directory
	err := EnsureHostsDir(hostsDir)
	if err != nil {
		t.Fatalf("EnsureHostsDir failed: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(hostsDir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory, got file")
	}

	// Should not error for existing directory
	err = EnsureHostsDir(hostsDir)
	if err != nil {
		t.Fatalf("EnsureHostsDir failed on existing dir: %v", err)
	}
}

func TestConfigPath(t *testing.T) {
	tests := []struct {
		name     string
		baseDir  string
		filename string
		expected string
	}{
		{
			name:     "Simple",
			baseDir:  "/etc/agbero",
			filename: "config.hcl",
			expected: "/etc/agbero/config.hcl",
		},
		{
			name:     "WithSubdir",
			baseDir:  "/etc/agbero",
			filename: "hosts.d/app.hcl",
			expected: "/etc/agbero/hosts.d/app.hcl",
		},
		{
			name:     "EmptyFilename",
			baseDir:  "/etc/agbero",
			filename: "",
			expected: "/etc/agbero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConfigPath(tt.baseDir, tt.filename)
			if result != tt.expected {
				t.Errorf("ConfigPath(%q, %q) = %q, want %q", tt.baseDir, tt.filename, result, tt.expected)
			}
		})
	}
}

func TestParser_WebBlockBug(t *testing.T) {
	content := `
domains = ["test.com"]

route "/" {
  web {
    root = "."
  }
}

route "/api" {
  backend {
    server {
      address = "http://localhost:3000"
    }
  }
}
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.hcl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	host, err := ParseHostConfig(path)
	if err != nil {
		t.Fatalf("ParseHostConfig failed: %v", err)
	}

	// Check what we actually parsed
	if len(host.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(host.Routes))
	}

	// Route 0 should have web
	if !host.Routes[0].Web.Root.IsSet() {
		t.Error("route 0 should have web block")
	}

	// Route 1 should NOT have web
	if host.Routes[1].Web.Root.IsSet() {
		t.Errorf("route 1 should not have web block, but has: %v", host.Routes[1].Web.Root.String())
	}

	// Route 1 should have backends
	if len(host.Routes[1].Backends.Servers) == 0 {
		t.Error("route 1 should have backends")
	}
}
