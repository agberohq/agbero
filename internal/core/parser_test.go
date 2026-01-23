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
  http = [":8080"]
  https = [":443"]
  metrics = ":9090"
}

hosts_dir = "./custom_hosts"
le_email = "test@example.com"
development = true

timeouts {
  read = "1s"
  write = "30s"
  idle = "120s"
  read_header = "5s"
}

rate_limits {
  ttl = "10m"
  max_entries = 123

  global {
    requests = 5
    window   = "1s"
    burst    = 9
  }

  auth {
    requests = 1
    window   = "1m"
    burst    = 1
  }
}
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.hcl")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	var global alaye.Global
	p := NewParser(path)
	if err := p.Unmarshal(&global); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(global.Bind.HTTP) != 1 || global.Bind.HTTP[0] != ":8080" {
		t.Errorf("expected bind.http [:8080], got %v", global.Bind.HTTP)
	}
	if len(global.Bind.HTTPS) != 1 || global.Bind.HTTPS[0] != ":443" {
		t.Errorf("expected bind.https [:443], got %v", global.Bind.HTTPS)
	}
	if global.Bind.Metrics != ":9090" {
		t.Errorf("expected bind.metrics :9090, got %s", global.Bind.Metrics)
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

	if global.Timeouts.Read != 1*time.Second {
		t.Errorf("expected timeouts.read 1s, got %v", global.Timeouts.Read)
	}
	if global.Timeouts.Write != 30*time.Second {
		t.Errorf("expected timeouts.write 30s, got %v", global.Timeouts.Write)
	}
	if global.Timeouts.Idle != 120*time.Second {
		t.Errorf("expected timeouts.idle 120s, got %v", global.Timeouts.Idle)
	}
	if global.Timeouts.ReadHeader != 5*time.Second {
		t.Errorf("expected timeouts.read_header 5s, got %v", global.Timeouts.ReadHeader)
	}

	if global.RateLimits.TTL != 10*time.Minute {
		t.Errorf("expected rate_limits.ttl 10m, got %v", global.RateLimits.TTL)
	}
	if global.RateLimits.MaxEntries != 123 {
		t.Errorf("expected max_entries 123, got %d", global.RateLimits.MaxEntries)
	}
	if global.RateLimits.Global.Requests != 5 || global.RateLimits.Global.Window != 1*time.Second || global.RateLimits.Global.Burst != 9 {
		t.Errorf("unexpected global policy: %+v", global.RateLimits.Global)
	}
	if global.RateLimits.Auth.Requests != 1 || global.RateLimits.Auth.Window != 1*time.Minute || global.RateLimits.Auth.Burst != 1 {
		t.Errorf("unexpected auth policy: %+v", global.RateLimits.Auth)
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

	if len(host.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(host.Routes))
	}

	// Check web route
	if host.Routes[0].Path != "/" {
		t.Errorf("expected first route path /, got %s", host.Routes[0].Path)
	}
	if &host.Routes[0].Web == nil {
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
	if host.Routes[1].LBStrategy != "leastconn" {
		t.Errorf("expected lb_strategy leastconn, got %q", host.Routes[1].LBStrategy)
	}
	if len(host.Routes[1].Backends) != 1 || host.Routes[1].Backends[0] != "http://localhost:3000" {
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
  backends = ["http://localhost:3000"]
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
  backends = ["http://localhost:3000"]
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
			name: "valid: web route with compression and headers",
			content: `
domains = ["test.com"]
route "/" {
  web {
    root = "."
  }
  compression {
    compression = true
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

			host, err := ParseHostConfig(path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected validation error, got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Validate the parsed config
			if err := host.Validate(); err != nil {
				t.Fatalf("validation failed: %v", err)
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
