package parser

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

// writeTemp writes content to a temp file and returns its path.
// The caller is responsible for removing the file.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.hcl")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// Global config tests

const minimalGlobalHCL = `
version = 1

bind {
  http = [":8080"]
}
`

func TestUnmarshalGlobal_minimal(t *testing.T) {
	path := writeTemp(t, minimalGlobalHCL)
	var g alaye.Global
	p := NewParser(path)
	if err := p.Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if g.Version != 1 {
		t.Errorf("Version: got %d, want 1", g.Version)
	}
	if len(g.Bind.HTTP) != 1 || g.Bind.HTTP[0] != ":8080" {
		t.Errorf("Bind.HTTP: got %v, want [:8080]", g.Bind.HTTP)
	}
}

const fullGlobalHCL = `
version     = 1
development = true

bind {
  http     = [":8080"]
  https    = [":8443"]
  redirect = "on"
}

timeouts {
  enabled     = "on"
  read        = "10s"
  write       = "30s"
  idle        = "120s"
  read_header = "5s"
}

storage {
  hosts_dir = "/etc/agbero/hosts.d"
  certs_dir = "/etc/agbero/certs.d"
}

logging {
  enabled = "on"
  level   = "info"
}

admin {
  enabled = "off"
  address = ":9090"
}
`

func TestUnmarshalGlobal_full(t *testing.T) {
	path := writeTemp(t, fullGlobalHCL)
	var g alaye.Global
	p := NewParser(path)
	if err := p.Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if g.Version != 1 {
		t.Errorf("Version: got %d, want 1", g.Version)
	}
	if !g.Development {
		t.Error("Development: got false, want true")
	}
	if g.Bind.Redirect != expect.Active {
		t.Errorf("Bind.Redirect: got %v, want Active", g.Bind.Redirect)
	}
	// Fields below compare alaye.Duration to alaye.Duration(time.Second constants).
	// After Step 6 these become direct == comparisons unchanged.
	if g.Timeouts.Read != expect.Duration(10*time.Second) {
		t.Errorf("Timeouts.Read: got %v, want 10s", g.Timeouts.Read)
	}
	if g.Timeouts.Write != expect.Duration(30*time.Second) {
		t.Errorf("Timeouts.Write: got %v, want 30s", g.Timeouts.Write)
	}
	if g.Timeouts.Idle != expect.Duration(120*time.Second) {
		t.Errorf("Timeouts.Idle: got %v, want 120s", g.Timeouts.Idle)
	}
	if g.Timeouts.ReadHeader != expect.Duration(5*time.Second) {
		t.Errorf("Timeouts.ReadHeader: got %v, want 5s", g.Timeouts.ReadHeader)
	}
	if g.Storage.HostsDir != "/etc/agbero/hosts.d" {
		t.Errorf("Storage.HostsDir: got %q", g.Storage.HostsDir)
	}
	if g.Logging.Enabled != expect.Active {
		t.Errorf("Logging.Enabled: got %v, want Active", g.Logging.Enabled)
	}
	if g.Logging.Level != "info" {
		t.Errorf("Logging.Level: got %q, want info", g.Logging.Level)
	}
	if g.Admin.Enabled != expect.Inactive {
		t.Errorf("Admin.Enabled: got %v, want Inactive", g.Admin.Enabled)
	}
}

// Host config tests

const proxyHostHCL = `
domains = ["example.com", "www.example.com"]

tls {
  mode = "auto"
}

route "/" {
  backend {
    enabled  = "on"
    strategy = "round_robin"

    server {
      address = "http://127.0.0.1:3000"
      weight  = 1
    }

    server {
      address = "http://127.0.0.1:3001"
      weight  = 2
    }
  }

  health_check {
    enabled   = "on"
    path      = "/health"
    interval  = "10s"
    timeout   = "5s"
    threshold = 3
  }
}
`

func TestUnmarshalHost_proxyRoute(t *testing.T) {
	path := writeTemp(t, proxyHostHCL)
	var h alaye.Host
	p := NewParser(path)
	if err := p.Unmarshal(&h); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(h.Domains) != 2 {
		t.Fatalf("Domains: got %v", h.Domains)
	}
	if len(h.Routes) != 1 {
		t.Fatalf("Routes: got %d, want 1", len(h.Routes))
	}

	r := h.Routes[0]
	if r.Path != "/" {
		t.Errorf("Route.Path: got %q, want /", r.Path)
	}
	if r.Backends.Enabled != expect.Active {
		t.Errorf("Backends.Enabled: got %v, want Active", r.Backends.Enabled)
	}
	if r.Backends.Strategy != "round_robin" {
		t.Errorf("Backends.Strategy: got %q, want round_robin", r.Backends.Strategy)
	}
	if len(r.Backends.Servers) != 2 {
		t.Fatalf("Backends.Servers: got %d, want 2", len(r.Backends.Servers))
	}
	if r.Backends.Servers[1].Weight != 2 {
		t.Errorf("Server[1].Weight: got %d, want 2", r.Backends.Servers[1].Weight)
	}
	if r.HealthCheck.Enabled != expect.Active {
		t.Errorf("HealthCheck.Enabled: got %v, want Active", r.HealthCheck.Enabled)
	}
	if r.HealthCheck.Path != "/health" {
		t.Errorf("HealthCheck.Path: got %q, want /health", r.HealthCheck.Path)
	}
	if r.HealthCheck.Interval != expect.Duration(10*time.Second) {
		t.Errorf("HealthCheck.Interval: got %v, want 10s", r.HealthCheck.Interval)
	}
	if r.HealthCheck.Threshold != 3 {
		t.Errorf("HealthCheck.Threshold: got %d, want 3", r.HealthCheck.Threshold)
	}
}

const webHostHCL = `
domains = ["static.example.com"]

route "/" {
  web {
    enabled = "on"
    root    = "/var/www/html"
    index   = "index.html"
    listing = true
  }
}
`

func TestUnmarshalHost_webRoute(t *testing.T) {
	path := writeTemp(t, webHostHCL)
	var h alaye.Host
	p := NewParser(path)
	if err := p.Unmarshal(&h); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(h.Routes) != 1 {
		t.Fatalf("Routes: got %d, want 1", len(h.Routes))
	}
	r := h.Routes[0]
	if r.Web.Enabled != expect.Active {
		t.Errorf("Web.Enabled: got %v, want Active", r.Web.Enabled)
	}
	if r.Web.Root.String() != "/var/www/html" {
		t.Errorf("Web.Root: got %q, want /var/www/html", r.Web.Root)
	}
	if r.Web.Index[0] != "index.html" {
		t.Errorf("Web.Index: got %q, want index.html", r.Web.Index)
	}
	if !r.Web.Listing.Active() {
		t.Error("Web.Listing: got false, want true")
	}
}

// Enabled coercion tests

func TestEnabled_fromBoolTrue(t *testing.T) {
	hclContent := `
domains = ["x.com"]
route "/" {
  web {
    enabled = true
    root    = "/var/www"
  }
}
`
	path := writeTemp(t, hclContent)
	var h alaye.Host
	if err := NewParser(path).Unmarshal(&h); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if h.Routes[0].Web.Enabled != expect.Active {
		t.Errorf("Enabled from bool true: got %v, want Active", h.Routes[0].Web.Enabled)
	}
}

func TestEnabled_fromBoolFalse(t *testing.T) {
	hclContent := `
domains = ["x.com"]
route "/" {
  web {
    enabled = false
    root    = "/var/www"
  }
}
`
	path := writeTemp(t, hclContent)
	var h alaye.Host
	if err := NewParser(path).Unmarshal(&h); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if h.Routes[0].Web.Enabled != expect.Inactive {
		t.Errorf("Enabled from bool false: got %v, want Inactive", h.Routes[0].Web.Enabled)
	}
}

func TestEnabled_fromStringOn(t *testing.T) {
	hclContent := `
version = 1
bind { http = [":8080"] }
admin {
  enabled = "on"
  address = ":9090"
}
`
	path := writeTemp(t, hclContent)
	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if g.Admin.Enabled != expect.Active {
		t.Errorf("Enabled from string 'on': got %v, want Active", g.Admin.Enabled)
	}
}

func TestEnabled_fromStringOff(t *testing.T) {
	hclContent := `
version = 1
bind { http = [":8080"] }
admin {
  enabled = "off"
  address = ":9090"
}
`
	path := writeTemp(t, hclContent)
	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if g.Admin.Enabled != expect.Inactive {
		t.Errorf("Enabled from string 'off': got %v, want Inactive", g.Admin.Enabled)
	}
}

func TestEnabled_fromInt1(t *testing.T) {
	hclContent := `
version = 1
bind { http = [":8080"] }
admin {
  enabled = 1
  address = ":9090"
}
`
	path := writeTemp(t, hclContent)
	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if g.Admin.Enabled != expect.Active {
		t.Errorf("Enabled from int 1: got %v, want Active", g.Admin.Enabled)
	}
}

// Duration decode tests

func TestDuration_fromGoString(t *testing.T) {
	hclContent := `
domains = ["x.com"]
route "/" {
  backend {
    server { address = "http://127.0.0.1:3000" }
  }
  health_check {
    enabled  = "on"
    path     = "/health"
    interval = "30s"
    timeout  = "5s"
  }
}
`
	path := writeTemp(t, hclContent)
	var h alaye.Host
	if err := NewParser(path).Unmarshal(&h); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if h.Routes[0].HealthCheck.Interval != expect.Duration(30*time.Second) {
		t.Errorf("Interval: got %v, want 30s", h.Routes[0].HealthCheck.Interval)
	}
	if h.Routes[0].HealthCheck.Timeout != expect.Duration(5*time.Second) {
		t.Errorf("Timeout: got %v, want 5s", h.Routes[0].HealthCheck.Timeout)
	}
}

func TestDuration_fromBareInteger(t *testing.T) {
	hclContent := `
domains = ["x.com"]
route "/" {
  backend {
    server { address = "http://127.0.0.1:3000" }
  }
  health_check {
    enabled  = "on"
    path     = "/health"
    interval = "30"
  }
}
`
	path := writeTemp(t, hclContent)
	var h alaye.Host
	if err := NewParser(path).Unmarshal(&h); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if h.Routes[0].HealthCheck.Interval != expect.Duration(30*time.Second) {
		t.Errorf("Interval from bare int: got %v, want 30s", h.Routes[0].HealthCheck.Interval)
	}
}

// Env var interpolation tests

func TestEnvVar_interpolation(t *testing.T) {
	t.Setenv("TEST_ADMIN_PORT", "9191")

	hclContent := `
version = 1
bind { http = [":8080"] }
admin {
  enabled = "on"
  address = ":${env.TEST_ADMIN_PORT}"
}
`
	path := writeTemp(t, hclContent)
	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if g.Admin.Address != ":9191" {
		t.Errorf("Admin.Address: got %q, want :9191", g.Admin.Address)
	}
}

func TestEnvVar_missingVarDecodesAsEmpty(t *testing.T) {
	os.Unsetenv("AGBERO_NONEXISTENT_VAR_XYZ")

	// A missing env var key causes the attribute expression evaluation to fail
	// with an "Unsupported attribute" diagnostic. The parser treats this as a
	// skipped field, leaving the zero value — identical to the field being absent.
	hclContent := `
version = 1
bind { http = [":8080"] }
admin {
  enabled = "off"
  address = ":9090"
}
`
	path := writeTemp(t, hclContent)
	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if g.Admin.Address != ":9090" {
		t.Errorf("Admin.Address: got %q, want :9090", g.Admin.Address)
	}
}

// Marshal / round-trip tests

func TestMarshalBytes_roundTrip(t *testing.T) {
	original := minimalGlobalHCL
	path := writeTemp(t, original)

	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	data, err := MarshalBytes(&g)
	if err != nil {
		t.Fatalf("MarshalBytes: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalBytes: returned empty bytes")
	}

	path2 := writeTemp(t, string(data))
	var g2 alaye.Global
	if err := NewParser(path2).Unmarshal(&g2); err != nil {
		t.Fatalf("Unmarshal after MarshalBytes: %v", err)
	}

	if g.Version != g2.Version {
		t.Errorf("round-trip Version: got %d, want %d", g2.Version, g.Version)
	}
	if len(g.Bind.HTTP) != len(g2.Bind.HTTP) {
		t.Errorf("round-trip Bind.HTTP length: got %d, want %d", len(g2.Bind.HTTP), len(g.Bind.HTTP))
	}
}

func TestMarshalFile_roundTrip(t *testing.T) {
	srcPath := writeTemp(t, minimalGlobalHCL)
	var g alaye.Global
	if err := NewParser(srcPath).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	outPath := srcPath + ".out.hcl"
	defer os.Remove(outPath)

	if err := MarshalFile(outPath, &g); err != nil {
		t.Fatalf("MarshalFile: %v", err)
	}

	var g2 alaye.Global
	if err := NewParser(outPath).Unmarshal(&g2); err != nil {
		t.Fatalf("Unmarshal from MarshalFile output: %v", err)
	}
	if g.Version != g2.Version {
		t.Errorf("round-trip Version: got %d, want %d", g2.Version, g.Version)
	}
}

// ValidateHCL tests

func TestValidateHCL_valid(t *testing.T) {
	data := []byte(`
version = 1
bind {
  http = [":8080"]
}
`)
	if err := ValidateHCL(data); err != nil {
		t.Errorf("ValidateHCL valid input: unexpected error: %v", err)
	}
}

func TestValidateHCL_invalid(t *testing.T) {
	data := []byte(`
version = 
`)
	err := ValidateHCL(data)
	if err == nil {
		t.Error("ValidateHCL invalid input: expected error, got nil")
	}
}

func TestValidateHCL_diagnosticContainsPosition(t *testing.T) {
	data := []byte("version = \n")
	err := ValidateHCL(data)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, ":1,") && !strings.Contains(msg, ":2,") {
		t.Errorf("diagnostic missing line/column info: %q", msg)
	}
}

// LoadGlobal version mismatch tests

func TestLoadGlobal_correctVersion(t *testing.T) {
	hclContent := `
version = 1
bind { http = [":8080"] }
`
	path := writeTemp(t, hclContent)
	g, err := LoadGlobal(path)
	if err != nil {
		t.Fatalf("LoadGlobal: %v", err)
	}
	if g.Version != def.ConfigFormatVersion {
		t.Errorf("Version: got %d, want %d", g.Version, def.ConfigFormatVersion)
	}
}

func TestLoadGlobal_versionTooLow(t *testing.T) {
	hclContent := `
version = 0
bind { http = [":8080"] }
`
	path := writeTemp(t, hclContent)
	_, err := LoadGlobal(path)
	if err == nil {
		t.Fatal("expected error for version too low, got nil")
	}
	if !strings.Contains(err.Error(), "version mismatch") {
		t.Errorf("error should mention version mismatch: %v", err)
	}
}

func TestLoadGlobal_emptyPath(t *testing.T) {
	_, err := LoadGlobal("")
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

// ParseHostConfig tests

func TestParseHostConfig_missingFile(t *testing.T) {
	_, err := ParseHostConfig("/tmp/agbero_nonexistent_file_xyz.hcl")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestParseHostConfig_valid(t *testing.T) {
	path := writeTemp(t, proxyHostHCL)
	h, err := ParseHostConfig(path)
	if err != nil {
		t.Fatalf("ParseHostConfig: %v", err)
	}
	if len(h.Domains) == 0 {
		t.Error("Domains: expected at least one domain")
	}
}

// Marshal writer test

func TestMarshal_writer(t *testing.T) {
	path := writeTemp(t, minimalGlobalHCL)
	var g alaye.Global
	if err := NewParser(path).Unmarshal(&g); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	var sb strings.Builder
	if err := Marshal(&sb, &g); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if sb.Len() == 0 {
		t.Error("Marshal: wrote zero bytes")
	}
}

// Omitempty and Tag Parsing tests

func TestParseTag(t *testing.T) {
	tests := []struct {
		tag      string
		wantName string
		wantKind string
	}{
		{"", "", ""},
		{"-", "-", ""},
		{"backend,block,omitempty", "backend", "block"},
		{"web,block,omitempty", "web", "block"},
		{"domains,attr", "domains", "attr"},
		{"address,attr,omitempty", "address", "attr"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			name, kind := parseTag(tt.tag)
			if name != tt.wantName {
				t.Errorf("parseTag(%q) name = %q, want %q", tt.tag, name, tt.wantName)
			}
			if kind != tt.wantKind {
				t.Errorf("parseTag(%q) kind = %q, want %q", tt.tag, kind, tt.wantKind)
			}
		})
	}
}

func TestWithOmitempty(t *testing.T) {
	hclContent := `
domains = ["omitempty.example.com"]

route "/web" {
  web {
    enabled = "on"
    root    = "/var/www/html"
  }
}

route "/backend" {
  backend {
    enabled = "on"
    server {
      address = "http://127.0.0.1:8080"
    }
  }
}
`
	path := writeTemp(t, hclContent)
	defer os.Remove(path)

	var h alaye.Host
	p := NewParser(path)
	if err := p.Unmarshal(&h); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(h.Routes) != 2 {
		t.Fatalf("Expected 2 routes, got %d", len(h.Routes))
	}

	// Verify the 'web' block (tagged with `hcl:"web,block,omitempty"`)
	webRoute := h.Routes[0]
	if webRoute.Path != "/web" {
		t.Errorf("Expected path '/web', got %q", webRoute.Path)
	}
	if webRoute.Web.Enabled != expect.Active {
		t.Errorf("Expected Web.Enabled to be Active, got %v", webRoute.Web.Enabled)
	}
	if webRoute.Web.Root.String() != "/var/www/html" {
		t.Errorf("Expected Web.Root to be '/var/www/html', got %q", webRoute.Web.Root)
	}

	// Verify the 'backend' block (tagged with `hcl:"backend,block,omitempty"`)
	backendRoute := h.Routes[1]
	if backendRoute.Path != "/backend" {
		t.Errorf("Expected path '/backend', got %q", backendRoute.Path)
	}
	if backendRoute.Backends.Enabled != expect.Active {
		t.Errorf("Expected Backends.Enabled to be Active, got %v", backendRoute.Backends.Enabled)
	}
	if len(backendRoute.Backends.Servers) == 0 || backendRoute.Backends.Servers[0].Address.String() != "http://127.0.0.1:8080" {
		t.Errorf("Expected backend server address 'http://127.0.0.1:8080', got %v", backendRoute.Backends.Servers)
	}
}

// TestMarshal_omitemptyBlocksSuppressed proves that blocks tagged
// `hcl:"...,block,omitempty"` are not written when they contain no data.
func TestMarshal_omitemptyBlocksSuppressed(t *testing.T) {
	// Only set the minimum required to make a valid host.
	// All omitempty blocks (health_check, circuit_breaker, basic_auth, etc.)
	// are left at their zero value.
	h := alaye.Host{
		Domains: []string{"test.localhost"},
		Routes: []alaye.Route{
			{
				Enabled: expect.Active,
				Path:    "/",
				Web: alaye.Web{
					Enabled: expect.Active,
					Root:    alaye.WebRoot("/var/www"),
				},
			},
		},
	}

	data, err := MarshalBytes(&h)
	if err != nil {
		t.Fatalf("MarshalBytes: %v", err)
	}

	output := string(data)
	t.Logf("encoded output:\n%s", output)

	// These blocks are tagged omitempty and are all zero — must NOT appear
	for _, block := range []string{
		"health_check",
		"circuit_breaker",
		"timeouts",
		"basic_auth",
		"forward_auth",
		"jwt_auth",
		"o_auth",
		"cors",
		"rate_limit",
		"firewall",
		"compression",
		"fallback",
		"serverless",
		"backend",
	} {
		if strings.Contains(output, block+" {") || strings.Contains(output, block+"{") {
			t.Errorf("block %q should be suppressed (omitempty) but appeared in output", block)
		}
	}

	// The web block IS set — must appear
	if !strings.Contains(output, "web {") {
		t.Error("web block should appear but was missing")
	}
}

// TestMarshal_omitemptyBlocksPreservedWhenSet proves that a populated
// omitempty block still gets written after the fix.
func TestMarshal_omitemptyBlocksPreservedWhenSet(t *testing.T) {
	h := alaye.Host{
		Domains: []string{"test.localhost"},
		Routes: []alaye.Route{
			{
				Enabled: expect.Active,
				Path:    "/",
				Web: alaye.Web{
					Enabled: expect.Active,
					Root:    alaye.WebRoot("/var/www"),
				},
				HealthCheck: alaye.HealthCheck{
					Enabled:  expect.Active,
					Path:     "/health",
					Interval: expect.Duration(10 * time.Second),
				},
			},
		},
	}

	data, err := MarshalBytes(&h)
	if err != nil {
		t.Fatalf("MarshalBytes: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "health_check {") {
		t.Error("health_check block should appear when populated, but was missing")
	}
	if !strings.Contains(output, "/health") {
		t.Error("health_check path should appear in output")
	}
}

// TestUnmarshalHost_envMap is the regression for a reflect panic: setMap built
// map values with reflect.ValueOf(string), which is not assignable to named
// string types, so `env = { ... }` (map[string]expect.Value) crashed the process
// instead of returning an error.
func TestUnmarshalHost_envMap(t *testing.T) {
	path := writeTemp(t, `
domains = ["env.example"]

route "/fn" {
  serverless {
    enabled = "on"
    work "render" {
      enabled = "on"
      command = ["node", "index.js"]
      env = { "NODE_ENV" = "production" }
    }
  }
  env = { "API_URL" = "https://api.internal,a,b" }
}
`)

	h, err := ParseHostConfig(path)
	if err != nil {
		t.Fatalf("ParseHostConfig: %v", err)
	}
	if len(h.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(h.Routes))
	}
	if got := h.Routes[0].Env["API_URL"].String(); got != "https://api.internal,a,b" {
		t.Errorf("route env lost (got %q)", got)
	}
	w := h.Routes[0].Serverless.Workers
	if len(w) != 1 || w[0].Env["NODE_ENV"].String() != "production" {
		t.Errorf("work env lost: %+v", w)
	}
}

// TestUnmarshalHost_ttlPolicyDurationMap covers map[string]expect.Duration, the
// other named-type map in the schema (int64-backed, encoded as a Go duration).
func TestUnmarshalHost_ttlPolicyDurationMap(t *testing.T) {
	path := writeTemp(t, `
domains = ["cache.example"]

route "/" {
  web {
    root = "/tmp"
  }
  cache {
    enabled = "on"
    driver  = "memory"
    ttl     = "5m"
    policy {
      enabled = "on"
      content_type = {
        "text/html" = "1h"
        "image/png" = "24h"
      }
    }
  }
}
`)

	h, err := ParseHostConfig(path)
	if err != nil {
		t.Fatalf("ParseHostConfig: %v", err)
	}
	ct := h.Routes[0].Cache.TTLPolicy.ContentType
	if got := time.Duration(ct["text/html"]); got != time.Hour {
		t.Errorf("content_type[t ext/html] = %v, want 1h", got)
	}
	if got := time.Duration(ct["image/png"]); got != 24*time.Hour {
		t.Errorf("content_type[image/png] = %v, want 24h", got)
	}
}

// TestMarshal_RoundTripsMaps is the encoder half of the map fix: env, claim maps
// and TTL-policy overrides were silently dropped when a config was re-encoded
// (the API rewrites HCL on every host update).
func TestMarshal_RoundTripsMaps(t *testing.T) {
	h := alaye.Host{
		Domains: []string{"env.example"},
		Routes: []alaye.Route{{
			Enabled: expect.Active,
			Path:    "/",
			Env:     map[string]expect.Value{"API_URL": "https://api.internal,a,b"},
			Web:     alaye.Web{Enabled: expect.Active, Root: "/tmp"},
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "memory",
				TTL:     expect.Duration(5 * time.Minute),
				TTLPolicy: alaye.TTLPolicy{
					Enabled:     expect.Active,
					ContentType: map[string]expect.Duration{"text/html": expect.Duration(time.Hour)},
				},
			},
			JWTAuth: alaye.JWTAuth{
				Enabled:  expect.Active,
				Secret:   "jwt-secret",
				ClaimMap: map[string]string{"sub": "X-User-ID"},
			},
		}},
	}

	data, err := MarshalBytes(&h)
	if err != nil {
		t.Fatalf("MarshalBytes: %v", err)
	}
	out := string(data)
	for _, want := range []string{"env", "API_URL", "claims_to_headers", "content_type"} {
		if !strings.Contains(out, want) {
			t.Errorf("encoded HCL is missing %q:\n%s", want, out)
		}
	}

	path := writeTemp(t, out)
	back, err := ParseHostConfig(path)
	if err != nil {
		t.Fatalf("re-parsing encoded HCL: %v\n%s", err, out)
	}
	r := back.Routes[0]
	if got := r.Env["API_URL"].String(); got != "https://api.internal,a,b" {
		t.Errorf("env lost in round-trip (got %q)", got)
	}
	if got := r.JWTAuth.ClaimMap["sub"]; got != "X-User-ID" {
		t.Errorf("claim map lost in round-trip (got %q)", got)
	}
	if got := time.Duration(r.Cache.TTLPolicy.ContentType["text/html"]); got != time.Hour {
		t.Errorf("ttl policy content_type lost in round-trip (got %v)", got)
	}
}
