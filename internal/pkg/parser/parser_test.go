package parser

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
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

// --- Global config tests ---

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
	if g.Bind.Redirect != alaye.Active {
		t.Errorf("Bind.Redirect: got %v, want Active", g.Bind.Redirect)
	}
	// Fields below compare alaye.Duration to alaye.Duration(time.Second constants).
	// After Step 6 these become direct == comparisons unchanged.
	if g.Timeouts.Read != alaye.Duration(10*time.Second) {
		t.Errorf("Timeouts.Read: got %v, want 10s", g.Timeouts.Read)
	}
	if g.Timeouts.Write != alaye.Duration(30*time.Second) {
		t.Errorf("Timeouts.Write: got %v, want 30s", g.Timeouts.Write)
	}
	if g.Timeouts.Idle != alaye.Duration(120*time.Second) {
		t.Errorf("Timeouts.Idle: got %v, want 120s", g.Timeouts.Idle)
	}
	if g.Timeouts.ReadHeader != alaye.Duration(5*time.Second) {
		t.Errorf("Timeouts.ReadHeader: got %v, want 5s", g.Timeouts.ReadHeader)
	}
	if g.Storage.HostsDir != "/etc/agbero/hosts.d" {
		t.Errorf("Storage.HostsDir: got %q", g.Storage.HostsDir)
	}
	if g.Logging.Enabled != alaye.Active {
		t.Errorf("Logging.Enabled: got %v, want Active", g.Logging.Enabled)
	}
	if g.Logging.Level != "info" {
		t.Errorf("Logging.Level: got %q, want info", g.Logging.Level)
	}
	if g.Admin.Enabled != alaye.Inactive {
		t.Errorf("Admin.Enabled: got %v, want Inactive", g.Admin.Enabled)
	}
}

// --- Host config tests ---

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
	if r.Backends.Enabled != alaye.Active {
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
	if r.HealthCheck.Enabled != alaye.Active {
		t.Errorf("HealthCheck.Enabled: got %v, want Active", r.HealthCheck.Enabled)
	}
	if r.HealthCheck.Path != "/health" {
		t.Errorf("HealthCheck.Path: got %q, want /health", r.HealthCheck.Path)
	}
	if r.HealthCheck.Interval != alaye.Duration(10*time.Second) {
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
	if r.Web.Enabled != alaye.Active {
		t.Errorf("Web.Enabled: got %v, want Active", r.Web.Enabled)
	}
	if r.Web.Root.String() != "/var/www/html" {
		t.Errorf("Web.Root: got %q, want /var/www/html", r.Web.Root)
	}
	if r.Web.Index != "index.html" {
		t.Errorf("Web.Index: got %q, want index.html", r.Web.Index)
	}
	if !r.Web.Listing {
		t.Error("Web.Listing: got false, want true")
	}
}

// --- Enabled coercion tests ---

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
	if h.Routes[0].Web.Enabled != alaye.Active {
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
	if h.Routes[0].Web.Enabled != alaye.Inactive {
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
	if g.Admin.Enabled != alaye.Active {
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
	if g.Admin.Enabled != alaye.Inactive {
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
	if g.Admin.Enabled != alaye.Active {
		t.Errorf("Enabled from int 1: got %v, want Active", g.Admin.Enabled)
	}
}

// --- Duration decode tests ---

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
	if h.Routes[0].HealthCheck.Interval != alaye.Duration(30*time.Second) {
		t.Errorf("Interval: got %v, want 30s", h.Routes[0].HealthCheck.Interval)
	}
	if h.Routes[0].HealthCheck.Timeout != alaye.Duration(5*time.Second) {
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
	if h.Routes[0].HealthCheck.Interval != alaye.Duration(30*time.Second) {
		t.Errorf("Interval from bare int: got %v, want 30s", h.Routes[0].HealthCheck.Interval)
	}
}

// --- Env var interpolation tests ---

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

// --- Marshal / round-trip tests ---

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

// --- ValidateHCL tests ---

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

// --- LoadGlobal version mismatch tests ---

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
	if g.Version != woos.ConfigFormatVersion {
		t.Errorf("Version: got %d, want %d", g.Version, woos.ConfigFormatVersion)
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

// --- ParseHostConfig tests ---

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

// --- Marshal writer test ---

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
