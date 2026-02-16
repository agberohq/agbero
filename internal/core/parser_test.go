package core

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func TestParser_UnmarshalGlobal(t *testing.T) {
	content := `
development = true

bind {
  http    = [":8080", ":8081"]
  https   = [":8443"]
}

# Admin block instead of metrics attribute
admin {
  enabled = true
  address = ":9090"
}

storage {
  hosts_dir = "./my_hosts"
  certs_dir = "./my_certs"
  data_dir  = "./my_data"
}

security {
  enabled = true
  trusted_proxies = ["10.0.0.0/8", "127.0.0.1"]
}

general {
  max_header_bytes = 2048
}

logging {
  enabled = true
  level = "debug"
  file  = "/var/log/agbero.log"
  victoria {
    enabled = true
    url     = "http://victoria:8428"
  }
}

timeouts {
  enabled = true
  read  = "15s"
  write = "30s"
}

letsencrypt {
  email   = "admin@example.com"
  staging = true
}
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agbero.hcl")
	err := os.WriteFile(configPath, []byte(content), woos.FilePerm)
	if err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	var global alaye.Global
	parser := NewParser(configPath)
	err = parser.Unmarshal(&global)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !global.Development {
		t.Error("expected development = true")
	}
	if len(global.Bind.HTTP) != 2 {
		t.Error("expected 2 http bind addresses")
	}
	// Verify Admin block parsing
	if global.Admin.Enabled.No() {
		t.Fatal("expected admin block to be parsed")
	}

	if global.Admin.Address != ":9090" {
		t.Errorf("expected admin address :9090, got %v", global.Admin.Address)
	}
	if global.Storage.DataDir != "./my_data" {
		t.Errorf("expected data_dir ./my_data, got %s", global.Storage.DataDir)
	}
	if global.General.MaxHeaderBytes != 2048 {
		t.Error("expected max_header_bytes = 2048")
	}
	if global.Logging.Level != "debug" {
		t.Error("expected logging level = debug")
	}
	if !global.LetsEncrypt.Staging {
		t.Error("expected staging = true")
	}
}

func TestParser_UnmarshalHost(t *testing.T) {
	content := `
domains = ["example.com", "www.example.com"]
compression = true

tls {
  mode = "local"
  local {
    cert_file = "/tmp/cert.pem"
    key_file  = "/tmp/key.pem"
  }
}

route "/" {
  web {
    root  = "./www"
    index = "index.html"
  }
}

route "/api" {
  strip_prefixes = ["/api"]
  backend {
    strategy = "round_robin"
    
    server {
        address = "http://localhost:3000"
    }
    
    server {
        address = "http://localhost:3001"
        weight  = 3
    }
  }
}
`
	tmpDir := t.TempDir()
	hostPath := filepath.Join(tmpDir, "example.hcl")
	err := os.WriteFile(hostPath, []byte(content), woos.FilePerm)
	if err != nil {
		t.Fatalf("failed to write temp host config: %v", err)
	}

	host, err := ParseHostConfig(hostPath)
	if err != nil {
		t.Fatalf("ParseHostConfig failed: %v", err)
	}

	expectedDomains := []string{"example.com", "www.example.com"}
	if !reflect.DeepEqual(host.Domains, expectedDomains) {
		t.Errorf("Domains: expected %v, got %v", expectedDomains, host.Domains)
	}

	if !host.Compression {
		t.Error("Active: expected true")
	}

	if host.TLS.Mode != alaye.ModeLocalCert {
		t.Errorf("TLS.Mode: expected %v, got %v", alaye.ModeLocalCert, host.TLS.Mode)
	}

	if len(host.Routes) != 2 {
		t.Errorf("Routes: expected 2, got %d", len(host.Routes))
	}

	// Validate Backend Server Parsing
	var apiRoute alaye.Route
	for _, r := range host.Routes {
		if r.Path == "/api" {
			apiRoute = r
			break
		}
	}

	if len(apiRoute.Backends.Servers) != 2 {
		t.Errorf("Expected 2 backend servers, got %d", len(apiRoute.Backends.Servers))
	}

	if apiRoute.Backends.Servers[1].Weight != 3 {
		t.Errorf("Expected weight 3, got %d", apiRoute.Backends.Servers[1].Weight)
	}
}

// TestParser_EnvironmentValue verifies that the alaye.Value unmarshaling
// works correctly when parsing a real HCL file with env variables.
func TestParser_EnvironmentValue(t *testing.T) {
	// Set test environment variable
	secret := "test-gossip-secret-12345678" // 24 bytes
	os.Setenv("AGBERO_TEST_SECRET", secret)
	defer os.Unsetenv("AGBERO_TEST_SECRET")

	// Config using different syntax styles for the secret
	content := `
enabled = true
# Test unwrapped env
secret_key = "env.AGBERO_TEST_SECRET"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "gossip.hcl")
	err := os.WriteFile(configPath, []byte(content), woos.FilePerm)
	if err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	var gossip alaye.Gossip
	parser := NewParser(configPath)
	err = parser.Unmarshal(&gossip)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if gossip.SecretKey.String() != secret {
		t.Errorf("Expected secret %q, got %q", secret, gossip.SecretKey.String())
	}

	// Test 2: Wrapped syntax ${env.VAR}
	content2 := `
enabled = true
secret_key = "${env.AGBERO_TEST_SECRET}"
`
	configPath2 := filepath.Join(tmpDir, "gossip_wrapped.hcl")
	os.WriteFile(configPath2, []byte(content2), woos.FilePerm)

	var gossip2 alaye.Gossip
	parser2 := NewParser(configPath2)
	err = parser2.Unmarshal(&gossip2)
	if err != nil {
		t.Fatalf("Unmarshal wrapped failed: %v", err)
	}

	if gossip2.SecretKey.String() != secret {
		t.Errorf("Expected secret %q from wrapped syntax, got %q", secret, gossip2.SecretKey.String())
	}
}
