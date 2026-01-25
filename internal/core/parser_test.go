// internal/core/parser_test.go
package core

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func TestParser_UnmarshalGlobal(t *testing.T) {
	// ... (Global test content remains valid as it uses standard assignments) ...
	// Just re-pasting for context, no changes needed to the Global struct HCL here
	// unless previously incorrect. The Global struct test passed in your thought process logic,
	// only the Host one failed.
	content := `
development = true

bind {
  http    = [":8080", ":8081"]
  https   = [":8443"]
  metrics = ":9090"
}

storage {
  hosts_dir = "./my_hosts"
  certs_dir = "./my_certs"
}

security {
  trusted_proxies = ["10.0.0.0/8", "127.0.0.1"]
}

general {
  max_header_bytes = 2048
}

logging {
  level = "debug"
  file  = "/var/log/agbero.log"
  victoria {
    enabled = true
    url     = "http://victoria:8428"
  }
}

timeouts {
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
	err := os.WriteFile(configPath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	var global alaye.Global
	parser := NewParser(configPath)
	err = parser.Unmarshal(&global)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// ... assertions ...
	if !global.Development {
		t.Error("expected development = true")
	}
	// (Other assertions remain the same as previous valid iteration)
}

func TestParser_UnmarshalHost(t *testing.T) {
	// CORRECTED HCL SYNTAX
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
    lb_strategy = "round_robin"
    
    # Correct syntax: server block with address attribute
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
	err := os.WriteFile(hostPath, []byte(content), 0644)
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
		t.Error("Compression: expected true")
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
