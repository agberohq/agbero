// internal/core/parser_test.go
package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/stretchr/testify/assert"
)

func TestParser_UnmarshalGlobal(t *testing.T) {
	// Create a temporary config file with the NEW structure
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
	assert.NoError(t, err)

	// Test Parsing
	var global alaye.Global
	parser := NewParser(configPath)
	err = parser.Unmarshal(&global)

	assert.NoError(t, err)

	// 1. Top Level
	assert.True(t, global.Development)

	// 2. Bind Block
	assert.Equal(t, []string{":8080", ":8081"}, global.Bind.HTTP)
	assert.Equal(t, []string{":8443"}, global.Bind.HTTPS)
	assert.Equal(t, ":9090", global.Bind.Metrics)

	// 3. Storage Block (New)
	assert.Equal(t, "./my_hosts", global.Storage.HostsDir)
	assert.Equal(t, "./my_certs", global.Storage.CertsDir)

	// 4. Security Block (New)
	assert.Equal(t, []string{"10.0.0.0/8", "127.0.0.1"}, global.Security.TrustedProxies)

	// 5. General Block (New)
	assert.Equal(t, 2048, global.General.MaxHeaderBytes)

	// 6. Logging
	assert.Equal(t, "debug", global.Logging.Level)
	assert.True(t, global.Logging.Victoria.Enabled)

	// 7. Timeouts
	assert.Equal(t, 15*time.Second, global.Timeouts.Read)
	assert.Equal(t, 30*time.Second, global.Timeouts.Write)

	// 8. LetsEncrypt
	assert.Equal(t, "admin@example.com", global.LetsEncrypt.Email)
	assert.True(t, global.LetsEncrypt.Staging)
}

func TestParser_UnmarshalHost(t *testing.T) {
	// Simple sanity check for host files to ensure they still parse
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
    server "http://localhost:3000" {}
    server "http://localhost:3001" {
        weight = 3
    }
  }
}
`
	tmpDir := t.TempDir()
	hostPath := filepath.Join(tmpDir, "example.hcl")
	err := os.WriteFile(hostPath, []byte(content), 0644)
	assert.NoError(t, err)

	host, err := ParseHostConfig(hostPath)
	assert.NoError(t, err)

	assert.Equal(t, []string{"example.com", "www.example.com"}, host.Domains)
	assert.True(t, host.Compression)
	assert.Equal(t, alaye.ModeLocalCert, host.TLS.Mode)
	assert.Len(t, host.Routes, 2)
}
