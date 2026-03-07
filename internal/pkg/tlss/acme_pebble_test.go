package tlss

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
)

// This test requires Pebble and pebble-challtestsrv to be running
// Run with: go test -tags=pebble -run TestPebbleIntegration
func TestPebbleIntegration(t *testing.T) {
	if os.Getenv("PEBBLE_TEST") == "" {
		t.Skip("Set PEBBLE_TEST=1 to run Pebble integration tests")
	}

	// Configuration
	pebbleURL := os.Getenv("PEBBLE_URL")
	if pebbleURL == "" {
		pebbleURL = "https://localhost:14000/dir"
	}

	challSrvURL := os.Getenv("CHALLTESTSRV_URL")
	if challSrvURL == "" {
		challSrvURL = "http://localhost:8055" // Management API for pebble-challtestsrv
	}

	// Setup test directory
	tmpDir := t.TempDir()

	// Initialize challenge test server client
	challClient := &http.Client{Timeout: 5 * time.Second}

	// Configure for Pebble
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{
			Enabled:   alaye.Inactive,
			SecretKey: "test-secret-1234567890123456",
		},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@pebble.local",
			Staging: false,
			Pebble: alaye.Pebble{
				Enabled:  true,
				URL:      pebbleURL,
				Insecure: true, // Pebble uses self-signed certs
			},
		},
	}

	// Create manager with mock mode enabled
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global)

	// CRITICAL: Enable mock mode for the local installer
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}

	defer mgr.Close()

	// Test domain - should resolve to localhost where pebble-challtestsrv runs
	testDomain := "example.pebble.local"

	// Register the test domain with the challenge test server
	// This tells pebble-challtestsrv to respond to A/AAAA queries for our domain
	resp, err := challClient.Post(
		fmt.Sprintf("%s/set-default-ipv4", challSrvURL),
		"application/json",
		nil,
	)
	if err != nil {
		t.Logf("Warning: could not configure challenge test server: %v", err)
	} else {
		resp.Body.Close()
	}

	// Add A record for our test domain
	resp, err = challClient.Post(
		fmt.Sprintf("%s/add-a?host=%s&ip=127.0.0.1", challSrvURL, testDomain),
		"application/json",
		nil,
	)
	if err != nil {
		t.Logf("Warning: could not add A record: %v", err)
	} else {
		resp.Body.Close()
	}

	// Try to obtain a certificate
	t.Logf("Attempting to obtain certificate for %s from Pebble...", testDomain)

	// First, ensure we have a valid CA for local certificates
	// In mock mode, this should just generate files without system installation
	if mgr.installer != nil {
		err = mgr.installer.InstallCARootIfNeeded()
		if err != nil {
			t.Fatalf("Failed to install CA root in mock mode: %v", err)
		}
	}

	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: testDomain})
	if err != nil {
		// If Pebble isn't actually running, we'll get a connection error
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") {
			t.Skipf("Pebble not running: %v", err)
		}
		t.Fatalf("Failed to obtain certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("Got nil certificate")
	}

	// Parse and verify the certificate
	if len(cert.Certificate) == 0 {
		t.Fatal("Certificate has no leaf")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	t.Logf("Successfully obtained certificate:")
	t.Logf("  Subject: %s", leaf.Subject)
	t.Logf("  DNS Names: %v", leaf.DNSNames)
	t.Logf("  Issuer: %s", leaf.Issuer)
	t.Logf("  Not After: %s", leaf.NotAfter)

	// Verify the certificate is for our domain
	found := false
	for _, dns := range leaf.DNSNames {
		if dns == testDomain {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Certificate missing DNS name %s", testDomain)
	}

	// Clean up challenge test server records
	resp, err = challClient.Post(
		fmt.Sprintf("%s/clear-a?host=%s", challSrvURL, testDomain),
		"application/json",
		nil,
	)
	if err != nil {
		t.Logf("Warning: could not clear A record: %v", err)
	} else {
		resp.Body.Close()
	}
}

// TestPebbleWithCustomDomain tests obtaining a certificate for a custom domain
func TestPebbleWithCustomDomain(t *testing.T) {
	if os.Getenv("PEBBLE_TEST") == "" {
		t.Skip("Set PEBBLE_TEST=1 to run Pebble integration tests")
	}

	tmpDir := t.TempDir()

	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{
			Enabled:   alaye.Inactive,
			SecretKey: "test-secret-1234567890123456",
		},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@pebble.local",
			Pebble: alaye.Pebble{
				Enabled:  true,
				URL:      "https://localhost:14000/dir",
				Insecure: true,
			},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global)

	// CRITICAL: Enable mock mode for the local installer
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}

	defer mgr.Close()

	// First, ensure we have a valid CA for local certificates
	if mgr.installer != nil {
		err := mgr.installer.InstallCARootIfNeeded()
		if err != nil {
			t.Fatalf("Failed to install CA root in mock mode: %v", err)
		}
	}

	// Test multiple domains
	domains := []string{
		"test1.pebble.local",
		"test2.pebble.local",
		"*.wildcard.pebble.local",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
			if err != nil {
				// If Pebble isn't actually running, we'll get a connection error
				if strings.Contains(err.Error(), "connection refused") ||
					strings.Contains(err.Error(), "no such host") {
					t.Skipf("Pebble not running: %v", err)
				}
				// Pebble might not support wildcards in the same way
				if strings.HasPrefix(domain, "*.") && strings.Contains(err.Error(), "wildcard") {
					t.Skipf("Pebble may not support wildcards: %v", err)
				}
				t.Fatalf("Failed to obtain certificate for %s: %v", domain, err)
			}

			if cert == nil {
				t.Fatal("Got nil certificate")
			}

			leaf, _ := x509.ParseCertificate(cert.Certificate[0])
			t.Logf("Got certificate for %s: %v", domain, leaf.DNSNames)
		})
	}
}
