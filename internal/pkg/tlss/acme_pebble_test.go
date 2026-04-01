// acme_pebble_test.go
package tlss

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
)

func TestPebbleIntegration(t *testing.T) {
	if os.Getenv("PEBBLE_TEST") == "" {
		t.Skip("Set PEBBLE_TEST=1 to run Pebble integration tests")
	}
	pebbleURL := os.Getenv("PEBBLE_URL")
	if pebbleURL == "" {
		pebbleURL = "https://localhost:14000/dir"
	}
	challSrvURL := os.Getenv("CHALLTESTSRV_URL")
	if challSrvURL == "" {
		challSrvURL = "http://localhost:8055"
	}
	tmpDir := t.TempDir()
	challClient := &http.Client{Timeout: 5 * time.Second}

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
			Staging: alaye.Inactive,
			Pebble: alaye.Pebble{
				Enabled:  alaye.Active,
				URL:      pebbleURL,
				Insecure: alaye.Active,
			},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))

	testDomain := "example.pebble.local"
	testHost := &alaye.Host{
		Domains: []string{testDomain},
		TLS: alaye.TLS{
			// leave Mode empty → global LetsEncrypt / Pebble fallback
			LetsEncrypt: global.LetsEncrypt,
		},
	}
	hm.Set(testDomain, testHost)

	mgr := NewManager(testLogger, hm, global, nil)
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}
	defer mgr.Close()

	// configure challtestsrv
	resp, err := challClient.Post(
		fmt.Sprintf("%s/set-default-ipv4", challSrvURL),
		"application/json",
		nil,
	)
	if err == nil {
		resp.Body.Close()
	}
	resp, err = challClient.Post(
		fmt.Sprintf("%s/add-a?host=%s&ip=127.0.0.1", challSrvURL, testDomain),
		"application/json",
		nil,
	)
	if err == nil {
		resp.Body.Close()
	}

	t.Logf("Attempting to obtain certificate for %s from Pebble...", testDomain)
	if mgr.installer != nil {
		_ = mgr.installer.InstallCARootIfNeeded()
	}

	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: testDomain})
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "no such host") {
			t.Skipf("Pebble not running: %v", err)
		}
		t.Fatalf("Failed to obtain certificate: %v", err)
	}
	if cert == nil {
		t.Fatal("Got nil certificate")
	}
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

	found := slices.Contains(leaf.DNSNames, testDomain)
	if !found {
		t.Errorf("Certificate missing DNS name %s", testDomain)
	}

	// cleanup
	resp, err = challClient.Post(
		fmt.Sprintf("%s/clear-a?host=%s", challSrvURL, testDomain),
		"application/json",
		nil,
	)
	if err == nil {
		resp.Body.Close()
	}
}

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
				Enabled:  alaye.Active,
				URL:      "https://localhost:14000/dir",
				Insecure: alaye.Active,
			},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))

	// === REGISTER ALL TEST HOSTS ===
	domains := []string{
		"test1.pebble.local",
		"test2.pebble.local",
		"*.wildcard.pebble.local",
	}
	for _, domain := range domains {
		testHost := &alaye.Host{
			Domains: []string{domain},
			TLS: alaye.TLS{
				LetsEncrypt: global.LetsEncrypt,
			},
		}
		hm.Set(domain, testHost)
	}

	mgr := NewManager(testLogger, hm, global, nil)
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}
	defer mgr.Close()

	if mgr.installer != nil {
		_ = mgr.installer.InstallCARootIfNeeded()
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
			if err != nil {
				if strings.Contains(err.Error(), "connection refused") ||
					strings.Contains(err.Error(), "no such host") {
					t.Skipf("Pebble not running: %v", err)
				}
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
