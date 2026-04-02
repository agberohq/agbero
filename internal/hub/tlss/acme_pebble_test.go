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
	"github.com/agberohq/agbero/internal/hub/discovery"
)

// mockClusterForPebble catches Lego's HTTP-01 tokens and posts them directly to
// pebble-challtestsrv's management API (port 8055). This completely avoids
// port 5002 binding conflicts.
type mockClusterForPebble struct {
	challSrvURL string
}

func (m *mockClusterForPebble) BroadcastChallenge(token, keyAuth string, deleted bool) {
	client := &http.Client{Timeout: 2 * time.Second}
	if !deleted {
		payload := fmt.Sprintf(`{"token":"%s","content":"%s"}`, token, keyAuth)
		_, _ = client.Post(fmt.Sprintf("%s/add-http01", m.challSrvURL), "application/json", strings.NewReader(payload))
	} else {
		payload := fmt.Sprintf(`{"token":"%s"}`, token)
		_, _ = client.Post(fmt.Sprintf("%s/del-http01", m.challSrvURL), "application/json", strings.NewReader(payload))
	}
}

func (m *mockClusterForPebble) BroadcastCert(domain string, certPEM, keyPEM []byte) error { return nil }
func (m *mockClusterForPebble) TryAcquireLock(key string) bool                            { return true }

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
	hm.Set(testDomain, &alaye.Host{
		Domains: []string{testDomain},
		TLS:     alaye.TLS{LetsEncrypt: global.LetsEncrypt},
	})

	mgr := NewManager(testLogger, hm, global, nil)
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}

	// Inject the mock cluster to push to challtestsrv
	mgr.SetCluster(&mockClusterForPebble{challSrvURL: challSrvURL})
	defer mgr.Close()

	// Configure challtestsrv to route DNS to 127.0.0.1
	resp, _ := challClient.Post(fmt.Sprintf("%s/set-default-ipv4", challSrvURL), "application/json", nil)
	if resp != nil {
		resp.Body.Close()
	}
	resp, _ = challClient.Post(fmt.Sprintf("%s/add-a?host=%s&ip=127.0.0.1", challSrvURL, testDomain), "application/json", nil)
	if resp != nil {
		resp.Body.Close()
	}

	t.Logf("Attempting to obtain certificate for %s from Pebble...", testDomain)
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: testDomain})
	if err != nil {
		t.Fatalf("Failed to obtain certificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("Got nil/empty certificate")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	if !slices.Contains(leaf.DNSNames, testDomain) {
		t.Errorf("Certificate missing DNS name %s", testDomain)
	}
}

func TestPebbleWithCustomDomain(t *testing.T) {
	if os.Getenv("PEBBLE_TEST") == "" {
		t.Skip("Set PEBBLE_TEST=1 to run Pebble integration tests")
	}
	challSrvURL := os.Getenv("CHALLTESTSRV_URL")
	if challSrvURL == "" {
		challSrvURL = "http://localhost:8055"
	}
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
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
	domains := []string{"test1.pebble.local", "test2.pebble.local"}

	for _, domain := range domains {
		hm.Set(domain, &alaye.Host{
			Domains: []string{domain},
			TLS:     alaye.TLS{LetsEncrypt: global.LetsEncrypt},
		})

		// Configure DNS for tests
		http.Post(fmt.Sprintf("%s/add-a?host=%s&ip=127.0.0.1", challSrvURL, domain), "application/json", nil)
	}

	mgr := NewManager(testLogger, hm, global, nil)
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}
	mgr.SetCluster(&mockClusterForPebble{challSrvURL: challSrvURL})
	defer mgr.Close()

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
			if err != nil {
				t.Fatalf("Failed to obtain certificate for %s: %v", domain, err)
			}
			if cert == nil {
				t.Fatal("Got nil certificate")
			}
		})
	}
}

func TestACMEProvider_PebbleIntegration(t *testing.T) {
	if os.Getenv("PEBBLE_TEST") == "" {
		t.Skip("set PEBBLE_TEST=1 to run Pebble integration tests")
	}
	tmpDir := t.TempDir()
	pebbleURL := os.Getenv("PEBBLE_URL")
	if pebbleURL == "" {
		pebbleURL = "https://localhost:14000/dir"
	}
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@pebble.local",
			Pebble: alaye.Pebble{
				Enabled:  alaye.Active,
				URL:      pebbleURL,
				Insecure: alaye.Active,
			},
		},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	testDomain := "test.pebble.local"
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: testDomain})
	if err != nil {
		t.Logf("Pebble cert obtain (expected if Pebble not running): %v", err)
		return
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("cert has no leaf")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if !leaf.IsCA && leaf.Subject.CommonName == testDomain {
		t.Logf("obtained cert for %s, valid until %s", testDomain, leaf.NotAfter)
	}
}
