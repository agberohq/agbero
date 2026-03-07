package tlss

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/olekukonko/ll"
)

// Helper: Generate valid PEM data
func generateTestCert(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24),
		DNSNames:     []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM
}

func setupManager(t *testing.T) (*Manager, string) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "secret-12345678"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	return mgr, tmpDir
}

func TestManager_AtomicHotSwap(t *testing.T) {
	mgr, _ := setupManager(t)
	defer mgr.Close()

	domain := "example.com"
	certPEM, keyPEM := generateTestCert(t, domain)

	// 1. Before update: Should fail
	chi := &tls.ClientHelloInfo{ServerName: domain}
	if _, err := mgr.GetCertificate(chi); err != woos.ErrCertNotfound {
		t.Error("Should return CertNotFound before update")
	}

	// 2. Perform Update
	if err := mgr.UpdateCertificate(domain, certPEM, keyPEM); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// 3. After update: Should succeed
	cert, err := mgr.GetCertificate(chi)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert.Leaf == nil {
		t.Error("Leaf certificate not parsed")
	}
	if cert.Leaf.Subject.CommonName != domain {
		t.Errorf("CN mismatch: got %s, want %s", cert.Leaf.Subject.CommonName, domain)
	}
}

func TestManager_WildcardPrecedence(t *testing.T) {
	mgr, _ := setupManager(t)
	defer mgr.Close()

	// Add *.example.com
	wildCert, wildKey := generateTestCert(t, "*.example.com")
	mgr.UpdateCertificate("*.example.com", wildCert, wildKey)

	// Add sub.example.com (Exact)
	subCert, subKey := generateTestCert(t, "sub.example.com")
	mgr.UpdateCertificate("sub.example.com", subCert, subKey)

	// 1. Request sub.example.com -> Should match Exact
	cert, _ := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "sub.example.com"})
	if cert.Leaf.Subject.CommonName != "sub.example.com" {
		t.Errorf("Expected exact match 'sub.example.com', got '%s'", cert.Leaf.Subject.CommonName)
	}

	// 2. Request other.example.com -> Should match Wildcard
	cert2, _ := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	if cert2.Leaf.Subject.CommonName != "*.example.com" {
		t.Errorf("Expected wildcard match '*.example.com', got '%s'", cert2.Leaf.Subject.CommonName)
	}
}

func TestManager_Persistence(t *testing.T) {
	// 1. Setup, save cert, close
	tmpDir := t.TempDir()
	global := &alaye.Global{Storage: alaye.Storage{CertsDir: tmpDir}}

	mgr1 := NewManager(ll.New("test").Disable(), nil, global)
	certPEM, keyPEM := generateTestCert(t, "persist.com")
	mgr1.UpdateCertificate("persist.com", certPEM, keyPEM)
	mgr1.Close()

	// Verify file on disk
	if _, err := os.Stat(filepath.Join(tmpDir, "persist.com.crt")); os.IsNotExist(err) {
		t.Fatal("Cert file not found on disk")
	}

	// 2. New Manager -> Should load from disk
	mgr2 := NewManager(ll.New("test").Disable(), nil, global)
	defer mgr2.Close()

	cert, err := mgr2.GetCertificate(&tls.ClientHelloInfo{ServerName: "persist.com"})
	if err != nil {
		t.Fatalf("Failed to load persisted cert: %v", err)
	}
	if cert == nil {
		t.Fatal("Loaded cert is nil")
	}
}

func TestManager_Concurrency(t *testing.T) {
	mgr, _ := setupManager(t)
	defer mgr.Close()

	domain := "concurrent.com"
	certPEM, keyPEM := generateTestCert(t, domain)

	// Start reader goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Start writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			mgr.UpdateCertificate(domain, certPEM, keyPEM)
			time.Sleep(2 * time.Millisecond)
		}
	}()

	wg.Wait()
	// If no panic/race detected, pass
}

func TestManager_GetConfigForClient(t *testing.T) {
	mgr, _ := setupManager(t)
	defer mgr.Close()

	cfg, err := mgr.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient failed: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS12 {
		t.Error("Expected TLS 1.2 minimum")
	}
}

func TestManager_InvalidPEM(t *testing.T) {
	mgr, _ := setupManager(t)
	defer mgr.Close()

	err := mgr.UpdateCertificate("bad.com", []byte("NOT PEM"), []byte("NOT KEY"))
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}

	// Ensure it wasn't added to cache
	_, err = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "bad.com"})
	if err != woos.ErrCertNotfound {
		t.Error("Invalid cert should not be in cache")
	}
}
