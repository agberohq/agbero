// internal/core/tls/tls_test.go
package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/caddyserver/certmagic"
	"github.com/fsnotify/fsnotify"
)

// Mock Logger
type mockLogger struct {
	logs []string
}

func (m *mockLogger) Info(msg string, args ...any)      { m.logs = append(m.logs, msg) }
func (m *mockLogger) Warn(msg string, args ...any)      { m.logs = append(m.logs, msg) }
func (m *mockLogger) Error(msg string, args ...any)     { m.logs = append(m.logs, msg) }
func (m *mockLogger) Fields(args ...any) woos.TlsLogger { return m }

// generateTestCert creates a minimal self-signed certificate for testing
func generateTestCert(t *testing.T, certFile, keyFile string) {
	t.Helper()

	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Write private key to file
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
}

func TestTlsManager_EnsureCertMagic_Success(t *testing.T) {
	tmpDir := t.TempDir()
	global := &woos.GlobalConfig{
		LEEmail:       "test@example.com",
		TLSStorageDir: tmpDir,
	}
	m := &TlsManager{
		Logger:      &mockLogger{},
		HostManager: &discovery.Host{},
		Global:      global,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	handler, err := m.EnsureCertMagic(next)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if m.cmProd == nil || m.cmStaging == nil {
		t.Error("CertMagic configs not initialized")
	}
	if handler == nil {
		t.Error("Handler not returned")
	}

	// Test that the handler works
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Handler returned status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestTlsManager_EnsureCertMagic_NoEmail(t *testing.T) {
	m := &TlsManager{
		Logger:      &mockLogger{},
		HostManager: &discovery.Host{},
		Global:      &woos.GlobalConfig{TLSStorageDir: "/tmp"},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, err := m.EnsureCertMagic(next)
	if err == nil || !strings.Contains(err.Error(), "le_email is empty") {
		t.Errorf("Expected email error, got %v", err)
	}
}

func TestTlsManager_CmForHost_DevMode(t *testing.T) {
	m := &TlsManager{Global: &woos.GlobalConfig{Development: true}}
	m.cmProd = &certmagic.Config{}
	m.cmStaging = &certmagic.Config{}

	cm := m.CmForHost(nil)
	if cm != m.cmStaging {
		t.Error("Expected staging in dev mode")
	}
}

func TestTlsManager_CmForHost_StagingOverride(t *testing.T) {
	m := &TlsManager{}
	m.cmProd = &certmagic.Config{}
	m.cmStaging = &certmagic.Config{}

	hcfg := &woos.HostConfig{TLS: &woos.TLS{LetsEncrypt: woos.LetsEncrypt{Staging: true}}}
	cm := m.CmForHost(hcfg)
	if cm != m.cmStaging {
		t.Error("Expected staging on host override")
	}
}

func TestTlsManager_GetLocalCertificate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate valid test certificate
	generateTestCert(t, certFile, keyFile)

	m := &TlsManager{Logger: &mockLogger{}, LocalCache: make(map[string]*tls.Certificate)}
	local := woos.LocalCert{CertFile: certFile, KeyFile: keyFile}
	cert, err := m.GetLocalCertificate(local, "test.com")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if cert == nil {
		t.Error("Cert not loaded")
	}
}

func TestTlsManager_GetLocalCertificate_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	m := &TlsManager{Logger: &mockLogger{}, LocalCache: make(map[string]*tls.Certificate)}
	local := woos.LocalCert{
		CertFile: filepath.Join(tmpDir, "nonexistent.pem"),
		KeyFile:  filepath.Join(tmpDir, "nonexistent.key"),
	}
	_, err := m.GetLocalCertificate(local, "test.com")
	if err == nil {
		t.Error("Expected error for missing files")
	}
}

func TestTlsManager_GetLocalCertificate_EmptyPaths(t *testing.T) {
	m := &TlsManager{Logger: &mockLogger{}, LocalCache: make(map[string]*tls.Certificate)}
	local := woos.LocalCert{CertFile: "", KeyFile: ""}
	_, err := m.GetLocalCertificate(local, "test.com")
	if err == nil || !strings.Contains(err.Error(), "local tls requires") {
		t.Errorf("Expected missing cert/key error, got %v", err)
	}
}

func TestTlsManager_GetCertificate_UnknownHost(t *testing.T) {
	m := &TlsManager{
		Logger:      &mockLogger{},
		HostManager: discovery.NewHost("", discovery.WithLogger(nil)),
	}

	chi := &tls.ClientHelloInfo{ServerName: "unknown.com"}
	_, err := m.GetCertificate(chi)
	if err == nil || !strings.Contains(err.Error(), "unknown host") {
		t.Errorf("Expected unknown host error, got %v", err)
	}
}

func TestTlsManager_GetCertificate_NoSNI(t *testing.T) {
	m := &TlsManager{Logger: &mockLogger{}}
	chi := &tls.ClientHelloInfo{ServerName: ""}
	_, err := m.GetCertificate(chi)
	if err == nil || !strings.Contains(err.Error(), "missing SNI") {
		t.Errorf("Expected missing SNI error, got %v", err)
	}
}

func TestTlsManager_Close(t *testing.T) {
	m := &TlsManager{}
	m.Watchers = make(map[string]*fsnotify.Watcher)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}
	m.Watchers["test"] = w

	m.Close()
	if len(m.Watchers) != 0 {
		t.Error("Watchers not closed")
	}
}

func TestTlsManager_GetLocalCertificate_Caching(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate valid test certificate
	generateTestCert(t, certFile, keyFile)

	m := &TlsManager{
		Logger:     &mockLogger{},
		LocalCache: make(map[string]*tls.Certificate),
	}
	local := woos.LocalCert{CertFile: certFile, KeyFile: keyFile}

	// First call should load and cache
	cert1, err := m.GetLocalCertificate(local, "test.com")
	if err != nil {
		t.Fatalf("First load failed: %v", err)
	}

	// Second call should use cache
	cert2, err := m.GetLocalCertificate(local, "test.com")
	if err != nil {
		t.Fatalf("Second load failed: %v", err)
	}

	// Should be the same certificate (pointer comparison)
	if cert1 != cert2 {
		t.Error("Certificate not cached")
	}

	// Cache should have one entry
	if len(m.LocalCache) != 1 {
		t.Errorf("Expected 1 cache entry, got %d", len(m.LocalCache))
	}
}

func TestTlsManager_InvalidateLocal(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate valid test certificate
	generateTestCert(t, certFile, keyFile)

	m := &TlsManager{
		Logger:     &mockLogger{},
		LocalCache: make(map[string]*tls.Certificate),
	}
	local := woos.LocalCert{CertFile: certFile, KeyFile: keyFile}
	cacheKey := certFile + "|" + keyFile

	// Load certificate into cache
	_, err := m.GetLocalCertificate(local, "test.com")
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	// Verify it's cached
	if len(m.LocalCache) != 1 {
		t.Fatalf("Certificate not cached, cache size: %d", len(m.LocalCache))
	}

	// Invalidate the cache
	m.invalidateLocal(cacheKey, "test.com")

	// Cache should be empty
	if len(m.LocalCache) != 0 {
		t.Errorf("Cache not invalidated, size: %d", len(m.LocalCache))
	}
}
