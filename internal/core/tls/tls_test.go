// internal/core/tls/tls_test.go
package tls

import (
	"crypto/tls"

	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
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
}

func TestTlsManager_EnsureCertMagic_NoEmail(t *testing.T) {
	m := &TlsManager{
		Logger:      &mockLogger{},
		HostManager: &discovery.Host{},
		Global:      &woos.GlobalConfig{TLSStorageDir: "/tmp"},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler, err := m.EnsureCertMagic(next)
	if err == nil || !strings.Contains(err.Error(), "le_email is empty") {
		t.Errorf("Expected email error, got %v", err)
	}
	if handler.ServeHTTP != next {
		t.Error("Handler modified unexpectedly")
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

	hcfg := &woos.HostConfig{TLS: &woos.TSL{LetsEncrypt: woos.LetsEncrypt{Staging: true}}}
	cm := m.CmForHost(hcfg)
	if cm != m.cmStaging {
		t.Error("Expected staging on host override")
	}
}

func TestTlsManager_GetLocalCertificate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Mock cert/key (minimal PEM)
	os.WriteFile(certFile, []byte(`-----BEGIN CERTIFICATE-----
MIIBCgKCAQEAtest
-----END CERTIFICATE-----`), 0644)
	os.WriteFile(keyFile, []byte(`-----BEGIN PRIVATE KEY-----
MIIBVAgBAQ==
-----END PRIVATE KEY-----`), 0644)

	m := &TlsManager{Logger: &mockLogger{}}
	local := woos.LocalCert{CertFile: certFile, KeyFile: keyFile}
	cert, err := m.GetLocalCertificate(local, "test.com")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if cert == nil {
		t.Error("Cert not loaded")
	}
}

func TestTlsManager_GetLocalCertificate_ReloadOnChange(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	os.WriteFile(certFile, []byte(`-----BEGIN CERTIFICATE-----
OLD
-----END CERTIFICATE-----`), 0644)
	os.WriteFile(keyFile, []byte(`-----BEGIN PRIVATE KEY-----
OLD
-----END PRIVATE KEY-----`), 0644)

	m := &TlsManager{Logger: &mockLogger{}}
	local := woos.LocalCert{CertFile: certFile, KeyFile: keyFile}
	_, err := m.GetLocalCertificate(local, "test.com")
	if err != nil {
		t.Fatal(err)
	}

	// Change file
	os.WriteFile(certFile, []byte(`-----BEGIN CERTIFICATE-----
NEW
-----END CERTIFICATE-----`), 0644)

	// Simulate watcher event (manual invalidate for test)
	cacheKey := certFile + "|" + keyFile
	m.invalidateLocal(cacheKey, "test.com")

	// Reload
	cert, err := m.GetLocalCertificate(local, "test.com")
	if err != nil {
		t.Errorf("Reload failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("Cert not reloaded")
	}
}

func TestTlsManager_GetCertificate_ShortLived(t *testing.T) {
	m := &TlsManager{Logger: &mockLogger{}, HostManager: discovery.NewHost("", discovery.WithLogger(nil))}
	m.cmProd = certmagic.NewDefault()
	m.issProd = &certmagic.ACMEIssuer{CA: "test-ca"}

	// hcfg := &woos.HostConfig{TLS: &woos.TSL{Mode: woos.ModeLetsEncrypt, LetsEncrypt: woos.LetsEncrypt{ShortLived: true}}}
	chi := &tls.ClientHelloInfo{ServerName: "example.com"}
	m.HostManager.UpdateGossipNode("test", "example.com", woos.Route{}) // Mock host

	_, err := m.GetCertificate(chi)
	if err == nil || !strings.Contains(err.Error(), "test-ca") { // Indirect check via CA
		t.Error("Short-lived not applied")
	}
}

func TestTlsManager_GetCertificate_CustomCA(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")
	os.WriteFile(caFile, []byte(`-----BEGIN CERTIFICATE-----
CA CERT
-----END CERTIFICATE-----`), 0644)

	m := &TlsManager{Logger: &mockLogger{}}
	// hcfg := &woos.HostConfig{TLS: &woos.TSL{Mode: woos.ModeCustomCA, CustomCA: woos.CustomCA{Root: caFile}}}
	m.HostManager = discovery.NewHost("", discovery.WithLogger(nil))
	m.HostManager.UpdateGossipNode("test", "example.com", woos.Route{})

	chi := &tls.ClientHelloInfo{ServerName: "example.com"}
	_, err := m.GetCertificate(chi)
	if err == nil { // Expect fallback error (no local cert)
		t.Error("Expected error without local cert")
	}
}

func TestTlsManager_Close(t *testing.T) {
	m := &TlsManager{}
	m.Watchers = make(map[string]*fsnotify.Watcher)

	w, _ := fsnotify.NewWatcher()
	m.Watchers["test"] = w

	m.Close()
	if len(m.Watchers) != 0 {
		t.Error("Watchers not closed")
	}
}
