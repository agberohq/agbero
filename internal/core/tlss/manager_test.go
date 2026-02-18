package tlss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/caddyserver/certmagic"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("tlss").Disable()
)

func generateTestCert(t *testing.T, certFile, keyFile string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

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

func generateECDSATestCert(t *testing.T, certFile, keyFile string, hosts []string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co ECDSA"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    hosts,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create ECDSA certificate: %v", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Failed to open cert.pem: %v", err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to open key.pem: %v", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal ECDSA key: %v", err)
	}

	pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
}

func TestTlsManager_EnsureCertMagic_Success(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		LetsEncrypt: alaye.LetsEncrypt{Enabled: alaye.Active, Email: "test@example.com"},
		Storage:     alaye.Storage{CertsDir: tmpDir},
	}

	m := &Manager{
		logger:      testLogger,
		hostManager: &discovery.Host{},
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

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Handler returned status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestTlsManager_EnsureCertMagic_NoEmail(t *testing.T) {
	m := &Manager{
		logger:      testLogger,
		hostManager: &discovery.Host{},
		Global: &alaye.Global{
			Storage:     alaye.Storage{CertsDir: "/tmp"},
			LetsEncrypt: alaye.LetsEncrypt{Enabled: alaye.Active},
		},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, err := m.EnsureCertMagic(next)
	if err == nil || !strings.Contains(err.Error(), "le_email is empty") {
		t.Errorf("Expected email error, got %v", err)
	}
}

func TestTlsManager_CmForHost_StagingDefault(t *testing.T) {
	m := &Manager{Global: &alaye.Global{
		LetsEncrypt: alaye.LetsEncrypt{Staging: true},
	}}
	m.cmProd = &certmagic.Config{}
	m.cmStaging = &certmagic.Config{}

	cm := m.CmForHost(&alaye.Host{})
	if cm != m.cmStaging {
		t.Error("Expected staging when staging_default=true")
	}
}

func TestTlsManager_CmForHost_ProdDefault(t *testing.T) {
	m := &Manager{Global: &alaye.Global{
		LetsEncrypt: alaye.LetsEncrypt{Enabled: alaye.Active, Staging: false},
	}}
	m.cmProd = &certmagic.Config{}
	m.cmStaging = &certmagic.Config{}

	cm := m.CmForHost(&alaye.Host{})
	if cm != m.cmProd {
		t.Error("Expected prod when staging_default=false")
	}
}

func TestTlsManager_CmForHost_StagingOverride(t *testing.T) {
	m := &Manager{}
	m.Global = &alaye.Global{}
	m.cmProd = &certmagic.Config{}
	m.cmStaging = &certmagic.Config{}

	hcfg := &alaye.Host{TLS: alaye.TLS{LetsEncrypt: alaye.LetsEncrypt{Staging: true}}}
	cm := m.CmForHost(hcfg)
	if cm != m.cmStaging {
		t.Error("Expected staging on host override")
	}
}

func TestTlsManager_GetLocalCertificate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	generateTestCert(t, certFile, keyFile)

	m := NewManager(testLogger, &discovery.Host{}, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	local := alaye.LocalCert{CertFile: certFile, KeyFile: keyFile}
	cert, err := m.GetLocalCertificate(&local, "test.com")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if cert == nil {
		t.Error("Cert not loaded")
	}
}

func TestTlsManager_GetLocalCertificate_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()

	m := NewManager(testLogger, &discovery.Host{}, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	local := alaye.LocalCert{
		CertFile: filepath.Join(tmpDir, "nonexistent.pem"),
		KeyFile:  filepath.Join(tmpDir, "nonexistent.key"),
	}
	_, err := m.GetLocalCertificate(&local, "test.com")
	if err == nil {
		t.Error("Expected error for missing files")
	}
}

func TestTlsManager_GetLocalCertificate_EmptyPaths(t *testing.T) {
	m := NewManager(testLogger, &discovery.Host{}, &alaye.Global{})

	local := alaye.LocalCert{CertFile: "", KeyFile: ""}
	_, err := m.GetLocalCertificate(&local, "test.com")
	if err == nil || !strings.Contains(err.Error(), "local tls requires") {
		t.Errorf("Expected missing cert/key error, got %v", err)
	}
}

func TestTlsManager_GetCertificate_UnknownHost(t *testing.T) {
	m := NewManager(testLogger, discovery.NewHost("", discovery.WithLogger(nil)), &alaye.Global{})

	chi := &tls.ClientHelloInfo{ServerName: "unknown.com"}
	_, err := m.GetCertificate(chi)
	if err == nil || !strings.Contains(err.Error(), "unknown host") {
		t.Errorf("Expected unknown host error, got %v", err)
	}
}

func TestTlsManager_GetCertificate_NoSNI(t *testing.T) {
	m := NewManager(testLogger, &discovery.Host{}, &alaye.Global{})

	chi := &tls.ClientHelloInfo{ServerName: ""}
	_, err := m.GetCertificate(chi)
	if err == nil || !strings.Contains(err.Error(), "missing SNI") {
		t.Errorf("Expected missing SNI error, got %v", err)
	}
}

func TestTlsManager_GetLocalCertificate_Caching(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	generateTestCert(t, certFile, keyFile)

	m := NewManager(testLogger, &discovery.Host{}, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	local := alaye.LocalCert{CertFile: certFile, KeyFile: keyFile}

	cert1, err := m.GetLocalCertificate(&local, "test.com")
	if err != nil {
		t.Fatalf("First load failed: %v", err)
	}

	cert2, err := m.GetLocalCertificate(&local, "test.com")
	if err != nil {
		t.Fatalf("Second load failed: %v", err)
	}

	if cert1 != cert2 {
		t.Error("Certificate not cached")
	}

	if len(m.LocalCache) != 1 {
		t.Errorf("Expected 1 cache entry, got %d", len(m.LocalCache))
	}
}

func TestTlsManager_InvalidateLocal(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	generateTestCert(t, certFile, keyFile)

	m := NewManager(testLogger, &discovery.Host{}, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	local := alaye.LocalCert{CertFile: certFile, KeyFile: keyFile}
	cacheKey := certFile + "|" + keyFile

	_, err := m.GetLocalCertificate(&local, "test.com")
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	if len(m.LocalCache) != 1 {
		t.Fatalf("Certificate not cached, cache size: %d", len(m.LocalCache))
	}

	m.invalidateLocal(cacheKey, "test.com")

	if len(m.LocalCache) != 0 {
		t.Errorf("Cache not invalidated, size: %d", len(m.LocalCache))
	}
}

func TestTlsManager_GetConfigForClient_Success(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "localhost.pem")
	keyFile := filepath.Join(tmpDir, "localhost.key.pem")

	generateECDSATestCert(t, certFile, keyFile, []string{"localhost", "127.0.0.1"})

	hostManager := discovery.NewHost("", discovery.WithLogger(nil))
	hostManager.Set("localhost", &alaye.Host{
		Domains: []string{"localhost"},
		TLS: alaye.TLS{
			Mode: alaye.ModeLocalCert,
			Local: alaye.LocalCert{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		},
	})

	m := NewManager(testLogger, hostManager, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	chi := &tls.ClientHelloInfo{ServerName: "localhost"}
	config, err := m.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("GetConfigForClient failed: %v", err)
	}

	if config == nil {
		t.Fatal("Config is nil")
	}

	if config.ClientSessionCache == nil {
		t.Error("ClientSessionCache not set")
	}
	if config.SessionTicketsDisabled {
		t.Error("SessionTickets should not be disabled")
	}

	if len(config.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(config.Certificates))
	}

	if len(config.CurvePreferences) == 0 {
		t.Error("CurvePreferences not set")
	} else if config.CurvePreferences[0] != tls.X25519 {
		t.Errorf("Expected X25519 as first preference, got %v", config.CurvePreferences[0])
	}

	hasTLS13 := false
	for _, suite := range config.CipherSuites {
		if suite == tls.TLS_AES_128_GCM_SHA256 ||
			suite == tls.TLS_AES_256_GCM_SHA384 ||
			suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
			hasTLS13 = true
			break
		}
	}
	if !hasTLS13 {
		t.Error("No TLS 1.3 cipher suites found")
	}
}

func TestTlsManager_GetConfigForClient_Caching(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "localhost.pem")
	keyFile := filepath.Join(tmpDir, "localhost.key.pem")

	generateECDSATestCert(t, certFile, keyFile, []string{"localhost"})

	hostManager := discovery.NewHost("", discovery.WithLogger(nil))
	hostManager.Set("localhost", &alaye.Host{
		Domains: []string{"localhost"},
		TLS: alaye.TLS{
			Mode: alaye.ModeLocalCert,
			Local: alaye.LocalCert{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		},
	})

	m := NewManager(testLogger, hostManager, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	chi := &tls.ClientHelloInfo{ServerName: "localhost"}

	config1, err := m.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	config2, err := m.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	if config1.ClientSessionCache != config2.ClientSessionCache {
		t.Error("Session cache not shared between configs")
	}
}

func TestTlsManager_GetConfigForClient_MissingSNI(t *testing.T) {
	m := NewManager(testLogger, &discovery.Host{}, &alaye.Global{})

	chi := &tls.ClientHelloInfo{ServerName: ""}
	_, err := m.GetConfigForClient(chi)
	if err == nil || !strings.Contains(err.Error(), "missing SNI") {
		t.Errorf("Expected missing SNI error, got %v", err)
	}
}

func TestTlsManager_GetConfigForClient_UnknownHost(t *testing.T) {
	m := NewManager(testLogger, discovery.NewHost("", discovery.WithLogger(nil)), &alaye.Global{})

	chi := &tls.ClientHelloInfo{ServerName: "unknown.localhost"}
	_, err := m.GetConfigForClient(chi)
	if err == nil || !strings.Contains(err.Error(), "unknown host") {
		t.Errorf("Expected unknown host error, got %v", err)
	}
}

func TestTlsManager_GetConfigForClient_SessionResumptionConfig(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test.pem")
	keyFile := filepath.Join(tmpDir, "test.key.pem")

	generateECDSATestCert(t, certFile, keyFile, []string{"test.localhost"})

	hostManager := discovery.NewHost("", discovery.WithLogger(nil))
	hostManager.Set("test.localhost", &alaye.Host{
		Domains: []string{"test.localhost"},
		TLS: alaye.TLS{
			Mode: alaye.ModeLocalCert,
			Local: alaye.LocalCert{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		},
	})

	m := NewManager(testLogger, hostManager, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	chi := &tls.ClientHelloInfo{ServerName: "test.localhost"}
	config, err := m.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("GetConfigForClient failed: %v", err)
	}

	if config.ClientSessionCache == nil {
		t.Fatal("ClientSessionCache is nil - session resumption disabled")
	}

	if config.SessionTicketsDisabled {
		t.Error("SessionTicketsDisabled should be false for resumption")
	}

	if config.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion too low: %d", config.MinVersion)
	}

	if config.DynamicRecordSizingDisabled {
		t.Error("DynamicRecordSizing should be enabled for throughput")
	}
}

func TestTlsManager_GetConfigForClient_IPHostRejected(t *testing.T) {
	m := NewManager(testLogger, discovery.NewHost("", discovery.WithLogger(nil)), &alaye.Global{})

	chi := &tls.ClientHelloInfo{ServerName: "127.0.0.1"}
	_, err := m.GetConfigForClient(chi)
	if err == nil || (!strings.Contains(err.Error(), "missing SNI") && !strings.Contains(err.Error(), "unknown host")) {
		t.Errorf("Expected error for IP SNI, got %v", err)
	}
}

func TestTlsManager_GetConfigForClient_ConfigCacheInvalidation(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "localhost.pem")
	keyFile := filepath.Join(tmpDir, "localhost.key.pem")

	generateECDSATestCert(t, certFile, keyFile, []string{"localhost"})

	hostManager := discovery.NewHost("", discovery.WithLogger(nil))
	hostManager.Set("localhost", &alaye.Host{
		Domains: []string{"localhost"},
		TLS: alaye.TLS{
			Mode: alaye.ModeLocalCert,
			Local: alaye.LocalCert{
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		},
	})

	m := NewManager(testLogger, hostManager, &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	})

	chi := &tls.ClientHelloInfo{ServerName: "localhost"}

	_, err := m.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	if _, ok := m.configCache.Load("localhost"); !ok {
		t.Fatal("Config not cached")
	}

	cacheKey := certFile + "|" + keyFile
	m.invalidateLocal(cacheKey, "localhost")

	if _, ok := m.configCache.Load("localhost"); ok {
		t.Error("Config cache not cleared after local cert invalidation")
	}
}
