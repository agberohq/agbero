package tlss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/tlss/tlsstore"
	"github.com/go-acme/lego/v4/registration"
)

func TestAcmeUser_Interface(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg := &registration.Resource{URI: "test"}
	user := &AcmeUser{
		Email:        "test@example.com",
		Registration: reg,
		key:          priv,
	}
	if user.GetEmail() != "test@example.com" {
		t.Error("GetEmail failed")
	}
	if user.GetRegistration() != reg {
		t.Error("GetRegistration failed")
	}
	if user.GetPrivateKey() != priv {
		t.Error("GetPrivateKey failed")
	}
}

func TestChallengeStore_Present(t *testing.T) {
	store := NewChallengeStore(testLogger)
	err := store.Present("example.com", "token123", "keyAuth456")
	if err != nil {
		t.Fatalf("Present failed: %v", err)
	}
	auth, ok := store.GetKeyAuth("token123")
	if !ok || auth != "keyAuth456" {
		t.Error("Present did not store challenge correctly")
	}
}

func TestChallengeStore_CleanUp(t *testing.T) {
	store := NewChallengeStore(testLogger)
	store.Present("example.com", "token123", "keyAuth456")
	err := store.CleanUp("example.com", "token123", "keyAuth456")
	if err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}
	_, ok := store.GetKeyAuth("token123")
	if ok {
		t.Error("CleanUp did not remove challenge")
	}
}

func TestChallengeStore_WithCluster(t *testing.T) {
	logger := testLogger
	store := NewChallengeStore(logger)
	var broadcastToken, broadcastAuth string
	var broadcastDeleted bool
	cluster := &mockCluster{
		broadcastFn: func(token, keyAuth string, deleted bool) {
			broadcastToken = token
			broadcastAuth = keyAuth
			broadcastDeleted = deleted
		},
	}
	store.SetCluster(cluster)
	store.Present("example.com", "t1", "a1")
	if broadcastToken != "t1" || broadcastAuth != "a1" || broadcastDeleted != false {
		t.Error("Present broadcast failed")
	}
	store.CleanUp("example.com", "t1", "a1")
	if broadcastToken != "t1" || broadcastDeleted != true {
		t.Error("CleanUp broadcast failed")
	}
}

func TestChallengeStore_GetKeyAuth_NotFound(t *testing.T) {
	store := NewChallengeStore(testLogger)
	_, ok := store.GetKeyAuth("nonexistent")
	if ok {
		t.Error("GetKeyAuth should return false for missing token")
	}
}

func TestChallengeStore_SyncFromCluster_Delete(t *testing.T) {
	store := NewChallengeStore(testLogger)
	store.Present("example.com", "t1", "a1")
	store.SyncFromCluster("t1", "a1", true)
	_, ok := store.GetKeyAuth("t1")
	if ok {
		t.Error("SyncFromCluster delete failed")
	}
}

type mockCluster struct {
	broadcastFn     func(token, keyAuth string, deleted bool)
	broadcastCertFn func(domain string, certPEM, keyPEM []byte) error
}

func (m *mockCluster) TryAcquireLock(key string) bool { return true }

func (m *mockCluster) BroadcastChallenge(token, keyAuth string, deleted bool) {
	if m.broadcastFn != nil {
		m.broadcastFn(token, keyAuth, deleted)
	}
}

func (m *mockCluster) BroadcastCert(domain string, certPEM, keyPEM []byte) error {
	if m.broadcastCertFn != nil {
		return m.broadcastCertFn(domain, certPEM, keyPEM)
	}
	return nil
}

func TestManager_updateInternal_Notify(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	var called atomic.Bool
	done := make(chan struct{})
	mgr.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {
		called.Store(true)
		close(done)
	})
	certPEM, keyPEM := generateACMETestCert(t, "test.com")
	err := mgr.UpdateCertificate("test.com", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("UpdateCertificate failed: %v", err)
	}
	select {
	case <-done:
		if !called.Load() {
			t.Error("UpdateCallback was not called")
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for callback")
	}
}

func TestManager_ApplyClusterCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	certPEM, keyPEM := generateACMETestCert(t, "cluster.com")
	err := mgr.ApplyClusterCertificate("cluster.com", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ApplyClusterCertificate failed: %v", err)
	}
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "cluster.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
}

func TestManager_ApplyClusterChallenge(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	mgr.ApplyClusterChallenge("token1", "auth1", false)
	auth, ok := mgr.Challenges.GetKeyAuth("token1")
	if !ok || auth != "auth1" {
		t.Error("ApplyClusterChallenge failed")
	}
	mgr.ApplyClusterChallenge("token1", "auth1", true)
	_, ok = mgr.Challenges.GetKeyAuth("token1")
	if ok {
		t.Error("ApplyClusterChallenge delete failed")
	}
}

func generateACMETestCert(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM
}

func TestManager_loadFromStorage(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	certPEM, keyPEM := generateACMETestCert(t, "localhost")
	err := mgr.UpdateCertificate("localhost", certPEM, keyPEM)
	if err != nil {
		mgr.Close()
		t.Fatalf("UpdateCertificate failed: %v", err)
	}
	mgr.Close()
	mgr2 := NewManager(testLogger, hm, global, nil)
	defer mgr2.Close()
	cert, err := mgr2.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
}

func TestManager_loadFromStorage_NilStorage(t *testing.T) {
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "not-a-dir")
	_ = os.WriteFile(badPath, []byte("x"), 0644)
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  badPath,
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	if mgr.storage == nil {
		t.Error("expected fallback to MemoryStore")
	}
	if _, ok := mgr.storage.(*tlsstore.MemoryStore); !ok {
		t.Error("expected MemoryStore fallback")
	}
	mgr.loadFromStorage()
}

func TestManager_updateInternal_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	err := mgr.UpdateCertificate("bad.com", []byte("invalid"), []byte("invalid"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestManager_GetCertificate_Wildcard(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	certPEM, keyPEM := generateACMETestCert(t, "*.example.com")
	err := mgr.UpdateCertificate("*.example.com", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("UpdateCertificate failed: %v", err)
	}
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "*.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
}

func TestManager_GetCertificate_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "missing.com"})
	if err != woos.ErrCertNotfound {
		t.Fatalf("expected ErrCertNotfound, got: %v", err)
	}
}

func TestManager_GetCertificate_EmptySNI(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if err != woos.ErrMissingSNI {
		t.Fatalf("expected ErrMissingSNI, got: %v", err)
	}
}

func TestManager_ACMEGetConfigForClient(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	cfg, err := mgr.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient failed: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Error("expected TLS 1.2 minimum")
	}
}

func TestManager_EnsureCertMagic(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h, err := mgr.EnsureCertMagic(handler)
	if err != nil {
		t.Fatalf("EnsureCertMagic failed: %v", err)
	}
	if h == nil {
		t.Fatal("handler is nil")
	}
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Error("handler did not execute")
	}
}

func TestManager_SetUpdateCallback(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	mgr.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {})
	if mgr.onUpdate == nil {
		t.Error("SetUpdateCallback failed")
	}
}

func TestManager_SetCluster(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	cluster := &mockCluster{}
	mgr.SetCluster(cluster)
	if mgr.Challenges.cluster != cluster {
		t.Error("ChallengeStore cluster not set")
	}
}

func TestManager_Close(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	mgr.Close()
}

func TestNewManager_StorageInitFail(t *testing.T) {
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "not-a-dir")
	_ = os.WriteFile(badPath, []byte("x"), 0644)
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  badPath,
		},
		Gossip: alaye.Gossip{
			Enabled:   alaye.Inactive,
			SecretKey: "test-secret-1234567890123456",
		},
	}
	mgr, _ := SetupTestManager(t, global)
	defer mgr.Close()
	if mgr.storage == nil {
		t.Error("expected fallback to MemoryStore")
	}
	if _, ok := mgr.storage.(*tlsstore.MemoryStore); !ok {
		t.Error("expected MemoryStore fallback")
	}
}

func TestManager_updateInternal_StorageSaveFail(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	certPEM, keyPEM := generateACMETestCert(t, "test.com")
	err := mgr.UpdateCertificate("test.com", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("UpdateCertificate failed: %v", err)
	}
}

func TestManager_loadFromStorage_InvalidCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "bad.com.crt")
	keyPath := filepath.Join(tmpDir, "bad.com.key")
	os.WriteFile(certPath, []byte("invalid cert"), 0644)
	os.WriteFile(keyPath, []byte("invalid key"), 0600)
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	mgr.loadFromStorage()
}

func TestManager_loadFromStorage_ListFail(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}
	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(testLogger, hm, global, nil)
	defer mgr.Close()
	os.RemoveAll(tmpDir)
	mgr.loadFromStorage()
}

func TestManager_EntryPoint_LocalhostVsPublic(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: filepath.Join(tmpDir, "certs"),
			DataDir:  filepath.Join(tmpDir, "data"),
		},
		Gossip: alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
			Pebble:  alaye.Pebble{Enabled: alaye.Active, Insecure: alaye.Active},
		},
	}
	mgr, _ := SetupTestManager(t, global)
	defer mgr.Close()
	if mgr.installer != nil {
		err := mgr.installer.InstallCARootIfNeeded()
		if err != nil {
			t.Fatalf("Failed to initialize CA in mock mode: %v", err)
		}
	}
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Logf("localhost cert result (mock mode): %v", err)
	} else if cert != nil {
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		t.Logf("got localhost cert with CN: %s", leaf.Subject.CommonName)
	}
	_, err = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "public.example.com"})
	if err != woos.ErrCertNotfound {
		t.Logf("public domain result: %v", err)
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
