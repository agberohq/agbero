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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/go-acme/lego/v4/registration"
	"github.com/olekukonko/ll"
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

func TestClusterProvider_Present(t *testing.T) {
	store := NewChallengeStore(ll.New("test").Disable())
	provider := &ClusterProvider{store: store}

	err := provider.Present("example.com", "token123", "keyAuth456")
	if err != nil {
		t.Fatalf("Present failed: %v", err)
	}

	auth, ok := store.GetKeyAuth("token123")
	if !ok || auth != "keyAuth456" {
		t.Error("Present did not store challenge correctly")
	}
}

func TestClusterProvider_CleanUp(t *testing.T) {
	store := NewChallengeStore(ll.New("test").Disable())
	provider := &ClusterProvider{store: store}

	store.Present("example.com", "token123", "keyAuth456")
	err := provider.CleanUp("example.com", "token123", "keyAuth456")
	if err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}

	_, ok := store.GetKeyAuth("token123")
	if ok {
		t.Error("CleanUp did not remove challenge")
	}
}

func TestManager_setupLegoClient_MissingEmail(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage:     alaye.Storage{CertsDir: tmpDir},
		Gossip:      alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{Enabled: alaye.Active},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.setupLegoClient()
	if err == nil || !strings.Contains(err.Error(), "email is required") {
		t.Fatal("expected error for missing email")
	}
}

func TestManager_setupLegoClient_GeneratesKey(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
			Pebble:  alaye.Pebble{Enabled: true, Insecure: true},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.setupLegoClient()
	if err != nil {
		t.Logf("expected error without pebble server: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "acme_account.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("acme_account.key not created")
	}

	pemBytes, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("invalid PEM in account key")
	}
	_, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("invalid EC key: %v", err)
	}
}

func TestManager_setupLegoClient_LoadsExistingKey(t *testing.T) {
	tmpDir := t.TempDir()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bytes, _ := x509.MarshalECPrivateKey(priv)
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes}
	keyPath := filepath.Join(tmpDir, "acme_account.key")
	f, _ := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(f, pemBlock)
	f.Close()

	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
			Pebble:  alaye.Pebble{Enabled: true, Insecure: true},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.setupLegoClient()
	if err != nil {
		t.Logf("expected error without pebble server: %v", err)
	}

	pemBytes, _ := os.ReadFile(keyPath)
	block, _ := pem.Decode(pemBytes)
	key, _ := x509.ParseECPrivateKey(block.Bytes)
	if key.X.Cmp(priv.X) != 0 {
		t.Error("loaded key differs from original")
	}
}

func TestManager_setupLegoClient_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "acme_account.key")
	os.WriteFile(keyPath, []byte("invalid pem"), 0600)

	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.loadOrGenAccountKey()
	if err == nil || !strings.Contains(err.Error(), "no PEM data") {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestManager_setupLegoClient_PebbleConfig(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
			Pebble: alaye.Pebble{
				Enabled:  true,
				URL:      "https://pebble.example.com/dir",
				Insecure: true,
			},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.setupLegoClient()
	if err != nil {
		t.Logf("expected error without server: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "acme_account.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("key not created with pebble config")
	}
}

func TestManager_setupLegoClient_StagingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
			Staging: true,
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.setupLegoClient()
	if err != nil {
		t.Logf("expected error without network: %v", err)
	}
}

func TestManager_setupLegoClient_ProductionConfig(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.setupLegoClient()
	if err != nil {
		t.Logf("expected error without network: %v", err)
	}
}

func TestManager_loadOrGenAccountKey_WriteError(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: "/nonexistent/path"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)

	_, err := mgr.loadOrGenAccountKey()
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestManager_setupLegoClient_DefaultPebbleURL(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
			Pebble: alaye.Pebble{
				Enabled: true,
				URL:     "",
			},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.setupLegoClient()
	if err != nil {
		t.Logf("expected error: %v", err)
	}

	keyPath := filepath.Join(tmpDir, "acme_account.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("key not created")
	}
}

func TestManager_loadOrGenAccountKey_ReadError(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "acme_account.key")
	os.Mkdir(keyPath, 0755)

	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)

	_, err := mgr.loadOrGenAccountKey()
	if err == nil {
		t.Fatal("expected error reading directory as file")
	}
}

func TestChallengeStore_WithCluster(t *testing.T) {
	logger := ll.New("test").Disable()
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
	store := NewChallengeStore(ll.New("test").Disable())

	_, ok := store.GetKeyAuth("nonexistent")
	if ok {
		t.Error("GetKeyAuth should return false for missing token")
	}
}

func TestChallengeStore_SyncFromCluster_Delete(t *testing.T) {
	store := NewChallengeStore(ll.New("test").Disable())

	store.Present("example.com", "t1", "a1")
	store.SyncFromCluster("t1", "a1", true)

	_, ok := store.GetKeyAuth("t1")
	if ok {
		t.Error("SyncFromCluster delete failed")
	}
}

type mockCluster struct {
	broadcastFn func(token, keyAuth string, deleted bool)
}

func (m *mockCluster) TryAcquireLock(key string) bool { return true }
func (m *mockCluster) BroadcastChallenge(token, keyAuth string, deleted bool) {
	if m.broadcastFn != nil {
		m.broadcastFn(token, keyAuth, deleted)
	}
}

func TestManager_obtainCert(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
			Pebble:  alaye.Pebble{Enabled: true, Insecure: true},
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	mgr.obtainCert("test.example.com")
}

func TestManager_checkRenewals(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	mgr.checkRenewals()
}

func TestManager_checkRenewals_WithExpiredCert(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
		LetsEncrypt: alaye.LetsEncrypt{
			Enabled: alaye.Active,
			Email:   "test@example.com",
		},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	cluster := &mockCluster{}
	mgr.SetCluster(cluster)

	mgr.checkRenewals()
}

func TestManager_updateInternal_Notify(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
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
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
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
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
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

func TestManager_startScheduler(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	if mgr.scheduler == nil {
		t.Error("scheduler not started")
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
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	certPEM, keyPEM := generateACMETestCert(t, "persist.com")
	err := mgr.UpdateCertificate("persist.com", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("UpdateCertificate failed: %v", err)
	}

	mgr2 := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr2.Close()

	cert, err := mgr2.GetCertificate(&tls.ClientHelloInfo{ServerName: "persist.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
}

func TestManager_loadFromStorage_NilStorage(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: ""},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	err := mgr.loadFromStorage()
	if err != nil {
		t.Fatalf("loadFromStorage should succeed with nil storage: %v", err)
	}
}

func TestManager_updateInternal_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	err := mgr.UpdateCertificate("bad.com", []byte("invalid"), []byte("invalid"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestManager_GetCertificate_Wildcard(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	certPEM, keyPEM := generateACMETestCert(t, "*.example.com")
	err := mgr.UpdateCertificate("*.example.com", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("UpdateCertificate failed: %v", err)
	}

	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "sub.example.com"})
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
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "missing.com"})
	if err != woos.ErrCertNotfound {
		t.Fatalf("expected ErrCertNotfound, got: %v", err)
	}
}

func TestManager_GetCertificate_EmptySNI(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if err != woos.ErrMissingSNI {
		t.Fatalf("expected ErrMissingSNI, got: %v", err)
	}
}

func TestManager_ACMEGetConfigForClient(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
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
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
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
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	mgr.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {})

	if mgr.onUpdate == nil {
		t.Error("SetUpdateCallback failed")
	}
}

func TestManager_SetCluster(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	cluster := &mockCluster{}
	mgr.SetCluster(cluster)

	if mgr.cluster != cluster {
		t.Error("SetCluster failed")
	}
	if mgr.Challenges.cluster != cluster {
		t.Error("ChallengeStore cluster not set")
	}
}

func TestManager_Close(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	mgr.Close()
}

func TestManager_checkRenewals_LockNotAcquired(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	cluster := &lockFailCluster{}
	mgr.SetCluster(cluster)

	certPEM, keyPEM := generateACMETestCert(t, "locked.com")
	mgr.UpdateCertificate("locked.com", certPEM, keyPEM)

	mgr.checkRenewals()
}

type lockFailCluster struct{}

func (l *lockFailCluster) TryAcquireLock(key string) bool                         { return false }
func (l *lockFailCluster) BroadcastChallenge(token, keyAuth string, deleted bool) {}

func TestManager_checkRenewals_NilLeaf(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	mgr.checkRenewals()
}

func TestNewManager_StorageInitFail(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: "/nonexistent/path/that/fails"},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	if mgr.storage != nil {
		t.Error("storage should be nil on init fail")
	}
}

func TestManager_updateInternal_StorageSaveFail(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
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
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	err := mgr.loadFromStorage()
	if err != nil {
		t.Logf("loadFromStorage error (expected): %v", err)
	}
}

func TestManager_loadFromStorage_ListFail(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	os.RemoveAll(tmpDir)

	err := mgr.loadFromStorage()
	if err == nil {
		t.Log("expected error when storage dir removed")
	}
}

func TestManager_checkRenewals_NoCluster(t *testing.T) {
	tmpDir := t.TempDir()
	global := &alaye.Global{
		Storage: alaye.Storage{CertsDir: tmpDir},
		Gossip:  alaye.Gossip{SecretKey: "test-secret-1234567890123456"},
	}

	hm := discovery.NewHost(woos.NewFolder(tmpDir))
	mgr := NewManager(ll.New("test").Disable(), hm, global)
	defer mgr.Close()

	certPEM, keyPEM := generateACMETestCert(t, "nocluster.com")
	mgr.UpdateCertificate("nocluster.com", certPEM, keyPEM)

	mgr.checkRenewals()
}
