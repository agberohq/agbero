package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	discovery2 "github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/go-chi/chi/v5"
)

type mockHostManagerForCerts struct {
	*discovery2.Host
}

func newMockHostManagerForCerts(t *testing.T) *mockHostManagerForCerts {
	t.Helper()
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		t.Fatalf("Failed to create hosts dir: %v", err)
	}
	h := discovery2.NewHost(woos.NewFolder(hostsDir), discovery2.WithLogger(testLogger))
	return &mockHostManagerForCerts{Host: h}
}

func setupTestCerts(t *testing.T) (*Shared, func()) {
	t.Helper()
	tmpDir := t.TempDir()

	certsDir := filepath.Join(tmpDir, "certs")
	dataDir := filepath.Join(tmpDir, "data")
	hostsDir := filepath.Join(tmpDir, "hosts")
	for _, d := range []string{certsDir, dataDir, hostsDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("Failed to create dir %s: %v", d, err)
		}
	}

	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: certsDir,
			DataDir:  dataDir,
			HostsDir: hostsDir,
		},
		LetsEncrypt: alaye.LetsEncrypt{Enabled: alaye.Inactive},
		Gossip:      alaye.Gossip{Enabled: alaye.Inactive},
	}

	hm := newMockHostManagerForCerts(t)
	// nil keeper → disk backend using certsDir/dataDir
	tlsMgr := tlss.NewManager(testLogger, hm.Host, global, nil)

	shared := &Shared{Logger: testLogger}
	shared.UpdateState(&ActiveState{
		Global: global,
		TLSS:   tlsMgr,
	})

	return shared, func() {
		tlsMgr.Close()
		os.RemoveAll(tmpDir)
	}
}

func generateTestCert(domain string) (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}

func TestCertsHandler_List_WithWildcardCert(t *testing.T) {
	shared, cleanup := setupTestCerts(t)
	defer cleanup()

	certPEM, keyPEM, err := generateTestCert("*.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	// UpdateCertificate stores via storage.Save(IssuerCustom, domain, ...).
	// list() now calls ts.ListCertificates() → storage.List() which sees it correctly.
	if err := shared.State().TLSS.UpdateCertificate("*.example.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Failed to update certificate: %v", err)
	}

	r := chi.NewRouter()
	CertsHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	certs, ok := resp["certificates"].([]any)
	if !ok {
		t.Fatal("Expected certificates array")
	}
	if len(certs) != 1 {
		t.Fatalf("Expected 1 certificate, got %d", len(certs))
	}

	firstCert := certs[0].(map[string]any)
	domain, _ := firstCert["domain"].(string)
	if domain != "*.example.com" && domain != "*example.com" {
		t.Errorf("Expected domain *.example.com or *example.com, got %q", domain)
	}
}

func TestCertsHandler_List_Empty(t *testing.T) {
	shared, cleanup := setupTestCerts(t)
	defer cleanup()

	r := chi.NewRouter()
	CertsHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/certs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	certs, ok := resp["certificates"].([]any)
	if !ok {
		t.Fatal("Expected certificates array")
	}
	if len(certs) != 0 {
		t.Errorf("Expected 0 certificates, got %d", len(certs))
	}
}

func TestCertsHandler_Upload(t *testing.T) {
	shared, cleanup := setupTestCerts(t)
	defer cleanup()

	certPEM, keyPEM, err := generateTestCert("upload.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	r := chi.NewRouter()
	CertsHandler(shared, r)

	body, _ := json.Marshal(map[string]string{
		"domain": "upload.example.com",
		"cert":   string(certPEM),
		"key":    string(keyPEM),
	})
	req := httptest.NewRequest(http.MethodPost, "/certs", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("Expected status=ok, got %v", resp)
	}
}

func TestCertsHandler_Delete_WildcardDomain(t *testing.T) {
	shared, cleanup := setupTestCerts(t)
	defer cleanup()

	certPEM, keyPEM, err := generateTestCert("*.wildcard.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	if err := shared.State().TLSS.UpdateCertificate("*.wildcard.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Failed to update certificate: %v", err)
	}

	r := chi.NewRouter()
	CertsHandler(shared, r)

	req := httptest.NewRequest(http.MethodDelete, "/certs/*.wildcard.com", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertsHandler_Delete_InvalidDomain(t *testing.T) {
	shared, cleanup := setupTestCerts(t)
	defer cleanup()

	r := chi.NewRouter()
	CertsHandler(shared, r)

	req := httptest.NewRequest(http.MethodDelete, "/certs/..", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestCertsHandler_Delete_NoDomain(t *testing.T) {
	shared, cleanup := setupTestCerts(t)
	defer cleanup()

	r := chi.NewRouter()
	CertsHandler(shared, r)

	req := httptest.NewRequest(http.MethodDelete, "/certs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}
