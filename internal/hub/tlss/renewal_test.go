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
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
)

func TestManager_RenewalLogic(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	dataDir.Init(0755)

	global := &alaye.Global{
		Storage: alaye.Storage{
			CertsDir: expect.NewFolder(filepath.Join(tmpDir, "certs")),
			DataDir:  dataDir,
		},
	}

	hm := discovery.NewHost(expect.NewFolder(tmpDir))
	domain := "localhost"

	hm.Set(domain, &alaye.Host{
		Domains: []string{domain},
		TLS:     alaye.TLS{Mode: def.ModeLocalAuto},
	})

	mgr := NewManager(testLogger, hm, global, nil)
	if mgr.installer != nil {
		mgr.installer.SetMockMode(true)
	}
	defer mgr.Close()

	// Generate a certificate that expired 1 minute ago
	expiredCertPEM, expiredKeyPEM := generateExpiringCert(t, domain, -1*time.Minute)
	err := mgr.UpdateCertificate(domain, expiredCertPEM, expiredKeyPEM)
	if err != nil {
		t.Fatalf("failed to insert expiring cert: %v", err)
	}

	certBefore, hit := mgr.cache.Get(domain)
	if !hit || certBefore == nil {
		t.Fatal("failed to get seeded cert from cache")
	}
	oldSerial := certBefore.Leaf.SerialNumber.String()

	wait := make(chan struct{})
	mgr.triggerRenewal(domain, func(response response) {
		wait <- struct{}{}
	})
	// Trigger the renewal by calling GetCertificate
	_, err = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	t.Logf("Waiting for renewal to complete...")
	<-wait
	close(wait)

	// Poll the cache until the serial changes or timeout
	deadline := time.Now().Add(10 * time.Second)
	var newSerial string
	for time.Now().Before(deadline) {
		if cert, ok := mgr.cache.Get(domain); ok && cert != nil && cert.Leaf != nil {
			newSerial = cert.Leaf.SerialNumber.String()
			if newSerial != oldSerial {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if newSerial == "" || newSerial == oldSerial {
		t.Fatal("certificate was not renewed")
	}
	t.Logf("Successfully renewed! Old Serial: %s, New Serial: %s", oldSerial, newSerial)
}

// generateExpiringCert creates a self-signed certificate with the given expiration relative to now.
// expiresIn: positive = expires in the future, negative = expired in the past.
func generateExpiringCert(t *testing.T, domain string, expiresIn time.Duration) ([]byte, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Expiry Org"},
			CommonName:   domain,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(expiresIn),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM
}
