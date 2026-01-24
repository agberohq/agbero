package tlss

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

func writeSelfSignedCert(t *testing.T, certPath, keyPath string, hosts []string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		host := h
		if ip := net.ParseIP(host); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, host)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	defer keyOut.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
}

func TestCertInstaller_validateCertificate_HostMatch(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test")

	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)

	certPath := filepath.Join(tmp, "localhost-443-cert.pem")
	keyPath := filepath.Join(tmp, "localhost-443-key.pem")

	writeSelfSignedCert(t, certPath, keyPath, []string{"localhost", "127.0.0.1"})

	if !ci.validateCertificate(certPath, keyPath, []string{"localhost"}) {
		t.Fatal("expected cert to validate for localhost")
	}
	if !ci.validateCertificate(certPath, keyPath, []string{"127.0.0.1"}) {
		t.Fatal("expected cert to validate for 127.0.0.1")
	}
	if ci.validateCertificate(certPath, keyPath, []string{"example.com"}) {
		t.Fatal("expected cert NOT to validate for example.com")
	}
}

func TestCertInstaller_findExistingCerts_UsesOnlyMatchingCert(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test")

	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	ci.SetHosts([]string{"app.localhost"}, 443)

	// Create cert for DIFFERENT host but with a matching filename pattern
	certPath := filepath.Join(tmp, "app-443-cert.pem")
	keyPath := filepath.Join(tmp, "app-443-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"other.localhost"})

	_, _, found := ci.findExistingCerts("app", 443)
	if found {
		t.Fatal("expected NOT to find cert because SAN doesn't match app.localhost")
	}

	// Now create correct cert
	os.Remove(certPath)
	os.Remove(keyPath)
	writeSelfSignedCert(t, certPath, keyPath, []string{"app.localhost"})

	_, _, found = ci.findExistingCerts("app", 443)
	if !found {
		t.Fatal("expected to find cert for app.localhost")
	}
}

func TestCertInstaller_certPrefix_StripsPort(t *testing.T) {
	logger := ll.New("test")
	ci := NewInstaller(logger)

	ci.SetHosts([]string{"app.localhost:443"}, 443)
	if got := ci.certPrefix(); got != "app" {
		t.Fatalf("expected prefix 'app', got %q", got)
	}

	ci.SetHosts([]string{"127.0.0.1:8443"}, 8443)
	if got := ci.certPrefix(); got != "127.0.0.1" {
		t.Fatalf("expected prefix '127.0.0.1', got %q", got)
	}
}
