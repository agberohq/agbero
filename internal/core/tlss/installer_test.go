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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/olekukonko/ll"
)

const useMock = true

func skipIfRealInstall(t *testing.T) {
	if !useMock {
		if os.Getenv("CI") == "true" || os.Geteuid() != 0 {
			t.Skip("Real install requires sudo; set useMock=true or run with sudo")
		}
	}
}

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
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, raw := range hosts {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		host, ok := normalizeHostForVerify(h)
		if !ok || host == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			tpl.DNSNames = append(tpl.DNSNames, host)
			continue
		}
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

func writeECDSASelfSignedCert(t *testing.T, certPath, keyPath string, hosts []string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ecdsa-cert"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, raw := range hosts {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		host, ok := normalizeHostForVerify(h)
		if !ok || host == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			tpl.DNSNames = append(tpl.DNSNames, host)
			continue
		}
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
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
}

func TestCertInstaller_validateCertificate_HostMatch(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	certPath := filepath.Join(tmp, "localhost-443-cert.pem")
	keyPath := filepath.Join(tmp, "localhost-443-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"localhost", "127.0.0.1"})
	ci.SetHosts([]string{"localhost"}, 443)
	if err := ci.validateCertificate(certPath, keyPath); err != nil {
		t.Fatalf("expected cert to validate for localhost, got: %v", err)
	}
	ci.SetHosts([]string{"127.0.0.1"}, 443)
	if err := ci.validateCertificate(certPath, keyPath); err != nil {
		t.Fatalf("expected cert to validate for 127.0.0.1, got: %v", err)
	}
	ci.SetHosts([]string{"example.com"}, 443)
	if err := ci.validateCertificate(certPath, keyPath); err == nil {
		t.Fatal("expected cert NOT to validate for example.com")
	}
}

func TestCertInstaller_validateCertificate_StripsPortAndBracketedIPv6(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	certPath := filepath.Join(tmp, "mixed-443-cert.pem")
	keyPath := filepath.Join(tmp, "mixed-443-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"localhost", "127.0.0.1", "::1"})
	ci.SetHosts([]string{"localhost:443", "127.0.0.1:443", "[::1]:443"}, 443)
	if err := ci.validateCertificate(certPath, keyPath); err != nil {
		t.Fatalf("expected cert to validate for host:port forms, got: %v", err)
	}
	ci.SetHosts([]string{"::1"}, 443)
	if err := ci.validateCertificate(certPath, keyPath); err != nil {
		t.Fatalf("expected cert to validate for raw IPv6 ::1, got: %v", err)
	}
}

func TestCertInstaller_validateCertificate_Wildcard_VerifiedByConcreteSubdomain(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	certPath := filepath.Join(tmp, "wild-443-cert.pem")
	keyPath := filepath.Join(tmp, "wild-443-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"*.localhost"})
	ci.SetHosts([]string{"*.localhost"}, 443)
	if err := ci.validateCertificate(certPath, keyPath); err != nil {
		t.Fatalf("expected wildcard cert to validate, got: %v", err)
	}
	ci.SetHosts([]string{"*.agbero"}, 443)
	if err := ci.validateCertificate(certPath, keyPath); err == nil {
		t.Fatal("expected wildcard cert NOT to validate for *.agbero")
	}
}

func TestCertInstaller_findExistingCerts_UsesOnlyMatchingCert(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	hosts := []string{"app.localhost"}
	port := 443
	ci.SetHosts(hosts, port)
	certPath := filepath.Join(tmp, "app-443-cert.pem")
	keyPath := filepath.Join(tmp, "app-443-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"other.localhost"})
	_, _, found := ci.FindExistingCerts("app", port)
	if found {
		t.Fatal("expected NOT to find cert because SAN doesn't match app.localhost")
	}
	_ = os.Remove(certPath)
	_ = os.Remove(keyPath)
	writeSelfSignedCert(t, certPath, keyPath, []string{"app.localhost"})
	_, _, found = ci.FindExistingCerts("app", port)
	if !found {
		t.Fatal("expected to find cert for app.localhost")
	}
}

func TestCertInstaller_certPrefix_NormalizesPortsAndIPv6(t *testing.T) {
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.SetHosts([]string{"app.localhost:443"}, 443)
	if got := ci.certPrefix(); got != "app" {
		t.Fatalf("expected prefix 'app', got %q", got)
	}
	ci.SetHosts([]string{"127.0.0.1:8443"}, 8443)
	if got := ci.certPrefix(); got != "127.0.0.1" {
		t.Fatalf("expected prefix '127.0.0.1', got %q", got)
	}
	ci.SetHosts([]string{"[::1]:443"}, 443)
	if got := ci.certPrefix(); got != "::1" {
		t.Fatalf("expected prefix '::1', got %q", got)
	}
	ci.SetHosts([]string{"::1"}, 443)
	if got := ci.certPrefix(); got != "::1" {
		t.Fatalf("expected prefix '::1', got %q", got)
	}
}

func TestCertInstaller_EnsureLocalhostCert_ReusesValidECDSA(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	ci.SetHosts([]string{"localhost"}, 443)
	ci.mockMode = true

	certPath := filepath.Join(tmp, "localhost-443-cert.pem")
	keyPath := filepath.Join(tmp, "localhost-443-key.pem")
	writeECDSASelfSignedCert(t, certPath, keyPath, []string{"localhost", "127.0.0.1", "::1"})

	gotCert, gotKey, err := ci.EnsureLocalhostCert()
	if err != nil {
		t.Fatalf("EnsureLocalhostCert failed: %v", err)
	}
	if gotCert != certPath {
		t.Errorf("cert path mismatch: got %q, want %q", gotCert, certPath)
	}
	if gotKey != keyPath {
		t.Errorf("key path mismatch: got %q, want %q", gotKey, keyPath)
	}
	pair, _ := tls.LoadX509KeyPair(gotCert, gotKey)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA cert, got %v", leaf.PublicKeyAlgorithm)
	}
}

func TestCertInstaller_InstallAndUninstallCARoot(t *testing.T) {
	if useMock {
		t.Skip("Skipping real install test; useMock=true")
	}
	skipIfRealInstall(t)
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	caPath := ci.caCertPath()
	if caPath == "" {
		t.Fatal("CA path should not be empty")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Test CA"}, CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certOut, err := os.Create(caPath)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		t.Fatalf("encode CA cert: %v", err)
	}
	certOut.Close()
	if !ci.caExists() {
		t.Error("caExists should return true after creating CA file")
	}
	err = ci.UninstallCARoot()
	if err != nil {
		t.Logf("UninstallCARoot error (expected in CI without sudo): %v", err)
	}
	_ = os.Remove(caPath)
	if ci.caExists() {
		t.Error("caExists should return false after removing CA file")
	}
}

func TestCertInstaller_generateAndInstallCA(t *testing.T) {
	if useMock {
		t.Skip("Skipping real install test; useMock=true")
	}
	skipIfRealInstall(t)
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	caPath := ci.caCertPath()
	if caPath == "" {
		t.Fatal("CA path should not be empty")
	}
	err := ci.generateAndInstallCA()
	if err != nil {
		t.Logf("generateAndInstallCA error (expected in CI without truststore perms): %v", err)
	}
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		t.Skip("CA cert not created (skipping - requires truststore permissions)")
	}
	certData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if !caCert.IsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if caCert.Subject.CommonName != "Agbero Development CA" {
		t.Errorf("unexpected CA subject: %q", caCert.Subject.CommonName)
	}
}

func TestCertInstaller_purgeStaleLeafCerts(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	certPath := filepath.Join(tmp, "stale-443-cert.pem")
	keyPath := filepath.Join(tmp, "stale-443-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"localhost"})
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatal("cert file should exist before purge")
	}
	ci.purgeStaleLeafCerts()
	if _, err := os.Stat(certPath); err == nil {
		t.Error("stale cert should have been removed")
	}
}

func TestCertInstaller_ListCertificates(t *testing.T) {
	tmp := t.TempDir()
	logger := ll.New("test").Disable()
	ci := NewInstaller(logger)
	ci.CertDir = woos.NewFolder(tmp)
	certPath := filepath.Join(tmp, "test-cert.pem")
	keyPath := filepath.Join(tmp, "test-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"localhost"})
	certs, err := ci.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates failed: %v", err)
	}
	var foundCert, foundKey bool
	for _, c := range certs {
		if c == "test-cert.pem" {
			foundCert = true
		}
		if c == "test-key.pem" {
			foundKey = true
		}
	}
	if !foundCert {
		t.Error("expected test-cert.pem in list")
	}
	if !foundKey {
		t.Error("expected test-key.pem in list")
	}
}
