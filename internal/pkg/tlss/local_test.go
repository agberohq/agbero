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

// Test helper to create a properly mocked Local instance
func setupLocalTest(t *testing.T, tmpDir string) *Local {
	t.Helper()
	logger := ll.New("test").Disable()
	ci := NewLocal(logger)
	ci.CertDir = woos.NewFolder(tmpDir)
	ci.SetMockMode(true) // Enable mock mode - NO SYSTEM INSTALLATION
	return ci
}

// Helper to write RSA self-signed cert for testing
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

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
}

// Helper to write ECDSA self-signed cert for testing
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

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
}

// Helper to write CA cert for testing
func writeCACert(t *testing.T, dir string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}), 0644)

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ECDSA key: %v", err)
	}
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}), 0600)
}

func TestCertLocal_validateCertificate_HostMatch(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

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

func TestCertLocal_validateCertificate_StripsPortAndBracketedIPv6(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

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

func TestCertLocal_validateCertificate_Wildcard_VerifiedByConcreteSubdomain(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

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

func TestCertLocal_findExistingCerts_UsesOnlyMatchingCert(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

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

func TestCertLocal_certPrefix_NormalizesPortsAndIPv6(t *testing.T) {
	ci := setupLocalTest(t, t.TempDir())

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

func TestCertLocal_EnsureLocalhostCert_ReusesValidECDSA(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	ci.SetHosts([]string{"localhost"}, 443)
	writeCACert(t, tmp) // Create CA files

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

func TestCertLocal_EnsureLocalhostCert_GeneratesNewWhenMissing(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	ci.SetHosts([]string{"test.local"}, 8443)
	writeCACert(t, tmp) // Create CA files

	gotCert, gotKey, err := ci.EnsureLocalhostCert()
	if err != nil {
		t.Fatalf("EnsureLocalhostCert failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(gotCert); os.IsNotExist(err) {
		t.Error("cert file was not created")
	}
	if _, err := os.Stat(gotKey); os.IsNotExist(err) {
		t.Error("key file was not created")
	}

	// Verify cert is valid
	pair, err := tls.LoadX509KeyPair(gotCert, gotKey)
	if err != nil {
		t.Fatalf("failed to load generated keypair: %v", err)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated cert: %v", err)
	}

	// Check SANs include our hosts
	found := false
	for _, dns := range leaf.DNSNames {
		if dns == "test.local" {
			found = true
			break
		}
	}
	if !found {
		t.Error("generated cert missing expected DNS name 'test.local'")
	}
}

func TestCertLocal_InstallCARootIfNeeded_MockMode(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	// Initially CA should not exist
	if ci.caExists() {
		t.Error("CA should not exist initially")
	}

	// Install in mock mode
	err := ci.InstallCARootIfNeeded()
	if err != nil {
		t.Fatalf("InstallCARootIfNeeded failed: %v", err)
	}

	// CA files should exist now
	if !ci.caExists() {
		t.Error("CA should exist after installation")
	}

	// Verify CA cert file exists and is valid
	caPath := ci.caCertPath()
	certData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	if !caCert.IsCA {
		t.Error("CA cert should have IsCA=true")
	}

	// Second call should be idempotent
	err = ci.InstallCARootIfNeeded()
	if err != nil {
		t.Fatalf("second InstallCARootIfNeeded failed: %v", err)
	}
}

func TestCertLocal_UninstallCARoot_MockMode(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	// First install CA
	err := ci.InstallCARootIfNeeded()
	if err != nil {
		t.Fatalf("InstallCARootIfNeeded failed: %v", err)
	}

	// Verify CA exists
	if !ci.caExists() {
		t.Error("CA should exist after installation")
	}

	// Uninstall in mock mode
	err = ci.UninstallCARoot()
	if err != nil {
		t.Fatalf("UninstallCARoot failed: %v", err)
	}

	// Files should still exist (mock mode doesn't delete files)
	if !ci.caExists() {
		t.Error("CA files should still exist after mock uninstall")
	}
}

func TestCertLocal_generateCAFilesOnly(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	err := ci.generateCAFilesOnly()
	if err != nil {
		t.Fatalf("generateCAFilesOnly failed: %v", err)
	}

	// Verify CA files were created
	certPath := ci.caCertPath()
	keyPath := ci.caKeyPath()

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("CA cert file not created")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("CA key file not created")
	}

	// Validate CA cert
	certData, err := os.ReadFile(certPath)
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
}

func TestCertLocal_loadCA(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	// Generate CA files first
	err := ci.generateCAFilesOnly()
	if err != nil {
		t.Fatalf("generateCAFilesOnly failed: %v", err)
	}

	// Load CA
	caCert, caKey, err := ci.loadCA()
	if err != nil {
		t.Fatalf("loadCA failed: %v", err)
	}

	if caCert == nil {
		t.Error("CA cert is nil")
	}
	if caKey == nil {
		t.Error("CA key is nil")
	}
	if !caCert.IsCA {
		t.Error("loaded CA cert should have IsCA=true")
	}
}

func TestCertLocal_purgeStaleLeafCerts(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	// Create some stale leaf certs
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

func TestCertLocal_ListCertificates(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	// Create some cert files
	certPath := filepath.Join(tmp, "test-cert.pem")
	keyPath := filepath.Join(tmp, "test-key.pem")
	writeSelfSignedCert(t, certPath, keyPath, []string{"localhost"})

	// Create CA files (should also be listed)
	ci.generateCAFilesOnly()

	certs, err := ci.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates failed: %v", err)
	}

	var foundCert, foundKey, foundCA bool
	for _, c := range certs {
		switch c {
		case "test-cert.pem":
			foundCert = true
		case "test-key.pem":
			foundKey = true
		case "ca-cert.pem":
			foundCA = true
		}
	}

	if !foundCert {
		t.Error("expected test-cert.pem in list")
	}
	if !foundKey {
		t.Error("expected test-key.pem in list")
	}
	if !foundCA {
		t.Error("expected ca-cert.pem in list")
	}
}

func TestCertLocal_SetStorageDir(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	newDir := woos.NewFolder(filepath.Join(tmp, "new-certs"))
	err := ci.SetStorageDir(newDir)
	if err != nil {
		t.Fatalf("SetStorageDir failed: %v", err)
	}

	if ci.CertDir.Path() != newDir.Path() {
		t.Errorf("CertDir not updated: got %s, want %s", ci.CertDir.Path(), newDir.Path())
	}

	// Directory should have been created
	if _, err := os.Stat(newDir.Path()); os.IsNotExist(err) {
		t.Error("storage directory was not created")
	}
}

func TestCertLocal_SetStorageDir_WithHomePrefix(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	// Mock home directory
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmp)
	defer os.Setenv("HOME", oldHome)

	// Test with ~/ prefix
	homeDir := woos.NewFolder("~/test-certs")
	err := ci.SetStorageDir(homeDir)
	if err != nil {
		t.Fatalf("SetStorageDir with home prefix failed: %v", err)
	}

	expected := filepath.Join(tmp, "test-certs")
	if ci.CertDir.Path() != expected {
		t.Errorf("CertDir not expanded correctly: got %s, want %s", ci.CertDir.Path(), expected)
	}
}

func TestCertLocal_validateCertificate_Expired(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	certPath := filepath.Join(tmp, "expired-cert.pem")
	keyPath := filepath.Join(tmp, "expired-key.pem")

	// Create expired cert
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600)

	ci.SetHosts([]string{"localhost"}, 443)
	err := ci.validateCertificate(certPath, keyPath)
	if err == nil {
		t.Error("expected validation to fail for expired cert")
	}
}

func TestCertLocal_validateCertificate_NotYetValid(t *testing.T) {
	tmp := t.TempDir()
	ci := setupLocalTest(t, tmp)

	certPath := filepath.Join(tmp, "future-cert.pem")
	keyPath := filepath.Join(tmp, "future-key.pem")

	// Create cert valid in the future
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600)

	ci.SetHosts([]string{"localhost"}, 443)
	err := ci.validateCertificate(certPath, keyPath)
	if err == nil {
		t.Error("expected validation to fail for not-yet-valid cert")
	}
}

func TestGetLocalLANIPs(t *testing.T) {
	ips := getLocalLANIPs()
	// Just verify it runs without panic and returns something sensible
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			t.Errorf("getLocalLANIPs returned invalid IP: %s", ip)
		}
	}
}

func TestNormalizeHostForVerify(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		ok       bool
	}{
		{"localhost", "localhost", true},
		{"localhost:443", "localhost", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"127.0.0.1:8443", "127.0.0.1", true},
		{"[::1]", "::1", true},
		{"[::1]:443", "::1", true},
		{"", "", false},
		{"   ", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := normalizeHostForVerify(tt.input)
			if ok != tt.ok {
				t.Errorf("ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.expected {
				t.Errorf("got = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	// Test EC private key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := parsePrivateKey(ecBytes)
	if err != nil {
		t.Fatalf("failed to parse EC key: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Error("parsed EC key is not *ecdsa.PrivateKey")
	}

	// Test PKCS8 private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err = parsePrivateKey(pkcs8Bytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS8 key: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Error("parsed PKCS8 key is not *rsa.PrivateKey")
	}
}
