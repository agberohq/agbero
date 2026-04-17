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
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/olekukonko/ll"
)

func writeSelfSignedCert(t *testing.T, store tlsstore.Store, domain string, hosts []string) {
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := store.Save(tlsstore.IssuerLocal, domain, certPEM, keyPEM); err != nil {
		t.Fatalf("save to store: %v", err)
	}
}

func writeECDSASelfSignedCert(t *testing.T, store tlsstore.Store, domain string, hosts []string) {
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := store.Save(tlsstore.IssuerLocal, domain, certPEM, keyPEM); err != nil {
		t.Fatalf("save to store: %v", err)
	}
}

func writeCACert(t *testing.T, store tlsstore.Store) {
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ECDSA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := store.Save(tlsstore.IssuerCA, "ca", certPEM, keyPEM); err != nil {
		t.Fatalf("save CA to store: %v", err)
	}
}

func TestCertLocal_validateCertificate_HostMatch(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	domain := "localhost-443"
	writeSelfSignedCert(t, store, domain, []string{"localhost", "127.0.0.1"})
	ci.SetHosts([]string{"localhost"}, 443)
	certPEM, keyPEM, err := store.Load(domain)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err != nil {
		t.Fatalf("expected cert to validate for localhost, got: %v", err)
	}
	ci.SetHosts([]string{"127.0.0.1"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err != nil {
		t.Fatalf("expected cert to validate for 127.0.0.1, got: %v", err)
	}
	ci.SetHosts([]string{"example.com"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err == nil {
		t.Fatal("expected cert NOT to validate for example.com")
	}
}

func TestCertLocal_validateCertificate_StripsPortAndBracketedIPv6(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	domain := "mixed-443"
	writeSelfSignedCert(t, store, domain, []string{"localhost", "127.0.0.1", "::1"})
	certPEM, keyPEM, err := store.Load(domain)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	ci.SetHosts([]string{"localhost:443", "127.0.0.1:443", "[::1]:443"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err != nil {
		t.Fatalf("expected cert to validate for host:port forms, got: %v", err)
	}
	ci.SetHosts([]string{"::1"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err != nil {
		t.Fatalf("expected cert to validate for raw IPv6 ::1, got: %v", err)
	}
}

func TestCertLocal_validateCertificate_Wildcard_VerifiedByConcreteSubdomain(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	domain := "wild-443"
	writeSelfSignedCert(t, store, domain, []string{"*.localhost"})
	certPEM, keyPEM, err := store.Load(domain)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	ci.SetHosts([]string{"*.localhost"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err != nil {
		t.Fatalf("expected wildcard cert to validate, got: %v", err)
	}
	ci.SetHosts([]string{"*.agbero"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err == nil {
		t.Fatal("expected wildcard cert NOT to validate for *.agbero")
	}
}

func TestCertLocal_certPrefix_NormalizesPortsAndIPv6(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
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
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	ci.SetHosts([]string{"localhost"}, 443)
	writeCACert(t, store)
	domain := "localhost-443"
	writeECDSASelfSignedCert(t, store, domain, []string{"localhost", "127.0.0.1", "::1"})
	gotCertDomain, gotKeyDomain, err := ci.EnsureLocalhostCert()
	if err != nil {
		t.Fatalf("EnsureLocalhostCert failed: %v", err)
	}
	expectedDomain := ci.certPrefix()
	if gotCertDomain != expectedDomain || gotKeyDomain != expectedDomain {
		t.Errorf("expected domain %q, got cert=%q key=%q", expectedDomain, gotCertDomain, gotKeyDomain)
	}
	certPEM, keyPEM, err := store.Load(expectedDomain)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	pair, _ := tls.X509KeyPair(certPEM, keyPEM)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA cert, got %v", leaf.PublicKeyAlgorithm)
	}
}

func TestCertLocal_EnsureLocalhostCert_GeneratesNewWhenMissing(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	ci.SetHosts([]string{"test.local"}, 8443)
	writeCACert(t, store)
	domain, _, err := ci.EnsureLocalhostCert()
	if err != nil {
		t.Fatalf("EnsureLocalhostCert failed: %v", err)
	}
	certPEM, keyPEM, err := store.Load(domain)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load generated keypair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated cert: %v", err)
	}
	found := slices.Contains(leaf.DNSNames, "test.local")
	if !found {
		t.Error("generated cert missing expected DNS name 'test.local'")
	}
}

func TestCertLocal_InstallCARootIfNeeded_MockMode(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	if ci.caExists() {
		t.Error("CA should not exist initially")
	}
	err := ci.InstallCARootIfNeeded()
	if err != nil {
		t.Fatalf("InstallCARootIfNeeded failed: %v", err)
	}
	if !ci.caExists() {
		t.Error("CA should exist after installation")
	}
	certPEM, _, err := store.Load("ca")
	if err != nil {
		t.Fatalf("failed to load CA cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
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
	err = ci.InstallCARootIfNeeded()
	if err != nil {
		t.Fatalf("second InstallCARootIfNeeded failed: %v", err)
	}
}

func TestCertLocal_UninstallCARoot_MockMode(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	err := ci.InstallCARootIfNeeded()
	if err != nil {
		t.Fatalf("InstallCARootIfNeeded failed: %v", err)
	}
	if !ci.caExists() {
		t.Error("CA should exist after installation")
	}
	err = ci.UninstallCARoot()
	if err != nil {
		t.Fatalf("UninstallCARoot failed: %v", err)
	}
	if !ci.caExists() {
		t.Error("CA should still exist in storage after mock uninstall")
	}
}

func TestCertLocal_LoadCA(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	err := ci.generateCAFilesOnly()
	if err != nil {
		t.Fatalf("generateCAFilesOnly failed: %v", err)
	}
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

func TestCertLocal_ListCertificates(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	writeSelfSignedCert(t, store, "test-cert", []string{"localhost"})
	writeCACert(t, store)
	certs, err := ci.ListCertificates()
	if err != nil {
		t.Fatalf("ListCertificates failed: %v", err)
	}
	var foundCert bool
	for _, c := range certs {
		if c == "test-cert" {
			foundCert = true
		}
	}
	if !foundCert {
		t.Error("expected test-cert in list")
	}
}

func TestCertLocal_validateCertificate_Expired(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := store.Save(tlsstore.IssuerLocal, "expired", certPEM, keyPEM); err != nil {
		t.Fatalf("save to store: %v", err)
	}
	ci.SetHosts([]string{"localhost"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err == nil {
		t.Error("expected validation to fail for expired cert")
	}
}

func TestCertLocal_validateCertificate_NotYetValid(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := store.Save(tlsstore.IssuerLocal, "future", certPEM, keyPEM); err != nil {
		t.Fatalf("save to store: %v", err)
	}
	ci.SetHosts([]string{"localhost"}, 443)
	if err := ci.validateCertificateBytes(certPEM, keyPEM); err == nil {
		t.Error("expected validation to fail for not-yet-valid cert")
	}
}

func TestGetLocalLANIPs(t *testing.T) {
	ips := getLocalLANIPs()
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

func TestCertLocal_HasCertutil(t *testing.T) {
	store := tlsstore.NewMemory()
	ci := NewLocal(ll.New("test").Disable(), store)
	ci.SetMockMode(true)
	result := ci.HasCertutil()
	if result != true && result != false {
		t.Errorf("HasCertutil returned unexpected value")
	}
}

func TestCertutilPaths(t *testing.T) {
	paths := certutilPaths()
	switch runtime.GOOS {
	case def.Darwin:
		if len(paths) == 0 {
			t.Error("certutilPaths should return paths for Darwin")
		}
	case def.Linux:
		if len(paths) == 0 {
			t.Error("certutilPaths should return paths for Linux")
		}
	default:
		if len(paths) != 0 {
			t.Errorf("certutilPaths should return nil for unsupported OS %s, got: %v", runtime.GOOS, paths)
		}
	}
}
