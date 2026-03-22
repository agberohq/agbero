package tlss

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
	"github.com/smallstep/truststore"
)

const (
	caCert = "ca-cert.pem"
	caKey  = "ca-key.pem"
)

type Local struct {
	mu        sync.Mutex
	logger    *ll.Logger
	CertDir   woos.Folder
	certHosts []string
	port      int
	mockMode  bool
}

func NewLocal(logger *ll.Logger, absoluteCertDir ...woos.Folder) *Local {
	certDir := woos.CertDir
	if len(absoluteCertDir) > 0 {
		certDir = absoluteCertDir[0]
	}

	mockMode := os.Getenv("AGBERO_TEST_MODE") == "1" || os.Getenv("PEBBLE_TEST") != ""

	return &Local{
		logger:   logger,
		CertDir:  certDir,
		mockMode: mockMode,
	}
}

func (ci *Local) SetStorageDir(dir woos.Folder) error {
	if !dir.IsSet() {
		return nil
	}
	if strings.HasPrefix(dir.String(), woos.HomeDirPrefix) {
		home, err := os.UserHomeDir()
		if err != nil {
			return errors.Newf("failed to get home directory: %w", err)
		}
		dir = woos.NewFolder(filepath.Join(home, dir.String()[2:]))
	}
	if err := dir.Ensure("", false); err != nil {
		return errors.Newf("failed to create storage directory: %w", err)
	}

	ci.CertDir = dir
	ci.logger.Fields("dir", dir).Info("storage directory")

	return nil
}

func (ci *Local) SetHosts(hosts []string, port int) {
	ci.certHosts = hosts
	ci.port = port
}

func (ci *Local) EnsureLocalhostCert() (certFile, keyFile string, err error) {
	prefix := ci.certPrefix()
	seen := make(map[string]bool)
	out := make([]string, 0, len(ci.certHosts)+8)
	for _, h := range ci.certHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	ci.certHosts = out

	defaults := []string{
		woos.Localhost,
		woos.LocalhostWildcardSAN,
		woos.IPv4LoopbackSAN,
		woos.IPv6LoopbackSAN,
	}
	defaults = append(defaults, getLocalLANIPs()...)
	for _, d := range defaults {
		if !seen[d] {
			ci.certHosts = append(ci.certHosts, d)
			seen[d] = true
		}
	}

	if err := ci.CertDir.Ensure(woos.Folder(""), true); err != nil {
		return "", "", errors.Newf("failed to ensure cert dir: %w", err)
	}

	certFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	if err := ci.validateCertificate(certFile, keyFile); err == nil {
		ci.logger.Fields("cert", certFile, "key", keyFile).Info("Using existing certificates")
		return certFile, keyFile, nil
	}

	ci.logger.Fields("hosts", ci.certHosts, "cert", certFile).Info("Generating localhost certificates with ECDSA")

	if !ci.caExists() {
		ci.logger.Info("CA root not found. Generating and installing local CA...")
		if err := ci.generateAndInstallCA(); err != nil {
			return "", "", err
		}
		ci.purgeStaleLeafCerts()
	}

	if _, _, err := ci.generateLeaf(certFile, keyFile); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

func (ci *Local) InstallCARootIfNeeded() error {
	_ = BootstrapEnv(ci.logger)

	if !ci.caExists() {
		ci.logger.Info("Generating and installing local CA root...")
		return ci.generateAndInstallCA()
	}

	ci.logger.Info("CA root already exists. Synchronizing with system trust stores...")
	return ci.installToTrustStore()
}

func (ci *Local) installToTrustStore() error {
	if ci.mockMode {
		ci.logger.Debug("mock mode: skipping system trust store installation")
		return nil
	}

	certPath := ci.caCertPath()
	var opts []truststore.Option
	opts = append(opts, truststore.WithJava())
	if ci.HasCertutil() {
		opts = append(opts, truststore.WithFirefox())
	}

	if err := truststore.InstallFile(certPath, opts...); err != nil {
		return errors.Newf("failed to install CA to system trust store: %w", err)
	}

	ci.logger.Fields("cert", certPath).Info("CA root synchronized to system trust stores")
	return nil
}

func (ci *Local) UninstallCARoot() error {
	if ci.mockMode {
		ci.logger.Debug("mock mode: skipping CA uninstall")
		return nil
	}

	caPath := ci.caCertPath()
	if caPath == "" {
		return errors.New("CA certificate path not set")
	}
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		ci.logger.Info("CA certificate not found, nothing to uninstall")
		return nil
	}

	var opts []truststore.Option
	opts = append(opts, truststore.WithJava())
	if ci.HasCertutil() {
		opts = append(opts, truststore.WithFirefox())
	}

	if err := truststore.UninstallFile(caPath, opts...); err != nil {
		return errors.Newf("failed to uninstall CA from system trust store: %w", err)
	}

	ci.logger.Fields("cert", caPath).Info("CA root uninstalled from system trust store")
	return nil
}

func (ci *Local) RemoveCA() {
	_ = os.Remove(ci.caCertPath())
	_ = os.Remove(ci.caKeyPath())
}

func (ci *Local) generateCAFilesOnly() error {
	if err := ci.CertDir.Ensure("", true); err != nil {
		return errors.Newf("failed to ensure cert dir: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Newf("generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return errors.Newf("generate serial: %w", err)
	}

	commonName := fmt.Sprintf("%s  Development CA", woos.Name)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{woos.Organization},
			OrganizationalUnit: []string{fmt.Sprintf("%s Development", woos.Name)},
			CommonName:         commonName,
			Country:            []string{"NG"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return errors.Newf("create CA cert: %w", err)
	}

	certPath := ci.caCertPath()
	keyPath := ci.caKeyPath()

	certOut, err := os.Create(certPath)
	if err != nil {
		return errors.Newf("create CA cert file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		return errors.Newf("encode CA cert: %w", err)
	}
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return errors.Newf("marshal CA key: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Newf("create CA key file: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		keyOut.Close()
		return errors.Newf("encode CA key: %w", err)
	}
	keyOut.Close()

	ci.logger.Fields("cert", keyPath, "cn", commonName, "algo", "ECDSA").Info("Successfully generated certificates")
	return nil
}

func (ci *Local) generateAndInstallCA() error {
	if err := ci.generateCAFilesOnly(); err != nil {
		return err
	}
	return ci.installToTrustStore()
}

func (ci *Local) generateLeaf(certFile, keyFile string) (string, string, error) {
	caCert, caKey, err := ci.loadCA()
	if err != nil {
		return "", "", errors.Newf("load CA: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", errors.Newf("generate leaf key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", errors.Newf("generate serial: %w", err)
	}

	var dnsNames []string
	var ipAddresses []net.IP
	for _, h := range ci.certHosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	commonName := fmt.Sprintf("%s  Development CA", woos.Name)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{woos.Organization},
			OrganizationalUnit: []string{fmt.Sprintf("%s Development", woos.Name)},
			CommonName:         commonName,
			Country:            []string{"NG"},
		},

		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return "", "", errors.Newf("create leaf cert: %w", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return "", "", errors.Newf("create leaf cert file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		return "", "", errors.Newf("encode leaf cert: %w", err)
	}
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", errors.Newf("marshal leaf key: %w", err)
	}
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", errors.Newf("create leaf key file: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		keyOut.Close()
		return "", "", errors.Newf("encode leaf key: %w", err)
	}
	keyOut.Close()

	if err := ci.validateCertificate(certFile, keyFile); err != nil {
		return "", "", errors.Newf("generated cert does not validate: %w", err)
	}

	ci.logger.Fields("cert", certFile, "cn", commonName, "algo", "ECDSA").Info("Successfully generated certificates")
	return certFile, keyFile, nil
}

func (ci *Local) loadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath := ci.caCertPath()
	keyPath := ci.caKeyPath()

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, errors.New("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid CA key PEM")
	}

	priv, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, errors.Newf("parse CA private key: %w", err)
	}

	caKey, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.Newf("expected ECDSA key, got %T", priv)
	}

	return caCert, caKey, nil
}

func (ci *Local) ListCertificates() ([]string, error) {
	names, err := ci.CertDir.ReadNames()
	if err != nil {
		return nil, errors.Newf("failed to read cert directory: %w", err)
	}
	var certs []string
	for _, name := range names {
		if strings.HasSuffix(name, woos.CertExtPEM) ||
			strings.HasSuffix(name, woos.CertExtCRT) ||
			strings.HasSuffix(name, woos.CertExtKEY) {
			certs = append(certs, name)
		}
	}
	return certs, nil
}

func (ci *Local) FindExistingCerts(prefix string, port int) (certFile, keyFile string, found bool) {
	originalPort := ci.port
	ci.port = port
	defer func() { ci.port = originalPort }()
	patterns := []struct {
		certPattern string
		keyPattern  string
	}{
		{fmt.Sprintf("%s.serve-cert.pem", prefix), fmt.Sprintf("%s.serve-key.pem", prefix)},
		{fmt.Sprintf("%s.pem", prefix), fmt.Sprintf("%s.key.pem", prefix)},
		{fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port)},
		{"localhost.pem", "localhost.key.pem"},
	}
	for _, pattern := range patterns {
		certPath := filepath.Join(ci.CertDir.Path(), pattern.certPattern)
		keyPath := filepath.Join(ci.CertDir.Path(), pattern.keyPattern)
		if err := ci.validateCertificate(certPath, keyPath); err == nil {
			return certPath, keyPath, true
		}
	}
	return "", "", false
}

func (ci *Local) validateCertificate(certFile, keyFile string) error {
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return errors.Newf("read cert: %w", err)
	}
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return errors.Newf("read key: %w", err)
	}
	pair, err := tls.X509KeyPair(certData, keyData)
	if err != nil || len(pair.Certificate) == 0 {
		if err == nil {
			err = woos.ErrNoCertificate
		}
		return errors.Newf("x509 key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.Newf("parse leaf: %w", err)
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return errors.Newf("%w: notAfter=%s", woos.ErrExpired, leaf.NotAfter)
	}
	if now.Before(leaf.NotBefore.Add(-2 * time.Minute)) {
		return errors.Newf("%s: notBefore=%s", woos.ErrNotYetValid, leaf.NotBefore)
	}

	ci.logger.Fields(
		"subject", leaf.Subject.String(),
		"dns", leaf.DNSNames,
		"ips", ipStrings(leaf.IPAddresses),
		"not_after", leaf.NotAfter,
		"algo", leaf.PublicKeyAlgorithm.String(),
	).Debug("tls: cert details")

	for _, raw := range ci.certHosts {
		target, ok := normalizeHostForVerify(raw)
		if !ok {
			continue
		}
		if strings.HasPrefix(target, "*.") {
			testHost := "example" + target[1:]
			if err := leaf.VerifyHostname(testHost); err != nil {
				return errors.Newf("verify wildcard via %q (from %q): %w", testHost, target, err)
			}
			continue
		}
		if err := leaf.VerifyHostname(target); err != nil {
			return errors.Newf("verify host %q: %w", target, err)
		}
	}
	return nil
}

func (ci *Local) certPrefix() string {
	if len(ci.certHosts) == 0 {
		return woos.Localhost
	}
	raw := strings.TrimSpace(ci.certHosts[0])
	if raw == "" {
		return woos.Localhost
	}
	host, ok := normalizeHostForVerify(raw)
	if !ok || host == "" {
		return woos.Localhost
	}
	if net.ParseIP(host) != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) > 0 && parts[0] != "" && parts[0] != "*" {
		return parts[0]
	}
	return woos.Localhost
}

func (ci *Local) purgeStaleLeafCerts() {
	names, err := ci.CertDir.ReadNames()
	if err != nil {
		return
	}
	removed := 0
	for _, n := range names {
		if strings.HasSuffix(n, "-cert.pem") || strings.HasSuffix(n, "-key.pem") {
			_ = os.Remove(filepath.Join(ci.CertDir.Path(), n))
			removed++
		}
	}
	if removed > 0 {
		ci.logger.Fields("removed", removed, "dir", ci.CertDir.Path()).Info("purged stale leaf certs after CA install")
	}
}

func (ci *Local) caExists() bool {
	m := ci.caCertPath()
	if m == "" {
		return false
	}
	_, err := os.Stat(m)
	return err == nil
}

func (ci *Local) caCertPath() string {
	if !ci.CertDir.IsSet() {
		return ""
	}
	return filepath.Join(ci.CertDir.Path(), caCert)
}

func (ci *Local) caKeyPath() string {
	if !ci.CertDir.IsSet() {
		return ""
	}
	return filepath.Join(ci.CertDir.Path(), caKey)
}

func (ci *Local) SetMockMode(mock bool) {
	ci.mockMode = mock
	if mock {
		ci.logger.Debug("local: mock mode enabled, CA installation disabled")
	}
}

func (ci *Local) HasCertutil() bool {
	return hasCertutil()
}

func (ci *Local) EnsureForHost(host string, port int) (certFile, keyFile string, err error) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.certHosts = []string{host}
	ci.port = port
	return ci.EnsureLocalhostCert()
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func normalizeHostForVerify(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, woos.IPv6BracketOpen) && strings.Contains(s, woos.IPv6BracketClose) {
		if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
			return h, true
		}
		s = strings.TrimPrefix(s, woos.IPv6BracketOpen)
		s = strings.TrimSuffix(s, woos.IPv6BracketClose)
		return s, s != ""
	}
	if strings.Count(s, woos.Colon) == 1 {
		if h, p, err := net.SplitHostPort(s); err == nil && h != "" && p != "" {
			return h, true
		}
	}
	return s, true
}

func getLocalLANIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	return ips
}

func hasCertutil() bool {
	paths := certutilPaths()
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func certutilPaths() []string {
	switch runtime.GOOS {
	case woos.Darwin:
		return []string{
			woos.NSSPathDarwinHomebrewBin,
			woos.NSSPathDarwinUsrLocalBin,
			woos.NSSPathDarwinMozillaNSS,
			woos.NSSPathDarwinMozillaNSSAlt,
		}
	case woos.Linux:
		return []string{
			woos.NSSPathLinuxUsrBin,
			woos.NSSPathLinuxUsrLocalBin,
			woos.NSSPathLinuxSnapBin,
		}
	default:
		return nil
	}
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	// Try PKCS#8 first (RFC 5958, modern standard)
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	// Fallback to SEC1 for ECDSA (legacy compatibility)
	return x509.ParseECPrivateKey(der)
}
