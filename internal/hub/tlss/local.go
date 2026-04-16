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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
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
	store     tlsstore.Store
	certHosts []string
	port      int
	mockMode  bool
}

// NewLocal creates a Local instance with the required storage backend.
func NewLocal(logger *ll.Logger, store tlsstore.Store) *Local {
	if store == nil {
		panic("tlss: Local requires a storage backend")
	}
	mockMode := os.Getenv("AGBERO_TEST_MODE") == "1" || os.Getenv("PEBBLE_TEST") != ""

	return &Local{
		logger:   logger,
		store:    store,
		mockMode: mockMode,
	}
}

// SetHosts configures the hosts and port for certificate generation.
func (ci *Local) SetHosts(hosts []string, port int) {
	ci.certHosts = hosts
	ci.port = port
}

// EnsureLocalhostCert ensures a local development certificate exists for the configured hosts.
// Returns the domain identifier (for storage lookup) on success.
func (ci *Local) EnsureLocalhostCert() (string, string, error) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	return ci.ensureLocalhostCertUnlocked()
}

// InstallCARootIfNeeded generates a CA root if missing and installs it to system trust stores.
func (ci *Local) InstallCARootIfNeeded() error {
	_ = BootstrapEnv(ci.logger)

	if !ci.caExists() {
		// No CA in storage — generate fresh and install to system trust store.
		ci.logger.Info("generating and installing local CA root")
		return ci.generateAndInstallCA()
	}

	if ci.caExistsInSystem() {
		// CA is in storage and already trusted by the OS — nothing to do.
		ci.logger.Info("CA root already exists and is trusted by system")
		return nil
	}

	// CA is in storage but not in the system trust store (e.g. OS upgrade,
	// new user profile, or mock mode). Sync to trust store.
	ci.logger.Info("CA root exists in storage, synchronizing with system trust stores")
	return ci.installToTrustStore()
}

func (ci *Local) UninstallCARoot() error {
	if ci.mockMode {
		ci.logger.Debug("mock mode: skipping CA uninstall")
		return nil
	}

	certPEM, _, err := ci.store.Load("ca")
	if err != nil {
		ci.logger.Info("CA certificate not found in store, nothing to uninstall")
		return nil
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("invalid CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Newf("failed to parse CA certificate: %w", err)
	}

	var opts []truststore.Option
	opts = append(opts, truststore.WithJava())
	if ci.HasCertutil() {
		opts = append(opts, truststore.WithFirefox())
	}

	if err := truststore.Uninstall(caCert, opts...); err != nil {
		return errors.Newf("failed to uninstall CA from system trust store: %w", err)
	}

	ci.logger.Info("CA root uninstalled from system trust store")
	return nil
}

// RemoveCA deletes the CA certificate from storage.
func (ci *Local) RemoveCA() {
	_ = ci.store.Delete("ca")
}

// SetMockMode enables or disables mock mode (skips system trust store operations).
func (ci *Local) SetMockMode(mock bool) {
	ci.mockMode = mock
	if mock {
		ci.logger.Debug("local: mock mode enabled, CA installation disabled")
	}
}

// HasCertutil reports whether certutil is available on the system.
func (ci *Local) HasCertutil() bool {
	return hasCertutil()
}

// EnsureForHost ensures a certificate exists for a specific host and port.
func (ci *Local) EnsureForHost(host string, port int) (certFile, keyFile string, err error) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.certHosts = []string{host}
	ci.port = port
	return ci.ensureLocalhostCertUnlocked()
}

func (ci *Local) ListCertificates() ([]string, error) {
	all, err := ci.store.List()
	if err != nil {
		return nil, err
	}

	var certs []string
	for _, name := range all {
		certs = append(certs, name)
	}
	return certs, nil
}

// caExists reports whether a valid CA certificate is present in the store.
// This is the storage check — it answers "do we have a CA saved?"
// It does NOT check whether the CA is trusted by the OS.
func (ci *Local) caExists() bool {
	certPEM, _, err := ci.store.Load("ca")
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		return false
	}
	return cert.IsCA
}

// caExistsInSystem reports whether the CA is in the store AND trusted by the
// OS system certificate pool. Used at runtime (non-mock) to decide whether to
// re-run trust store installation — e.g. after an OS upgrade wiped the pool.
//
// Returns true if the system pool is unavailable (sandboxed environments).
// Always returns false in mock mode since installToTrustStore is skipped.
func (ci *Local) caExistsInSystem() bool {
	if !ci.caExists() {
		return false
	}
	if ci.mockMode {
		return false
	}
	certPEM, _, err := ci.store.Load("ca")
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, parseErr := x509.ParseCertificate(block.Bytes)
	if parseErr != nil {
		return false
	}
	pool, poolErr := x509.SystemCertPool()
	if poolErr != nil {
		return true // pool unavailable — assume trusted if stored
	}
	opts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: cert.NotBefore.Add(time.Second),
	}
	_, verifyErr := cert.Verify(opts)
	return verifyErr == nil
}

// CAExists is the public API for checking CA presence in storage.
func (ci *Local) CAExists() bool {
	return ci.caExists()
}

// CAExistsInSystem is the public API for checking CA trust store presence.
func (ci *Local) CAExistsInSystem() bool {
	return ci.caExistsInSystem()
}

func (ci *Local) generateAndInstallCA() error {
	if err := ci.generateCAFilesOnly(); err != nil {
		return err
	}
	return ci.installToTrustStore()
}

// generateCAFilesOnly creates a new CA certificate and saves it to storage.
func (ci *Local) generateCAFilesOnly() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Newf("generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return errors.Newf("generate serial: %w", err)
	}

	commonName := fmt.Sprintf("%s Development CA", woos.Name)
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

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return errors.Newf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := ci.store.Save(tlsstore.IssuerCA, "ca", certPEM, keyPEM); err != nil {
		return errors.Newf("failed to save CA to store: %w", err)
	}

	ci.logger.Fields("cn", commonName, "algo", "ECDSA").Info("successfully generated CA certificate")
	return nil
}

// installToTrustStore installs the CA certificate to system trust stores.
func (ci *Local) installToTrustStore() error {
	if ci.mockMode {
		ci.logger.Debug("mock mode: skipping system trust store installation")
		return nil
	}

	certPEM, _, err := ci.store.Load("ca")
	if err != nil {
		return errors.Newf("failed to load CA cert from store: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("invalid CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Newf("failed to parse CA certificate: %w", err)
	}

	var opts []truststore.Option
	opts = append(opts, truststore.WithJava())
	if ci.HasCertutil() {
		opts = append(opts, truststore.WithFirefox())
	}

	if err := truststore.Install(caCert, opts...); err != nil {
		return errors.Newf("failed to install CA to system trust store: %w", err)
	}

	ci.logger.Info("CA root synchronized to system trust stores")
	return nil
}

// generateLeaf creates a leaf certificate signed by the CA and saves it to storage.
func (ci *Local) generateLeaf(domain string) error {
	caCert, caKey, err := ci.loadCA()
	if err != nil {
		return errors.Newf("load CA: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Newf("generate leaf key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return errors.Newf("generate serial: %w", err)
	}

	var dnsNames []string
	var ipAddresses []net.IP
	for _, h := range ci.certHosts {
		norm, ok := normalizeHostForVerify(h)
		if !ok {
			continue
		}
		if ip := net.ParseIP(norm); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, norm)
		}
	}

	ci.logger.Fields(
		"domain", domain,
		"dns_names", dnsNames,
		"ip_addresses", ipAddresses,
	).Debug("generating local leaf certificate SANs")

	commonName := fmt.Sprintf("%s Development CA", woos.Name)
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
		return errors.Newf("create leaf cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return errors.Newf("marshal leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := ci.validateCertificateBytes(certPEM, keyPEM); err != nil {
		return errors.Newf("generated cert does not validate: %w", err)
	}

	if err := ci.store.Save(tlsstore.IssuerLocal, domain, certPEM, keyPEM); err != nil {
		return errors.Newf("failed to save leaf cert to store: %w", err)
	}

	ci.logger.Fields("domain", domain, "algo", "ECDSA").Info("successfully generated leaf certificate")
	return nil
}

// loadCA retrieves the CA certificate and private key from storage.
func (ci *Local) loadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certData, keyData, err := ci.store.Load("ca")
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

// validateCertificateBytes validates that certificate and key pair are valid for the configured hosts.
func (ci *Local) validateCertificateBytes(certData, keyData []byte) error {
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

func (ci *Local) ensureLocalhostCertUnlocked() (string, string, error) {

	seen := make(map[string]bool)
	var out []string
	for _, h := range ci.certHosts {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	ci.certHosts = out

	defaults := []string{woos.Localhost, woos.LocalhostWildcardSAN, woos.IPv4LoopbackSAN, woos.IPv6LoopbackSAN}
	defaults = append(defaults, getLocalLANIPs()...)
	for _, d := range defaults {
		if !seen[d] {
			ci.certHosts = append(ci.certHosts, d)
			seen[d] = true
		}
	}

	domain := ci.certPrefix()

	certPEM, keyPEM, err := ci.store.Load(domain)
	if err == nil {
		if err := ci.validateCertificateBytes(certPEM, keyPEM); err == nil {
			ci.logger.Fields("domain", domain).Info("using existing local certificate")
			return domain, domain, nil
		}

		_ = ci.store.Delete(domain)
	}

	if !ci.caExists() {
		ci.logger.Info("CA root not found, generating and installing local CA")
		if err := ci.generateAndInstallCA(); err != nil {
			return "", "", err
		}
	}

	if err := ci.generateLeaf(domain); err != nil {
		return "", "", err
	}

	return domain, domain, nil
}

// hasCertutil checks for certutil presence on the system.
func hasCertutil() bool {
	paths := certutilPaths()
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// certutilPaths returns platform-specific paths where certutil may be installed.
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

// normalizeHostForVerify strips port and brackets from host strings for certificate validation.
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

// getLocalLANIPs returns non-loopback IPv4 addresses on the local machine.
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

// parsePrivateKey parses a private key from DER bytes, supporting PKCS#8 and SEC1 formats.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	return x509.ParseECPrivateKey(der)
}
