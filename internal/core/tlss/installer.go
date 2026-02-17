package tlss

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

// mkcert-only design (dev-friendly, deterministic):
// - Always use mkcert for BOTH CA install and leaf cert generation.
// - Never download mkcert from GitHub.
// - Per-host certs supported: localhost -> localhost-443-cert.pem, example.localhost -> example-443-cert.pem, etc.
// - Wildcards supported: *.localhost (so dance.localhost works).
// - Validation is IPv6-safe (does NOT treat "::1" as "host:port").
// - We write a marker file after CA install to avoid repeated "CA root not found" loops.
// - Uses ECDSA P-256 by default for performance (10x faster than RSA).

type Installer struct {
	logger    *ll.Logger
	CertDir   woos.Folder
	certHosts []string
	port      int
}

func NewInstaller(logger *ll.Logger, absoluteCertDir ...woos.Folder) *Installer {
	certDir := woos.CertDir
	if len(absoluteCertDir) > 0 {
		certDir = absoluteCertDir[0]
	}
	return &Installer{
		logger:  logger,
		CertDir: certDir,
	}
}

func (ci *Installer) SetStorageDir(dir woos.Folder) error {
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

	if err := dir.Ensure(woos.Folder(""), false); err != nil {
		return errors.Newf("failed to create storage directory: %w", err)
	}

	ci.CertDir = dir
	if ci.logger != nil {
		ci.logger.Fields("dir", dir).Info("Set certificate storage directory")
	}
	return nil
}

func (ci *Installer) SetHosts(hosts []string, port int) {
	ci.certHosts = hosts
	ci.port = port
}

func (ci *Installer) EnsureLocalhostCert() (certFile, keyFile string, err error) {
	prefix := ci.certPrefix()

	// Dedup + trim input hosts
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

	// Default local SANs (sane dev defaults)
	defaults := []string{
		woos.Localhost,
		woos.LocalhostWildcardSAN,
		woos.IPv4LoopbackSAN,
		woos.IPv6LoopbackSAN,
	}

	// NEW: Add LAN IPs so https://192.168.x.x  works
	defaults = append(defaults, getLocalLANIPs()...)

	for _, d := range defaults {
		if !seen[d] {
			ci.certHosts = append(ci.certHosts, d)
			seen[d] = true
		}
	}

	// Ensure cert dir exists (secure)
	if err := ci.CertDir.Ensure(woos.Folder(""), true); err != nil {
		return "", "", errors.Newf("failed to ensure cert dir: %w", err)
	}

	certFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	// Reuse existing cert if valid for requested SANs
	if err := ci.validateCertificate(certFile, keyFile); err == nil {
		if ci.logger != nil {
			ci.logger.Fields("cert", certFile, "key", keyFile).Info("Using existing certificates")
		}
		return certFile, keyFile, nil
	}

	if ci.logger != nil {
		ci.logger.Fields("hosts", ci.certHosts, "cert", certFile).Info("Generating localhost certificates with ECDSA")
	}

	// mkcert is REQUIRED
	mkcertPath, ok := findMkcertPath()
	if !ok {
		return "", "", errors.Newf("%w: %s", woos.ErrMkCertRequired, woos.MkcertInstallHint)
	}

	// Sanity: mkcert must be able to resolve its default CAROOT
	if _, err := MkcertDefaultCAROOT(mkcertPath); err != nil {
		return "", "", errors.Newf("mkcert default CAROOT not resolvable: %w", err)
	}

	// Ensure mkcert CA is installed (best-effort), but don't loop forever.
	if !ci.caInstalled() {
		if ci.logger != nil {
			ci.logger.Info("CA root not found (mkcert). Installing...")
		}
		if err := ci.installCAWithMkcert(mkcertPath); err != nil {
			return "", "", err
		}
		_ = ci.writeCAMarker()
		ci.purgeStaleLeafCerts()
	}

	// Generate leaf cert with mkcert (ECDSA for performance)
	if _, _, err := ci.generateWithMkcert(mkcertPath, certFile, keyFile); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

// InstallCARootIfNeeded installs mkcert CA root if not present.
// mkcert-only: no truststore fallback, no downloads.
func (ci *Installer) InstallCARootIfNeeded() error {
	_ = BootstrapEnv(ci.logger)

	if ci.caInstalled() {
		return nil
	}

	mkcertPath, ok := findMkcertPath()
	if !ok {
		return errors.New(woos.MkcertNotFoundMsg)
	}

	if ci.logger != nil {
		ci.logger.Fields("mkcert", mkcertPath).Info("Installing mkcert CA root")
	}

	if err := ci.installCAWithMkcert(mkcertPath); err != nil {
		return err
	}

	_ = ci.writeCAMarker()
	ci.purgeStaleLeafCerts()
	return nil
}

func (ci *Installer) installCAWithMkcert(mkcertPath string) error {
	_ = BootstrapEnv(ci.logger)

	cmd := exec.Command(mkcertPath, "-install")
	cmd.Env = mkcertEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Newf("%w: %s", woos.ErrMkCertInstalledFailed, strings.TrimSpace(string(out)))
	}
	return nil
}

func (ci *Installer) generateWithMkcert(mkcertPath, certFile, keyFile string) (string, string, error) {
	_ = BootstrapEnv(ci.logger)

	// Use ECDSA for 10x faster performance vs RSA
	// This only affects auto-generated localhost certs, not user-provided certs
	// CORRECT FLAG: -ecdsa (not -ecdsa-p256)
	args := []string{"-ecdsa", "-cert-file", certFile, "-key-file", keyFile}
	args = append(args, ci.certHosts...)

	cmd := exec.Command(mkcertPath, args...)
	cmd.Env = mkcertEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", errors.Newf("%w: %s", woos.ErrMkCertFailed, strings.TrimSpace(string(out)))
	}

	if err := ci.validateCertificate(certFile, keyFile); err != nil {
		return "", "", errors.Newf("generated cert does not validate: %w", err)
	}

	if ci.logger != nil {
		ci.logger.Fields("cert", certFile, "algo", "ECDSA").Info("Successfully generated certificates")
	}

	_ = out
	return certFile, keyFile, nil
}

func (ci *Installer) ListCertificates() ([]string, error) {
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

func (ci *Installer) FindExistingCerts(prefix string, port int) (certFile, keyFile string, found bool) {
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

// validateCertificate validates cert/key pair is usable for requested hosts.
// Wildcards verified by testing a concrete name: "*.localhost" -> "example.localhost".
// IPv6-safe: does NOT split "::1" into "host:port".
func (ci *Installer) validateCertificate(certFile, keyFile string) error {
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

	if ci.logger != nil {
		ci.logger.Fields(
			"subject", leaf.Subject.String(),
			"dns", leaf.DNSNames,
			"ips", ipStrings(leaf.IPAddresses),
			"not_after", leaf.NotAfter,
			"algo", leaf.PublicKeyAlgorithm.String(), // Log the algorithm
		).Debug("tls: cert details")
	}

	for _, raw := range ci.certHosts {
		target, ok := normalizeHostForVerify(raw)
		if !ok {
			continue
		}

		// Validate wildcard by testing a concrete subdomain.
		if strings.HasPrefix(target, "*.") {
			testHost := "example" + target[1:] // "*.localhost" -> "example.localhost"
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

func (ci *Installer) certPrefix() string {
	if len(ci.certHosts) == 0 {
		return woos.Localhost
	}

	raw := strings.TrimSpace(ci.certHosts[0])
	if raw == "" {
		return woos.Localhost
	}

	// Use the same safe normalization used by validation.
	host, ok := normalizeHostForVerify(raw)
	if !ok || host == "" {
		return woos.Localhost
	}

	// If it's an IP, just use it.
	if net.ParseIP(host) != nil {
		return host
	}

	parts := strings.Split(host, ".")
	if len(parts) > 0 && parts[0] != "" && parts[0] != "*" {
		return parts[0]
	}
	return woos.Localhost
}

func (ci *Installer) purgeStaleLeafCerts() {
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

	if ci.logger != nil && removed > 0 {
		ci.logger.Fields("removed", removed, "dir", ci.CertDir.Path()).Info("purged stale leaf certs after CA install")
	}
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func (ci *Installer) caInstalled() bool {
	// 1) Use OS best-effort check (mkcert dev CA label on macOS).
	if IsCARootInstalled() {
		return true
	}

	// 2) Fallback: our own marker (prevents repeated install loops in odd keychain contexts).
	// Marker is per-certdir, which is fine for agbero dev runtime.
	m := ci.caMarkerPath()
	if m == "" {
		return false
	}
	_, err := os.Stat(m)
	return err == nil
}

func (ci *Installer) caMarkerPath() string {
	if !ci.CertDir.IsSet() {
		return ""
	}
	return filepath.Join(ci.CertDir.Path(), woos.CAMarkerFile)
}

func (ci *Installer) writeCAMarker() error {
	m := ci.caMarkerPath()
	if m == "" {
		return nil
	}
	// Keep it simple; contents not important.
	return os.WriteFile(m, []byte(time.Now().UTC().Format(time.RFC3339)), woos.FileModePrivate)
}

// normalizeHostForVerify returns a hostname/IP suitable for x509 hostname verification.
// Handles:
// - "example.localhost:443" -> "example.localhost"
// - "127.0.0.1:443" -> "127.0.0.1"
// - "[::1]:443" -> "::1"
// - "::1" -> "::1" (IMPORTANT: do NOT treat as host:port)
// - trims whitespace and ignores empty strings.
func normalizeHostForVerify(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}

	// Bracketed IPv6 with port: [::1]:443
	if strings.HasPrefix(s, woos.IPv6BracketOpen) && strings.Contains(s, woos.IPv6BracketClose) {
		if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
			return h, true
		}
		// If SplitHostPort fails, fall through to return cleaned string.
		s = strings.TrimPrefix(s, woos.IPv6BracketOpen)
		s = strings.TrimSuffix(s, woos.IPv6BracketClose)
		return s, s != ""
	}

	// If it looks like host:port (single colon and port is numeric), split it.
	// Avoid breaking raw IPv6 like "::1" or "fe80::1".
	if strings.Count(s, woos.Colon) == 1 {
		if h, p, err := net.SplitHostPort(s); err == nil && h != "" && p != "" {
			return h, true
		}
		// net.SplitHostPort requires ":port" pattern; if it fails, keep original.
	}

	// Raw IPv6 or normal hostname/IP without port.
	return s, true
}

// findMkcertPath looks for mkcert in PATH and common install locations.
// This avoids service-context PATH issues (launchd/systemd).
func findMkcertPath() (string, bool) {
	if path, err := exec.LookPath("mkcert"); err == nil {
		return path, true
	}

	home, _ := os.UserHomeDir()
	common := []string{
		woos.MkcertPathUsrLocalBin,
		woos.MkcertPathUsrBin,
		woos.MkcertPathOptHomebrewBin,
		filepath.Join(home, woos.MkcertPathGoBin),
		filepath.Join(home, woos.MkcertPathLocalBin),
	}

	if runtime.GOOS == "windows" {
		common = append(common,
			filepath.Join(home, woos.MkcertPathScoopShims),
			filepath.Join(home, woos.MkcertPathChocoBin),
		)
	}

	for _, p := range common {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
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
