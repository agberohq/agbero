package tlss

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/jittering/truststore"
	"github.com/olekukonko/ll"
)

const (
	mkcertReleasesAPI = "https://api.github.com/repos/FiloSottile/mkcert/releases/latest"
)

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

	if strings.HasPrefix(dir.String(), "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		dir = woos.NewFolder(filepath.Join(home, dir.String()[2:]))
	}

	// Ensure dir exists (not necessarily secure here; cert dir can be secure elsewhere)
	if err := dir.Ensure(woos.Folder(""), false); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	ci.CertDir = dir
	ci.logger.Fields("dir", dir).Info("Set certificate storage directory")
	return nil
}

func (ci *Installer) SetHosts(hosts []string, port int) {
	ci.certHosts = hosts
	ci.port = port
}

func (ci *Installer) EnsureLocalhostCert() (certFile, keyFile string, err error) {
	prefix := ci.certPrefix()

	// FIX: Force default local domains.
	// We use a map to deduplicate before appending.
	seen := make(map[string]bool)
	for _, h := range ci.certHosts {
		seen[h] = true
	}

	defaults := []string{
		"localhost",
		"*.localhost",
		"127.0.0.1",
		"::1",
		"*.local",
		"*.agbero",
	}

	for _, d := range defaults {
		if !seen[d] {
			ci.certHosts = append(ci.certHosts, d)
			seen[d] = true
		}
	}

	if cert, key, found := ci.findExistingCerts(prefix); found {
		ci.logger.Fields("cert", cert, "key", key).Info("Using existing certificates")
		return cert, key, nil
	}

	if err := ci.CertDir.Ensure(woos.Folder(""), true); err != nil {
		return "", "", fmt.Errorf("failed to ensure cert dir: %w", err)
	}

	certFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	ci.logger.Fields("hosts", ci.certHosts, "cert", certFile).Info("Generating localhost certificates with expanded wildcards")

	methods := []func() (string, string, error){
		ci.tryMkcertInPath,
		ci.tryTruststore,
		ci.downloadAndUseMkcert,
	}

	var lastErr error
	for _, method := range methods {
		c, k, err := method()
		if err == nil {
			ci.logger.Fields("cert", c).Info("Successfully generated certificates")
			return c, k, nil
		}
		lastErr = err
		ci.logger.Warnf("cert method failed: %v", err)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unknown failure")
	}
	return "", "", fmt.Errorf("all certificate generation methods failed: %w", lastErr)
}

// InstallCARootIfNeeded attempts to ensure mkcert's CA root is installed into OS trust store.
// It does NOT change CAROOT to your cert storage.
// It relies on mkcert/truststore default behavior.
func (ci *Installer) InstallCARootIfNeeded() error {
	_ = BootstrapEnv(ci.logger)

	// Already trusted?
	if IsCARootInstalled() {
		return nil
	}

	ci.logger.Info("CA root not found, attempting to install...")

	// 1) Try truststore lib first (cross-platform best-effort)
	if lib, err := truststore.NewLib(); err == nil {
		if err := lib.Install(); err == nil {
			ci.logger.Info("CA installed successfully via truststore")
			return nil
		}
		ci.logger.Warnf("truststore install failed (permissions?): %v", err)
	} else {
		ci.logger.Warnf("failed to init truststore lib: %v", err)
	}

	// 2) Fallback to mkcert binary if present
	if path, err := exec.LookPath("mkcert"); err == nil {
		ci.logger.Info("Falling back to external mkcert binary")
		return ci.installCAWithMkcert(path)
	}

	return fmt.Errorf("failed to install CA root (no truststore install and mkcert not available)")
}

func (ci *Installer) installCAWithMkcert(mkcertPath string) error {
	_ = BootstrapEnv(ci.logger)

	cmd := exec.Command(mkcertPath, "-install")
	cmd.Env = mkcertEnv() // ensure HOME/USER/LOGNAME for service contexts

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkcert -install failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (ci *Installer) ListCertificates() ([]string, error) {
	names, err := ci.CertDir.ReadNames()
	if err != nil {
		return nil, fmt.Errorf("failed to read cert directory: %w", err)
	}

	var certs []string
	for _, name := range names {
		if strings.HasSuffix(name, ".pem") ||
			strings.HasSuffix(name, ".crt") ||
			strings.HasSuffix(name, ".key") {
			certs = append(certs, name)
		}
	}
	return certs, nil
}

func (ci *Installer) tryMkcertInPath() (string, string, error) {
	mkcertPath, err := exec.LookPath("mkcert")
	if err != nil {
		return "", "", fmt.Errorf("mkcert not in PATH: %w", err)
	}

	// Sanity: confirm mkcert can locate its default CAROOT (service env fix).
	if _, err := MkcertDefaultCAROOT(mkcertPath); err != nil {
		return "", "", fmt.Errorf("mkcert default CAROOT not resolvable: %w", err)
	}

	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.generateWithMkcert(mkcertPath, certFile, keyFile)
}

func (ci *Installer) generateWithMkcert(mkcertPath, certFile, keyFile string) (string, string, error) {
	_ = BootstrapEnv(ci.logger)

	args := []string{"-key-file", keyFile, "-cert-file", certFile}
	args = append(args, ci.certHosts...)

	cmd := exec.Command(mkcertPath, args...)
	cmd.Env = mkcertEnv() // don’t force CAROOT; let mkcert decide OS default

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("mkcert failed: %s", strings.TrimSpace(string(out)))
	}

	// If root isn't trusted, try install (best-effort, may require admin)
	if !IsCARootInstalled() {
		installCmd := exec.Command(mkcertPath, "-install")
		installCmd.Env = mkcertEnv()
		_ = installCmd.Run()
	}

	// Validate we produced a usable cert for requested hosts
	if !ci.validateCertificate(certFile, keyFile) {
		return "", "", fmt.Errorf("generated cert does not validate for requested hosts")
	}

	return certFile, keyFile, nil
}

func (ci *Installer) tryTruststore() (string, string, error) {
	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))
	return ci.tryTruststoreWithPaths(certFile, keyFile)
}

func (ci *Installer) tryTruststoreWithPaths(certFile, keyFile string) (string, string, error) {
	lib, err := truststore.NewLib()
	if err != nil {
		return "", "", fmt.Errorf("truststore init failed: %w", err)
	}

	// Best-effort install
	if !IsCARootInstalled() {
		_ = lib.Install()
	}

	cert, err := lib.MakeCert(ci.certHosts, ci.CertDir.Path())
	if err != nil {
		return "", "", fmt.Errorf("truststore makecert failed: %w", err)
	}

	// Normalize file names to our pattern
	if cert.CertFile != certFile {
		_ = os.Rename(cert.CertFile, certFile)
	}
	if cert.KeyFile != keyFile {
		_ = os.Rename(cert.KeyFile, keyFile)
	}

	if !ci.validateCertificate(certFile, keyFile) {
		return "", "", fmt.Errorf("truststore cert does not validate for requested hosts")
	}

	return certFile, keyFile, nil
}

func (ci *Installer) downloadAndUseMkcert() (string, string, error) {
	ci.logger.Info("Downloading mkcert from GitHub")

	mkcertPath, err := ci.downloadMkcert()
	if err != nil {
		return "", "", err
	}
	defer func() { _ = os.Remove(mkcertPath) }()

	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.generateWithMkcert(mkcertPath, certFile, keyFile)
}

func (ci *Installer) downloadMkcert() (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", mkcertReleasesAPI, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "agbero/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	version := strings.TrimPrefix(release.TagName, "v")

	mkcertArch := runtime.GOARCH
	switch mkcertArch {
	case "amd64", "386", "arm64":
		// ok
	default:
		// fallback to reported arch, might fail but we’ll show clear error
	}

	binaryName := fmt.Sprintf("mkcert-%s-%s-%s", version, runtime.GOOS, mkcertArch)
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	var binaryURL, checksumURL string
	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			binaryURL = asset.URL
		} else if strings.HasSuffix(asset.Name, "SHA256SUMS") {
			checksumURL = asset.URL
		}
	}

	if binaryURL == "" {
		return "", fmt.Errorf("mkcert binary not found in release for %s", binaryName)
	}

	// Fetch checksums (best-effort)
	var expectedChecksum string
	if checksumURL != "" {
		req, _ = http.NewRequest("GET", checksumURL, nil)
		resp2, err := client.Do(req)
		if err == nil {
			defer resp2.Body.Close()
			checksumData, _ := io.ReadAll(resp2.Body)

			for _, line := range strings.Split(string(checksumData), "\n") {
				if strings.Contains(line, binaryName) {
					fields := strings.Fields(line)
					if len(fields) > 0 {
						expectedChecksum = fields[0]
					}
					break
				}
			}
		}
	}

	// Download binary
	req, _ = http.NewRequest("GET", binaryURL, nil)
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "mkcert-*")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	hash := sha256.New()
	tee := io.TeeReader(resp.Body, hash)

	if _, err := io.Copy(tmpFile, tee); err != nil {
		return "", err
	}

	calculated := hex.EncodeToString(hash.Sum(nil))
	if expectedChecksum != "" && !strings.EqualFold(calculated, expectedChecksum) {
		return "", fmt.Errorf("checksum mismatch")
	}

	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmpFile.Name(), 0755)
	}

	return tmpFile.Name(), nil
}

func (ci *Installer) findExistingCerts(prefix string) (certFile, keyFile string, found bool) {
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

		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				if ci.validateCertificate(certPath, keyPath) {
					return certPath, keyPath, true
				}
			}
		}
	}
	return "", "", false
}

func (ci *Installer) validateCertificate(certFile, keyFile string) bool {
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return false
	}
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return false
	}

	pair, err := tls.X509KeyPair(certData, keyData)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}

	if time.Now().After(leaf.NotAfter) {
		return false
	}

	for _, h := range ci.certHosts {
		host := h
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if err := leaf.VerifyHostname(host); err != nil {
			return false
		}
	}
	return true
}

func (ci *Installer) ValidateCertificateForHosts(certFile, keyFile string, hosts []string) bool {
	originalHosts := ci.certHosts
	ci.certHosts = hosts
	defer func() { ci.certHosts = originalHosts }()
	return ci.validateCertificate(certFile, keyFile)
}

func (ci *Installer) FindExistingCerts(prefix string, port int) (certFile, keyFile string, found bool) {
	originalPort := ci.port
	ci.port = port
	defer func() { ci.port = originalPort }()
	return ci.findExistingCerts(prefix)
}

func (ci *Installer) certPrefix() string {
	if len(ci.certHosts) == 0 {
		return "localhost"
	}
	host := ci.certHosts[0]
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	if net.ParseIP(host) != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "localhost"
}
