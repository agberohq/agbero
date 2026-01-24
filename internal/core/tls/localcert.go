package tls

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

	"github.com/jittering/truststore"
	"github.com/olekukonko/ll"
)

const (
	mkcertReleasesAPI = "https://api.github.com/repos/FiloSottile/mkcert/releases/latest"
)

type CertInstaller struct {
	logger    *ll.Logger
	CertDir   string
	certHosts []string
	port      int
	useMkcert bool
}

func NewCertInstaller(logger *ll.Logger) *CertInstaller {
	// Try multiple locations in order of preference
	certDirs := []string{
		// 1. User's existing .cert directory
		filepath.Join(os.Getenv("HOME"), ".cert"),
		// 2. Agbero-specific cert directory
		filepath.Join(os.Getenv("HOME"), ".config", "agbero", "certs"),
		// 3. System-wide location
		"/etc/agbero/certs",
	}

	var certDir string
	for _, dir := range certDirs {
		if _, err := os.Stat(dir); err == nil {
			certDir = dir
			logger.Fields("dir", dir).Debug("Using existing cert directory")
			break
		}
	}

	// If no existing directory found, use the first one
	if certDir == "" {
		certDir = certDirs[0]
		logger.Fields("dir", certDir).Debug("Creating new cert directory")
	}

	return &CertInstaller{
		logger:  logger,
		CertDir: certDir,
	}
}

func (ci *CertInstaller) SetStorageDir(dir string) error {
	if dir == "" {
		return nil // Use default
	}

	// Expand ~ to home directory
	if strings.HasPrefix(dir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		dir = filepath.Join(home, dir[2:])
	}

	// Make directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	ci.CertDir = dir
	ci.logger.Fields("dir", dir).Info("Set certificate storage directory")
	return nil
}

func (ci *CertInstaller) SetHosts(hosts []string, port int) {
	ci.certHosts = hosts
	ci.port = port
}

func (ci *CertInstaller) EnsureLocalhostCert() (certFile, keyFile string, err error) {
	// Ensure cert directory exists
	if err := os.MkdirAll(ci.CertDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create cert directory %s: %w", ci.CertDir, err)
	}

	ci.logger.Fields("dir", ci.CertDir).Info("Using certificate directory")

	// Use first host as filename prefix
	prefix := "localhost"
	if len(ci.certHosts) > 0 {
		host := ci.certHosts[0]
		// Remove port if present
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if net.ParseIP(host) != nil {
			prefix = host
		} else {
			// Use first part of domain (e.g., "app" from "app.localhost")
			domainParts := strings.Split(host, ".")
			if len(domainParts) > 0 {
				prefix = domainParts[0]
			}
		}
	}

	// First, look for existing certificates in the directory
	if cert, key, found := ci.findExistingCerts(prefix, ci.port); found {
		ci.logger.Fields("cert", cert, "key", key).Info("Using existing certificates")
		return cert, key, nil
	}

	// If not found, use default naming pattern
	certFile = filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile = filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	ci.logger.Fields("hosts", ci.certHosts, "cert", certFile, "key", keyFile).Info("Generating localhost certificates")

	// Try different generation methods
	methods := []func() (string, string, error){
		ci.tryMkcertInPath,
		ci.tryTruststore,
		ci.downloadAndUseMkcert,
	}

	for _, method := range methods {
		cert, key, err := method()
		if err == nil {
			ci.logger.Fields("cert", cert, "key", key).Info("Successfully generated certificates")
			return cert, key, nil
		}
		ci.logger.Fields("err", err).Warn("Certificate generation method failed")
	}

	return "", "", fmt.Errorf("all certificate generation methods failed")
}

func (ci *CertInstaller) IsMkcertInstalled() bool {
	// Check if mkcert is in PATH
	if path, err := exec.LookPath("mkcert"); err == nil {
		// Verify it's actually mkcert and works
		cmd := exec.Command(path, "-version")
		if err := cmd.Run(); err == nil {
			ci.logger.Fields("path", path).Debug("Found working mkcert installation")
			return true
		}
	}

	// Check common installation locations
	commonPaths := []string{
		"/usr/local/bin/mkcert",
		"/usr/bin/mkcert",
		"/opt/homebrew/bin/mkcert", // macOS Homebrew
		filepath.Join(os.Getenv("HOME"), "go", "bin", "mkcert"),
		filepath.Join(os.Getenv("HOME"), ".local", "bin", "mkcert"),
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			ci.logger.Fields("path", path).Debug("Found mkcert at common location")
			return true
		}
	}

	return false
}

func (ci *CertInstaller) IsCARootInstalled() bool {
	// Platform-specific checks for CA installation

	switch runtime.GOOS {
	case "darwin":
		// Check macOS Keychain
		cmd := exec.Command("security", "find-certificate", "-c", "mkcert")
		return cmd.Run() == nil

	case "linux":
		// Check common Linux CA stores
		paths := []string{
			"/etc/ssl/certs/mkcert-root.pem",
			"/usr/local/share/ca-certificates/mkcert-root.crt",
			filepath.Join(os.Getenv("HOME"), ".local/share/mkcert/rootCA.pem"),
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return true
			}
		}

	case "windows":
		// PowerShell check for Windows cert store
		psCmd := `Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "mkcert"} | Select-Object -First 1`
		cmd := exec.Command("powershell", "-Command", psCmd)
		output, err := cmd.Output()
		return err == nil && len(strings.TrimSpace(string(output))) > 0
	}

	return false
}

func (ci *CertInstaller) InstallCARootIfNeeded() error {
	if ci.IsCARootInstalled() {
		ci.logger.Info("CA root already installed in system trust store")
		return nil
	}

	ci.logger.Info("CA root not found, attempting to install...")

	// Try mkcert first
	if ci.IsMkcertInstalled() {
		if path, err := exec.LookPath("mkcert"); err == nil {
			return ci.installCAWithMkcert(path)
		}
	}

	// Try truststore
	ml, err := truststore.NewLib()
	if err != nil {
		return fmt.Errorf("failed to initialize truststore: %w", err)
	}

	if err := ml.Install(); err != nil {
		return fmt.Errorf("truststore install failed: %w", err)
	}

	ci.logger.Info("CA installed successfully via truststore")
	return nil
}

func (ci *CertInstaller) installCAWithMkcert(mkcertPath string) error {
	ci.logger.Info("Installing CA with mkcert")
	cmd := exec.Command(mkcertPath, "-install")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkcert -install failed: %s", string(output))
	}

	ci.logger.Info("CA installed successfully via mkcert")
	return nil
}

func (ci *CertInstaller) InstallWithMkcert() error {
	if !ci.IsMkcertInstalled() {
		return fmt.Errorf("mkcert is not installed")
	}

	path, err := exec.LookPath("mkcert")
	if err != nil {
		return fmt.Errorf("mkcert not found: %w", err)
	}

	return ci.installCAWithMkcert(path)
}

func (ci *CertInstaller) InstallWithTruststore() error {
	ml, err := truststore.NewLib()
	if err != nil {
		return fmt.Errorf("failed to initialize truststore: %w", err)
	}

	if err := ml.Install(); err != nil {
		return fmt.Errorf("truststore install failed: %w", err)
	}

	ci.logger.Info("CA installed successfully via truststore")
	return nil
}

func (ci *CertInstaller) TestCAInstallation() bool {
	return ci.IsCARootInstalled()
}

func (ci *CertInstaller) ListCertificates() ([]string, error) {
	files, err := os.ReadDir(ci.CertDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert directory: %w", err)
	}

	var certs []string
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".pem") ||
			strings.HasSuffix(file.Name(), ".crt") ||
			strings.HasSuffix(file.Name(), ".key")) {
			certs = append(certs, file.Name())
		}
	}

	return certs, nil
}

func (ci *CertInstaller) generateNewCertificates(certFile, keyFile string) (string, string, error) {
	// Set mkcert flag for this generation
	ci.useMkcert = true

	// Try mkcert first if available
	if path, err := exec.LookPath("mkcert"); err == nil {
		return ci.generateWithMkcert(path, certFile, keyFile)
	}

	// Fall back to truststore
	return ci.tryTruststoreWithPaths(certFile, keyFile)
}

func (ci *CertInstaller) tryMkcertInPath() (string, string, error) {
	path, err := exec.LookPath("mkcert")
	if err != nil {
		return "", "", fmt.Errorf("mkcert not in PATH: %w", err)
	}

	prefix := "localhost"
	if len(ci.certHosts) > 0 {
		host := ci.certHosts[0]
		if net.ParseIP(host) != nil {
			prefix = host
		} else {
			domainParts := strings.Split(host, ".")
			if len(domainParts) > 0 {
				prefix = domainParts[0]
			}
		}
	}

	certFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.generateWithMkcert(path, certFile, keyFile)
}

func (ci *CertInstaller) generateWithMkcert(mkcertPath, certFile, keyFile string) (string, string, error) {
	ci.logger.Fields("mkcert_path", mkcertPath).Info("Using mkcert")

	args := []string{"-key-file", keyFile, "-cert-file", certFile}
	args = append(args, ci.certHosts...)

	cmd := exec.Command(mkcertPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("mkcert failed: %s", string(output))
	}

	// Try to install CA if not already installed (non-fatal)
	if !ci.IsCARootInstalled() {
		ci.logger.Info("Attempting to install mkcert CA root")
		installCmd := exec.Command(mkcertPath, "-install")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if installErr := installCmd.Run(); installErr != nil {
			ci.logger.Warn("Failed to install mkcert CA (browsers may show warnings): %v", installErr)
		} else {
			ci.logger.Info("mkcert CA installed successfully")
		}
	}

	return certFile, keyFile, nil
}

func (ci *CertInstaller) tryTruststore() (string, string, error) {
	prefix := "localhost"
	if len(ci.certHosts) > 0 {
		host := ci.certHosts[0]
		if net.ParseIP(host) != nil {
			prefix = host
		} else {
			domainParts := strings.Split(host, ".")
			if len(domainParts) > 0 {
				prefix = domainParts[0]
			}
		}
	}

	certFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.tryTruststoreWithPaths(certFile, keyFile)
}

func (ci *CertInstaller) tryTruststoreWithPaths(certFile, keyFile string) (string, string, error) {
	ml, err := truststore.NewLib()
	if err != nil {
		return "", "", fmt.Errorf("truststore init failed: %w", err)
	}

	// Install CA if not already installed
	if !ci.IsCARootInstalled() {
		if err := ml.Install(); err != nil {
			ci.logger.Warn("Failed to install truststore CA: %v", err)
		}
	}

	cert, err := ml.MakeCert(ci.certHosts, ci.CertDir)
	if err != nil {
		return "", "", fmt.Errorf("truststore makecert failed: %w", err)
	}

	// Move/rename to our preferred location
	if cert.CertFile != certFile {
		if err := os.Rename(cert.CertFile, certFile); err != nil {
			ci.logger.Fields("from", cert.CertFile, "to", certFile).Warn("Failed to rename cert file")
		}
	}
	if cert.KeyFile != keyFile {
		if err := os.Rename(cert.KeyFile, keyFile); err != nil {
			ci.logger.Fields("from", cert.KeyFile, "to", keyFile).Warn("Failed to rename key file")
		}
	}

	return certFile, keyFile, nil
}

func (ci *CertInstaller) downloadAndUseMkcert() (string, string, error) {
	ci.logger.Info("Downloading mkcert from GitHub")

	mkcertPath, err := ci.downloadMkcert()
	if err != nil {
		return "", "", err
	}

	defer func() {
		// Clean up downloaded binary
		if err := os.Remove(mkcertPath); err != nil {
			ci.logger.Fields("path", mkcertPath, "err", err).Warn("Failed to clean up downloaded mkcert")
		}
	}()

	prefix := "localhost"
	if len(ci.certHosts) > 0 {
		host := ci.certHosts[0]
		if net.ParseIP(host) != nil {
			prefix = host
		} else {
			domainParts := strings.Split(host, ".")
			if len(domainParts) > 0 {
				prefix = domainParts[0]
			}
		}
	}

	certFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.generateWithMkcert(mkcertPath, certFile, keyFile)
}

func (ci *CertInstaller) downloadMkcert() (string, error) {
	ci.logger.Info("Fetching latest mkcert release metadata")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(mkcertReleasesAPI)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest mkcert release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	// Parse release JSON
	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse release JSON: %w", err)
	}

	if release.TagName == "" {
		return "", fmt.Errorf("no tag_name in mkcert release")
	}

	// Determine binary name based on OS/arch
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	version := strings.TrimPrefix(release.TagName, "v")

	// Map Go arch to mkcert arch names
	archMap := map[string]string{
		"amd64": "amd64",
		"386":   "386",
		"arm64": "arm64",
		"arm":   "arm",
	}

	mkcertArch, ok := archMap[goarch]
	if !ok {
		mkcertArch = goarch
	}

	binaryName := fmt.Sprintf("mkcert-%s-%s-%s", version, goos, mkcertArch)
	if goos == "windows" {
		binaryName += ".exe"
	}

	ci.logger.Fields("binary", binaryName, "version", version).Debug("Looking for mkcert binary")

	// Find binary and checksum URLs
	var binaryURL, checksumURL string
	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			binaryURL = asset.URL
		} else if strings.HasSuffix(asset.Name, "SHA256SUMS") {
			checksumURL = asset.URL
		}
	}

	if binaryURL == "" {
		return "", fmt.Errorf("could not find mkcert binary %q in release assets", binaryName)
	}

	if checksumURL == "" {
		// Try alternative checksum names
		for _, asset := range release.Assets {
			if strings.Contains(asset.Name, "SHA256") {
				checksumURL = asset.URL
				break
			}
		}
		if checksumURL == "" {
			return "", fmt.Errorf("could not find SHA256 checksum in mkcert release assets")
		}
	}

	// Download checksum file
	ci.logger.Info("Downloading checksum file")
	resp, err = client.Get(checksumURL)
	if err != nil {
		return "", fmt.Errorf("failed to download checksum file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksum download returned status %d", resp.StatusCode)
	}

	checksumData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read checksum file: %w", err)
	}

	// Find expected checksum for our binary
	var expectedChecksum string
	for _, line := range strings.Split(string(checksumData), "\n") {
		if strings.Contains(line, binaryName) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				expectedChecksum = fields[0]
				break
			}
		}
	}

	if expectedChecksum == "" {
		return "", fmt.Errorf("could not find checksum entry for %s", binaryName)
	}

	ci.logger.Fields("checksum", expectedChecksum).Debug("Found expected checksum")

	// Download binary
	ci.logger.Info("Downloading mkcert binary")
	resp, err = client.Get(binaryURL)
	if err != nil {
		return "", fmt.Errorf("failed to download mkcert binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("binary download returned status %d", resp.StatusCode)
	}

	// Create temp file for binary
	tmpFile, err := os.CreateTemp("", "mkcert-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file for mkcert: %w", err)
	}
	defer tmpFile.Close()

	// Calculate SHA256 while downloading
	hash := sha256.New()
	tee := io.TeeReader(resp.Body, hash)

	// Download with progress
	buf := make([]byte, 32*1024)
	var total int64

	for {
		n, err := tee.Read(buf)
		if n > 0 {
			if _, writeErr := tmpFile.Write(buf[:n]); writeErr != nil {
				return "", fmt.Errorf("failed to write to temp file: %w", writeErr)
			}
			total += int64(n)
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return "", fmt.Errorf("failed to read binary data: %w", err)
		}
	}

	ci.logger.Fields("size", total).Info("Downloaded mkcert binary")

	// Verify checksum
	calculated := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(calculated, expectedChecksum) {
		return "", fmt.Errorf("checksum mismatch for mkcert: expected %s, got %s",
			expectedChecksum, calculated)
	}

	// Make executable on non-Windows systems
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
			return "", fmt.Errorf("failed to make mkcert binary executable: %w", err)
		}
	}

	ci.logger.Fields("path", tmpFile.Name()).Info("Successfully downloaded and verified mkcert")
	return tmpFile.Name(), nil
}

func (ci *CertInstaller) findExistingCerts(prefix string, port int) (certFile, keyFile string, found bool) {
	// Try multiple naming patterns in the cert directory
	patterns := []struct {
		certPattern string
		keyPattern  string
	}{
		// Your existing patterns from .cert/
		{fmt.Sprintf("%s.serve-cert.pem", prefix), fmt.Sprintf("%s.serve-key.pem", prefix)},
		{fmt.Sprintf("%s.pem", prefix), fmt.Sprintf("%s.key.pem", prefix)},
		// Port-specific patterns
		{fmt.Sprintf("%s-%d-cert.pem", prefix, port), fmt.Sprintf("%s-%d-key.pem", prefix, port)},
		{fmt.Sprintf("%s-%d.pem", prefix, port), fmt.Sprintf("%s-%d.key.pem", prefix, port)},
		// Generic patterns
		{"cert.pem", "key.pem"},
		{"localhost.pem", "localhost.key.pem"},
	}

	for _, pattern := range patterns {
		certPath := filepath.Join(ci.CertDir, pattern.certPattern)
		keyPath := filepath.Join(ci.CertDir, pattern.keyPattern)

		if _, certErr := os.Stat(certPath); certErr == nil {
			if _, keyErr := os.Stat(keyPath); keyErr == nil {
				// Validate the certificate
				if ci.validateCertificate(certPath, keyPath, ci.certHosts) {
					ci.logger.Fields("cert", certPath, "key", keyPath).Debug("Found existing valid certificates")
					return certPath, keyPath, true
				}
			}
		}
	}

	return "", "", false
}

func (ci *CertInstaller) validateCertificate(certFile, keyFile string, hosts []string) bool {
	// Read certificate
	certData, err := os.ReadFile(certFile)
	if err != nil {
		ci.logger.Fields("file", certFile, "err", err).Debug("Failed to read certificate")
		return false
	}

	// Read key
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		ci.logger.Fields("file", keyFile, "err", err).Debug("Failed to read key")
		return false
	}

	// Try to load the certificate
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		ci.logger.Fields("err", err).Debug("Failed to load X509 key pair")
		return false
	}

	// Parse certificate to check expiration
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		ci.logger.Fields("err", err).Debug("Failed to parse certificate")
		return false
	}

	// Check if certificate is expired
	if time.Now().After(x509Cert.NotAfter) {
		ci.logger.Fields("expires", x509Cert.NotAfter).Debug("Certificate expired")
		return false
	}

	// Check if certificate is about to expire (within 7 days)
	if time.Now().Add(7 * 24 * time.Hour).After(x509Cert.NotAfter) {
		ci.logger.Fields("expires", x509Cert.NotAfter).Info("Certificate expires soon")
	}

	ci.logger.Fields("subject", x509Cert.Subject, "expires", x509Cert.NotAfter).Debug("Certificate is valid")
	return true
}
