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
	logger    *ll.Logger // Changed to interface
	CertDir   woos.Folder
	certHosts []string
	port      int
	useMkcert bool
}

func NewInstaller(logger *ll.Logger, absoluteCertDir ...woos.Folder) *Installer {
	// We trust the caller (Server) has already resolved this path via woos.DefaultApply
	cetDir := woos.CertDir
	if len(absoluteCertDir) > 0 {
		cetDir = absoluteCertDir[0]
	}
	return &Installer{
		logger:  logger,
		CertDir: cetDir,
	}
}

func (ci *Installer) SetStorageDir(dir woos.Folder) error {
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

func (ci *Installer) SetHosts(hosts []string, port int) {
	ci.certHosts = hosts
	ci.port = port
}

func (ci *Installer) EnsureLocalhostCert() (certFile, keyFile string, err error) {
	// 1. Centralized Directory Creation
	// We use the woos package to ensure permissions and existence are correct
	// strictly based on the path provided by the Config/DefaultApply.
	if err := woos.EnsureDir(ci.CertDir, false); err != nil {
		return "", "", fmt.Errorf("failed to ensure cert directory: %w", err)
	}

	// 2. Determine Filename Prefix
	prefix := "localhost"
	if len(ci.certHosts) > 0 {
		host := ci.certHosts[0]
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if net.ParseIP(host) != nil {
			prefix = host
		} else {
			parts := strings.Split(host, ".")
			if len(parts) > 0 {
				prefix = parts[0]
			}
		}
	}

	// 3. Check for existing certs
	if cert, key, found := ci.findExistingCerts(prefix, ci.port); found {
		ci.logger.Fields("cert", cert, "key", key).Info("Using existing certificates")
		return cert, key, nil
	}

	// 4. Define Target Paths
	certFile = filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile = filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	ci.logger.Fields("hosts", ci.certHosts, "cert", certFile).Info("Generating localhost certificates")

	// 5. Attempt Generation Strategies
	methods := []func() (string, string, error){
		ci.tryMkcertInPath,
		ci.tryTruststore,
		ci.downloadAndUseMkcert,
	}

	for _, method := range methods {
		c, k, err := method()
		if err == nil {
			ci.logger.Fields("cert", c).Info("Successfully generated certificates")
			return c, k, nil
		}
		// Optional: Log debug here if specific methods fail
	}

	return "", "", fmt.Errorf("all certificate generation methods failed")
}

func (ci *Installer) IsMkcertInstalled() bool {
	return IsMkcertInstalled()
}

func (ci *Installer) IsCARootInstalled() bool {
	// Platform-specific checks for CA installation
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "find-certificate", "-c", "mkcert")
		return cmd.Run() == nil
	case "linux":
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
		psCmd := `Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "mkcert"} | Select-Object -First 1`
		cmd := exec.Command("powershell", "-Command", psCmd)
		output, err := cmd.Output()
		return err == nil && len(strings.TrimSpace(string(output))) > 0
	}
	return false
}

func (ci *Installer) InstallCARootIfNeeded() error {
	if ci.IsCARootInstalled() {
		return nil
	}

	ci.logger.Info("CA root not found, attempting to install...")

	if ci.IsMkcertInstalled() {
		if path, err := exec.LookPath("mkcert"); err == nil {
			return ci.installCAWithMkcert(path)
		}
	}

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

func (ci *Installer) installCAWithMkcert(mkcertPath string) error {
	ci.logger.Info("Installing CA with mkcert")
	cmd := exec.Command(mkcertPath, "-install")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkcert -install failed: %s", string(output))
	}
	return nil
}

func (ci *Installer) InstallWithMkcert() error {
	if !ci.IsMkcertInstalled() {
		return fmt.Errorf("mkcert is not installed")
	}
	path, err := exec.LookPath("mkcert")
	if err != nil {
		return fmt.Errorf("mkcert not found: %w", err)
	}
	return ci.installCAWithMkcert(path)
}

func (ci *Installer) InstallWithTruststore() error {
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

func (ci *Installer) TestCAInstallation() bool {
	return ci.IsCARootInstalled()
}

func (ci *Installer) ListCertificates() ([]string, error) {
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

func (ci *Installer) tryMkcertInPath() (string, string, error) {
	path, err := exec.LookPath("mkcert")
	if err != nil {
		return "", "", fmt.Errorf("mkcert not in PATH: %w", err)
	}

	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.generateWithMkcert(path, certFile, keyFile)
}

func (ci *Installer) generateWithMkcert(mkcertPath, certFile, keyFile string) (string, string, error) {
	ci.logger.Fields("mkcert_path", mkcertPath).Info("Using mkcert")

	args := []string{"-key-file", keyFile, "-cert-file", certFile}
	args = append(args, ci.certHosts...)

	cmd := exec.Command(mkcertPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("mkcert failed: %s", string(output))
	}

	if !ci.IsCARootInstalled() {
		ci.logger.Info("Attempting to install mkcert CA root")
		installCmd := exec.Command(mkcertPath, "-install")
		_ = installCmd.Run()
	}

	return certFile, keyFile, nil
}

func (ci *Installer) tryTruststore() (string, string, error) {
	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))
	return ci.tryTruststoreWithPaths(certFile, keyFile)
}

func (ci *Installer) tryTruststoreWithPaths(certFile, keyFile string) (string, string, error) {
	ml, err := truststore.NewLib()
	if err != nil {
		return "", "", fmt.Errorf("truststore init failed: %w", err)
	}

	if !ci.IsCARootInstalled() {
		_ = ml.Install()
	}

	cert, err := ml.MakeCert(ci.certHosts, ci.CertDir)
	if err != nil {
		return "", "", fmt.Errorf("truststore makecert failed: %w", err)
	}

	if cert.CertFile != certFile {
		_ = os.Rename(cert.CertFile, certFile)
	}
	if cert.KeyFile != keyFile {
		_ = os.Rename(cert.KeyFile, keyFile)
	}

	return certFile, keyFile, nil
}

func (ci *Installer) downloadAndUseMkcert() (string, string, error) {
	ci.logger.Info("Downloading mkcert from GitHub")

	mkcertPath, err := ci.downloadMkcert()
	if err != nil {
		return "", "", err
	}

	defer func() {
		_ = os.Remove(mkcertPath)
	}()

	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir, fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.generateWithMkcert(mkcertPath, certFile, keyFile)
}

func (ci *Installer) downloadMkcert() (string, error) {
	ci.logger.Info("Fetching latest mkcert release metadata")

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
	if mkcertArch == "amd64" {
		mkcertArch = "amd64"
	} else if mkcertArch == "386" {
		mkcertArch = "386"
	} else if mkcertArch == "arm64" {
		mkcertArch = "arm64"
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
		return "", fmt.Errorf("mkcert binary not found in release")
	}

	// Download checksum
	req, _ = http.NewRequest("GET", checksumURL, nil)
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	checksumData, _ := io.ReadAll(resp.Body)

	var expectedChecksum string
	for _, line := range strings.Split(string(checksumData), "\n") {
		if strings.Contains(line, binaryName) {
			expectedChecksum = strings.Fields(line)[0]
			break
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

func (ci *Installer) findExistingCerts(prefix string, port int) (certFile, keyFile string, found bool) {
	patterns := []struct {
		certPattern string
		keyPattern  string
	}{
		{fmt.Sprintf("%s.serve-cert.pem", prefix), fmt.Sprintf("%s.serve-key.pem", prefix)},
		{fmt.Sprintf("%s.pem", prefix), fmt.Sprintf("%s.key.pem", prefix)},
		{fmt.Sprintf("%s-%d-cert.pem", prefix, port), fmt.Sprintf("%s-%d-key.pem", prefix, port)},
		{"localhost.pem", "localhost.key.pem"},
	}

	for _, pattern := range patterns {
		certPath := filepath.Join(ci.CertDir, pattern.certPattern)
		keyPath := filepath.Join(ci.CertDir, pattern.keyPattern)

		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				if ci.validateCertificate(certPath, keyPath, ci.certHosts) {
					return certPath, keyPath, true
				}
			}
		}
	}
	return "", "", false
}

func (ci *Installer) validateCertificate(certFile, keyFile string, hosts []string) bool {
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
		ci.logger.Fields("file", certFile).Warn("Certificate expired")
		return false
	}

	for _, h := range hosts {
		host := h
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if err := leaf.VerifyHostname(host); err != nil {
			// Try wildcards loosely if VerifyHostname fails for localhost
			return false
		}
	}
	return true
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
