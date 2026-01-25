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
	CertDir   woos.Folder // ONLY for leaf certs created by agbero (not mkcert CA root)
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

	// NOTE: This directory is NOT mkcert CAROOT. It is only agbero's cert storage.
	if err := dir.Ensure(woos.Folder(""), true); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	ci.CertDir = dir
	if ci.logger != nil {
		ci.logger.Fields("dir", dir).Info("set certificate storage directory")
	}
	return nil
}

func (ci *Installer) SetHosts(hosts []string, port int) {
	ci.certHosts = hosts
	ci.port = port
}

// EnsureLocalhostCert ensures a leaf certificate for the current host set.
// It prefers mkcert if available (because it's dev-friendly), otherwise falls back to truststore,
// otherwise downloads mkcert (last resort).
//
// IMPORTANT:
// - We do NOT redirect mkcert's CAROOT into CertDir.
// - CertDir is only where we store the resulting LEAF cert/key files.
func (ci *Installer) EnsureLocalhostCert() (certFile, keyFile string, err error) {
	prefix := ci.certPrefix()

	if cert, key, found := ci.findExistingCerts(prefix); found {
		if ci.logger != nil {
			ci.logger.Fields("cert", cert, "key", key).Info("using existing certificates")
		}
		return cert, key, nil
	}

	certFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile = filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	if ci.logger != nil {
		ci.logger.Fields("hosts", ci.certHosts, "cert", certFile).Info("generating localhost certificates")
	}

	// Ensure directory exists for leaf outputs.
	if err := ci.CertDir.Ensure(woos.Folder(""), true); err != nil {
		return "", "", fmt.Errorf("ensure cert dir: %w", err)
	}

	methods := []func() (string, string, error){
		ci.tryMkcertInPath,
		ci.tryTruststore,
		ci.downloadAndUseMkcert,
	}

	var lastErr error
	for _, method := range methods {
		c, k, e := method()
		if e == nil {
			if ci.logger != nil {
				ci.logger.Fields("cert", c).Info("successfully generated certificates")
			}
			return c, k, nil
		}
		lastErr = e
		if ci.logger != nil {
			ci.logger.Fields("err", e).Debug("cert generation method failed; trying next")
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unknown error")
	}
	return "", "", fmt.Errorf("all certificate generation methods failed: %w", lastErr)
}

// InstallCARootIfNeeded installs mkcert/truststore root into OS trust store.
// This is only about trusting the CA, not where leaf cert files live.
func (ci *Installer) InstallCARootIfNeeded() error {
	// Best effort: if already trusted, stop.
	if IsCARootTrusted() {
		return nil
	}

	if ci.logger != nil {
		ci.logger.Info("CA root not trusted; attempting installation")
	}

	// 1) truststore library (preferred for non-interactive installs if it works on the platform)
	if ml, err := truststore.NewLib(); err == nil {
		if err := ml.Install(); err == nil {
			if ci.logger != nil {
				ci.logger.Info("CA installed successfully via truststore")
			}
			return nil
		}
		if ci.logger != nil {
			ci.logger.Fields("err", err).Warn("truststore install failed; will try mkcert")
		}
	}

	// 2) mkcert binary (fallback)
	mkcertPath, err := exec.LookPath("mkcert")
	if err != nil {
		return fmt.Errorf("mkcert not found and truststore failed; cannot install CA root")
	}

	// Make mkcert environment stable (HOME/USER/LOGNAME/CAROOT default).
	// We DO NOT point CAROOT to ci.CertDir.
	if os.Getenv("CAROOT") == "" {
		if caroot, err := MkcertDefaultCAROOT(mkcertPath); err == nil {
			_ = os.Setenv("CAROOT", caroot)
		}
	}

	cmd := exec.Command(mkcertPath, "-install")
	cmd.Env = mkcertEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkcert -install failed: %s", strings.TrimSpace(string(out)))
	}

	if ci.logger != nil {
		ci.logger.Info("CA installed successfully via mkcert")
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

	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	return ci.generateWithMkcert(mkcertPath, certFile, keyFile)
}

func (ci *Installer) generateWithMkcert(mkcertPath, certFile, keyFile string) (string, string, error) {
	if ci.logger != nil {
		ci.logger.Fields("mkcert_path", mkcertPath).Info("using mkcert for leaf cert")
	}

	args := []string{"-key-file", keyFile, "-cert-file", certFile}
	args = append(args, ci.certHosts...)

	cmd := exec.Command(mkcertPath, args...)
	cmd.Env = mkcertEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("mkcert failed: %s", strings.TrimSpace(string(out)))
	}

	// If CA isn't trusted, try installing it (best-effort; do not block leaf generation success).
	if !IsCARootTrusted() {
		installCmd := exec.Command(mkcertPath, "-install")
		installCmd.Env = mkcertEnv()
		_ = installCmd.Run()
	}

	return certFile, keyFile, nil
}

func (ci *Installer) tryTruststore() (string, string, error) {
	prefix := ci.certPrefix()
	certFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port))
	keyFile := filepath.Join(ci.CertDir.Path(), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port))

	ml, err := truststore.NewLib()
	if err != nil {
		return "", "", fmt.Errorf("truststore init failed: %w", err)
	}

	// Best-effort install (may require elevated permissions).
	if !IsCARootTrusted() {
		_ = ml.Install()
	}

	cert, err := ml.MakeCert(ci.certHosts, ci.CertDir.Path())
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
	if ci.logger != nil {
		ci.logger.Info("downloading mkcert from GitHub")
	}

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
	default:
		// best-effort
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

	var expectedChecksum string
	if checksumURL != "" {
		req, _ = http.NewRequest("GET", checksumURL, nil)
		resp, err = client.Do(req)
		if err != nil {
			return "", err
		}
		checksumData, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		for _, line := range strings.Split(string(checksumData), "\n") {
			if strings.Contains(line, binaryName) {
				expectedChecksum = strings.Fields(line)[0]
				break
			}
		}
	}

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

	if expectedChecksum != "" {
		calculated := hex.EncodeToString(hash.Sum(nil))
		if !strings.EqualFold(calculated, expectedChecksum) {
			return "", fmt.Errorf("checksum mismatch")
		}
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
		{fmt.Sprintf("%s-%d-cert.pem", prefix, ci.port), fmt.Sprintf("%s-%d-key.pem", prefix, ci.port)},
		{"localhost.pem", "localhost.key.pem"},
	}

	for _, p := range patterns {
		certPath := filepath.Join(ci.CertDir.Path(), p.certPattern)
		keyPath := filepath.Join(ci.CertDir.Path(), p.keyPattern)

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
