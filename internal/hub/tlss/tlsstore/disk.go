package tlsstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

type Disk struct {
	dataDir expect.Folder // For CA, System certs (persistent)
	certDir expect.Folder // For domain certs (custom, ACME, local)
	cipher  interface {
		Encrypt([]byte) ([]byte, error)
		Decrypt([]byte) ([]byte, error)
	}
	mu sync.Mutex
}

type DiskConfig struct {
	DataDir expect.Folder
	CertDir expect.Folder
	Cipher  interface {
		Encrypt([]byte) ([]byte, error)
		Decrypt([]byte) ([]byte, error)
	}
}

func NewDisk(cfg DiskConfig) (*Disk, error) {
	d := &Disk{
		dataDir: cfg.DataDir,
		certDir: cfg.CertDir,
		cipher:  cfg.Cipher,
	}
	// Create necessary directories if they exist
	if d.dataDir != "" {
		// Create issuer subdirectories for data dir (CA and System)
		for _, issuer := range []string{IssuerCA, IssuerSystem} {
			path := filepath.Join(d.dataDir.Path(), issuer)
			if err := os.MkdirAll(path, 0700); err != nil {
				return nil, fmt.Errorf("failed to create %s directory: %w", issuer, err)
			}
		}
	}

	if d.certDir != "" {
		// Create issuer subdirectories for cert dir (Custom, ACME, Local)
		for _, issuer := range []string{IssuerCustom, IssuerACME, IssuerLocal} {
			path := filepath.Join(d.certDir.FilePath(), issuer)
			if err := os.MkdirAll(path, 0700); err != nil {
				return nil, fmt.Errorf("failed to create %s directory: %w", issuer, err)
			}
		}
	}

	return d, nil
}

func (s *Disk) safeName(domain string) string {
	// Replace wildcard prefix for filesystem safety.
	safe := strings.ReplaceAll(domain, "*", "_wildcard_")
	// Belt-and-suspenders: strip path separators and dot-dot sequences that
	// might slip through upstream validation.  Order matters: replace slashes
	// first so that "../" becomes "..#", then replace any remaining "..".
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")
	safe = strings.ReplaceAll(safe, "..", "_")
	if safe == "" || safe == "." {
		safe = "_invalid_"
	}
	return safe
}

func (s *Disk) filenameKey(base string) string {
	if s.cipher != nil {
		return base + ".key.enc"
	}
	return base + ".key"
}

func (s *Disk) writeFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	tmpPath := targetPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, targetPath)
}

func (s *Disk) getBaseDir(issuer string) expect.Folder {
	// Determine preferred directory based on issuer type
	var preferredDir expect.Folder
	if issuer == IssuerCA || issuer == IssuerSystem {
		preferredDir = s.dataDir
	} else {
		preferredDir = s.certDir
	}

	// If preferred directory is configured, use it
	if preferredDir != "" {
		return preferredDir
	}

	// Fallback to the other directory if available
	if s.dataDir != "" {
		return s.dataDir
	}
	if s.certDir != "" {
		return s.certDir
	}

	return ""
}

func (s *Disk) Save(issuer, domain string, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject domain values that contain path traversal sequences.  This is a
	// defence-in-depth check; the primary gate is isValidSNI in manager.go.
	// safeName below will also strip separators, but filepath.Join resolves
	// ".." before safeName is applied, so we must catch it here first.
	if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
		return fmt.Errorf("tlsstore: domain %q contains illegal path characters", domain)
	}

	baseDir := s.getBaseDir(issuer)
	if baseDir == "" {
		return fmt.Errorf("no directory configured for issuer %s (needs DataDir or CertDir)", issuer)
	}

	issuerDir := filepath.Join(baseDir.Path(), issuer)
	if err := os.MkdirAll(issuerDir, 0700); err != nil {
		return fmt.Errorf("failed to create issuer directory: %w", err)
	}

	base := filepath.Join(issuerDir, s.safeName(domain))

	if len(certPEM) > 0 {
		if err := s.writeFileAtomic(base+".crt", certPEM, def.ConfigFilePerm); err != nil {
			return fmt.Errorf("failed to save certificate: %w", err)
		}
	}

	if len(keyPEM) > 0 {
		keyData := keyPEM
		if s.cipher != nil {
			var err error
			if keyData, err = s.cipher.Encrypt(keyPEM); err != nil {
				return fmt.Errorf("encryption failed: %w", err)
			}
		}
		if err := s.writeFileAtomic(s.filenameKey(base), keyData, 0600); err != nil {
			return fmt.Errorf("failed to save key: %w", err)
		}
	}

	return nil
}

func (s *Disk) loadKey(base string) ([]byte, error) {
	keyPath := s.filenameKey(base)

	// Handle encryption fallback
	if s.cipher != nil {
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			plainKeyPath := base + ".key"
			if _, err := os.Stat(plainKeyPath); err == nil {
				keyPath = plainKeyPath
			}
		}
	}

	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	if s.cipher != nil && strings.HasSuffix(keyPath, ".enc") {
		return s.cipher.Decrypt(rawKey)
	}

	return rawKey, nil
}

func (s *Disk) Load(domain string) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	safeDomain := s.safeName(domain)

	// Priority: custom > ACME > local (search in certDir first, then dataDir)
	for _, issuer := range []string{IssuerCustom, IssuerACME, IssuerLocal} {
		// Try certDir first
		if s.certDir != "" {
			base := filepath.Join(s.certDir.Path(), issuer, safeDomain)
			certPEM, certErr := os.ReadFile(base + ".crt")
			keyPEM, keyErr := s.loadKey(base)
			if certErr == nil && keyErr == nil {
				return certPEM, keyPEM, nil
			}
		}

		// Fallback to dataDir
		if s.dataDir != "" {
			base := s.dataDir.FilePath(issuer, safeDomain)
			certPEM, certErr := os.ReadFile(base + ".crt")
			keyPEM, keyErr := s.loadKey(base)
			if certErr == nil && keyErr == nil {
				return certPEM, keyPEM, nil
			}
		}
	}

	// Check CA and System (search in dataDir first, then certDir)
	for _, issuer := range []string{IssuerCA, IssuerSystem} {
		// Try dataDir first for CA/System
		if s.dataDir != "" {
			base := s.dataDir.FilePath(issuer, safeDomain)
			keyPEM, keyErr := s.loadKey(base)
			if keyErr == nil {
				certPEM, _ := os.ReadFile(base + ".crt")
				return certPEM, keyPEM, nil
			}
		}

		// Fallback to certDir
		if s.certDir != "" {
			base := s.certDir.FilePath(issuer, safeDomain)
			keyPEM, keyErr := s.loadKey(base)
			if keyErr == nil {
				certPEM, _ := os.ReadFile(base + ".crt")
				return certPEM, keyPEM, nil
			}
		}
	}

	return nil, nil, ErrCertNotFound
}

func (s *Disk) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	domainMap := make(map[string]bool)

	// Function to scan a directory for certificates
	scanDir := func(baseDir string) {
		if baseDir == "" {
			return
		}
		for _, issuer := range []string{IssuerCustom, IssuerACME, IssuerLocal} {
			issuerPath := filepath.Join(baseDir, issuer)
			entries, err := os.ReadDir(issuerPath)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".crt") {
					name := strings.TrimSuffix(e.Name(), ".crt")
					name = strings.ReplaceAll(name, "_wildcard_", "*")
					domainMap[name] = true
				}
			}
		}
	}

	// Scan both directories
	scanDir(s.certDir.Path())
	scanDir(s.dataDir.Path())

	domains := make([]string, 0, len(domainMap))
	for domain := range domainMap {
		domains = append(domains, domain)
	}
	return domains, nil
}

func (s *Disk) Delete(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	safeDomain := s.safeName(domain)

	// Delete from both directories
	for _, baseDir := range []string{s.certDir.Path(), s.dataDir.Path()} {
		if baseDir == "" {
			continue
		}
		for _, issuer := range []string{IssuerCustom, IssuerACME, IssuerLocal, IssuerCA, IssuerSystem} {
			base := filepath.Join(baseDir, issuer, safeDomain)
			_ = os.Remove(base + ".crt")
			_ = os.Remove(base + ".key")
			_ = os.Remove(base + ".key.enc")
		}
	}

	return nil
}

func (s *Disk) CertDir() expect.Folder {
	return s.certDir
}
