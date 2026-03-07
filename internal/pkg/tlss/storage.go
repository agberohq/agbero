package tlss

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
	"github.com/olekukonko/errors"
)

var (
	ErrCertNotFound = errors.New("certificate not found")
)

// Storage defines how certificates are persisted.
// This abstraction allows swapping Disk for Gossip/Memory in Phase 3.
type Storage interface {
	// Save persists a certificate and its private key.
	Save(domain string, certPEM, keyPEM []byte) error

	// Load retrieves a certificate and private key.
	Load(domain string) (certPEM, keyPEM []byte, err error)

	// List returns all domains currently stored.
	List() ([]string, error)

	// Delete removes a certificate.
	Delete(domain string) error
}

// DiskStorage implements Storage using the local filesystem.
// It supports encryption at rest for private keys.
type DiskStorage struct {
	baseDir string
	cipher  *security.Cipher
	mu      sync.RWMutex
}

func NewDiskStorage(dir woos.Folder, secretKey string) (*DiskStorage, error) {
	if !dir.IsSet() {
		return nil, woos.ErrDataDirNotSet
	}

	if err := dir.Ensure(woos.Folder(""), true); err != nil {
		return nil, err
	}

	ds := &DiskStorage{
		baseDir: dir.Path(),
	}

	if secretKey != "" {
		c, err := security.NewCipher(secretKey)
		if err != nil {
			return nil, err
		}
		ds.cipher = c
	}

	return ds, nil
}

func (s *DiskStorage) Save(domain string, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	safeDomain := safeFileName(domain)
	certPath := filepath.Join(s.baseDir, safeDomain+".crt")
	keyPath := filepath.Join(s.baseDir, safeDomain+".key")

	// Encrypt key if cipher is available
	keyData := keyPEM
	if s.cipher != nil {
		var err error
		keyData, err = s.cipher.Encrypt(keyPEM)
		if err != nil {
			return err
		}
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return err
	}

	return nil
}

func (s *DiskStorage) Load(domain string) ([]byte, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	safeDomain := safeFileName(domain)
	certPath := filepath.Join(s.baseDir, safeDomain+".crt")
	keyPath := filepath.Join(s.baseDir, safeDomain+".key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrCertNotFound
		}
		return nil, nil, err
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt if cipher is available
	if s.cipher != nil {
		decrypted, err := s.cipher.Decrypt(keyData)
		if err != nil {
			// Fallback: try reading as plaintext in case encryption was enabled recently
			// and this is an old legacy file (PEM usually starts with --)
			if len(keyData) > 0 && keyData[0] == '-' {
				return certPEM, keyData, nil
			}
			return nil, nil, errors.Newf("failed to decrypt key for %s: %w", domain, err)
		}
		keyData = decrypted
	}

	return certPEM, keyData, nil
}

func (s *DiskStorage) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, err
	}

	var domains []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".crt") {
			domain := strings.TrimSuffix(e.Name(), ".crt")
			// Rudimentary un-safeFileName (mostly just for simple cases)
			// In production, we might store metadata mapping file ID to Domain
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

func (s *DiskStorage) Delete(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	safeDomain := safeFileName(domain)
	_ = os.Remove(filepath.Join(s.baseDir, safeDomain+".crt"))
	_ = os.Remove(filepath.Join(s.baseDir, safeDomain+".key"))
	return nil
}

func safeFileName(domain string) string {
	return strings.ReplaceAll(domain, "*", "_wildcard_")
}
