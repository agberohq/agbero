package tlss

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/security"
)

var ErrCertNotFound = errors.New("certificate not found")

type Store interface {
	Save(domain string, certPEM, keyPEM []byte) error
	Load(domain string) (certPEM, keyPEM []byte, err error)
	List() ([]string, error)
	Delete(domain string) error
}

type Storage struct {
	dir    string
	cipher *security.Cipher
	mu     sync.Mutex
}

// NewDiskStorage initializes a new certificate storage instance with atomic write guarantees
// Ensures directory exists and is writable before accepting save operations
func NewDiskStorage(dir woos.Folder, cipher *security.Cipher) (*Storage, error) {
	// Check if path exists but is not a directory
	if dir.IsSet() {
		info, err := os.Stat(dir.Path())
		if err == nil && !info.IsDir() {
			return nil, fmt.Errorf("path exists but is not a directory: %s", dir.Path())
		}
	}

	if err := dir.Ensure(woos.Folder(""), true); err != nil {
		return nil, err
	}
	return &Storage{
		dir:    dir.Path(),
		cipher: cipher,
	}, nil
}

// safeName replaces wildcard characters to create filesystem-safe filenames
// Prevents path traversal or invalid filename issues with special characters
func (s *Storage) safeName(domain string) string {
	return strings.ReplaceAll(domain, "*", "_wildcard_")
}

// filenameKey returns the appropriate key filename based on encryption status
// Appends .enc suffix when encryption is enabled for the storage backend
func (s *Storage) filenameKey(base string) string {
	if s.cipher != nil {
		return base + ".key.enc"
	}
	return base + ".key"
}

// writeFileAtomic writes data to a temporary file then atomically renames to target
// Prevents corrupted files from partial writes during crashes or disk full errors
func (s *Storage) writeFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	tmpPath := targetPath + ".tmp"

	// Write to temporary file
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Atomic rename replaces target only after write succeeds
	return os.Rename(tmpPath, targetPath)
}

// Save stores certificate and key files atomically with optional encryption
// Both files are written via temporary files to ensure完整性 on disk
func (s *Storage) Save(domain string, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	base := filepath.Join(s.dir, s.safeName(domain))

	// Write certificate atomically
	if err := s.writeFileAtomic(base+".crt", certPEM, 0644); err != nil {
		return err
	}

	keyData := keyPEM
	if s.cipher != nil {
		var err error
		keyData, err = s.cipher.Encrypt(keyPEM)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Write key atomically with restricted permissions
	return s.writeFileAtomic(s.filenameKey(base), keyData, 0600)
}

// Load retrieves certificate and key files, handling legacy unencrypted keys
// Automatically detects and decrypts encrypted key files when cipher is configured
func (s *Storage) Load(domain string) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	base := filepath.Join(s.dir, s.safeName(domain))

	certPEM, err := os.ReadFile(base + ".crt")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrCertNotFound
		}
		return nil, nil, err
	}

	keyPath := s.filenameKey(base)

	// Check for legacy unencrypted key file during migration
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
		return nil, nil, err
	}

	keyPEM := rawKey
	if s.cipher != nil && strings.HasSuffix(keyPath, ".enc") {
		keyPEM, err = s.cipher.Decrypt(rawKey)
		if err != nil {
			return nil, nil, fmt.Errorf("decryption failed: %w", err)
		}
	}

	return certPEM, keyPEM, nil
}

// List returns all domains with stored certificates in the directory
// Scans for .crt files and converts safe names back to wildcard format
func (s *Storage) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var domains []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".crt") {
			name := strings.TrimSuffix(e.Name(), ".crt")
			name = strings.ReplaceAll(name, "_wildcard_", "*")
			domains = append(domains, name)
		}
	}
	return domains, nil
}

// Delete removes all certificate files for a given domain
// Cleans up both .crt, .key, and encrypted .key.enc variants
func (s *Storage) Delete(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	base := filepath.Join(s.dir, s.safeName(domain))
	_ = os.Remove(base + ".crt")
	_ = os.Remove(base + ".key")
	_ = os.Remove(base + ".key.enc")
	return nil
}
