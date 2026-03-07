package tlss

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
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

func (s *Storage) safeName(domain string) string {
	return strings.ReplaceAll(domain, "*", "_wildcard_")
}

func (s *Storage) filenameKey(base string) string {
	if s.cipher != nil {
		return base + ".key.enc"
	}
	return base + ".key"
}

func (s *Storage) Save(domain string, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	base := filepath.Join(s.dir, s.safeName(domain))

	if err := os.WriteFile(base+".crt", certPEM, 0644); err != nil {
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

	return os.WriteFile(s.filenameKey(base), keyData, 0600)
}

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

func (s *Storage) Delete(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	base := filepath.Join(s.dir, s.safeName(domain))
	_ = os.Remove(base + ".crt")
	_ = os.Remove(base + ".key")
	_ = os.Remove(base + ".key.enc")
	return nil
}
