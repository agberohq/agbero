// Package security provides a secure, encrypted secret store backed by BoltDB.
// It supports passphrase-based encryption, optional Shamir's Secret Sharing for M-of-N
// admin access, automatic locking, key rotation, and comprehensive audit logging.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

var (
	// ErrStoreLocked indicates the secret store is locked and requires unlocking.
	ErrStoreLocked = errors.New("secret store is locked")
	// ErrInvalidPassphrase indicates the provided passphrase was incorrect.
	ErrInvalidPassphrase = errors.New("invalid passphrase")
	// ErrKeyNotFound indicates the requested secret key does not exist.
	ErrKeyNotFound = errors.New("secret key not found")
	// ErrAlreadyUnlocked indicates the store is already unlocked.
	ErrAlreadyUnlocked = errors.New("store already unlocked")
	// ErrInvalidConfig indicates the store configuration is invalid.
	ErrInvalidConfig = errors.New("invalid store configuration")
	// ErrShamirThreshold indicates insufficient shares for Shamir reconstruction.
	ErrShamirThreshold = errors.New("insufficient shares for Shamir reconstruction")
	// ErrShamirDisabled indicates Shamir operations were requested but not enabled.
	ErrShamirDisabled = errors.New("Shamir secret sharing is not enabled")
)

// Store manages encrypted secrets in BoltDB with optional passphrase protection.
// It provides thread-safe access to encrypted data with automatic locking capabilities.
type Store struct {
	db        *bbolt.DB
	masterKey []byte // Only in memory when unlocked, never persisted
	salt      []byte
	locked    bool
	mu        sync.RWMutex

	config StoreConfig

	// Audit logging callback: func(action, key string, success bool, duration time.Duration)
	auditFn func(string, string, bool, time.Duration)

	// Activity tracking for auto-lock
	lastActivity int64
	autoLockStop chan struct{}

	// Shamir's Secret Sharing configuration (only used if EnableShamir=true)
	shamirThreshold int
	shamirTotal     int
	shamirEnabled   bool

	shamir *Shamir
}

// StoreConfig contains configuration parameters for the secret store.
type StoreConfig struct {
	// DBPath is the file path for the BoltDB database.
	DBPath string
	// ScryptN is the CPU/memory cost parameter (default: 32768).
	ScryptN int
	// ScryptR is the block size parameter (default: 8).
	ScryptR int
	// ScryptP is the parallelism parameter (default: 1).
	ScryptP int
	// KeyLen is the derived key length in bytes (default: 32).
	KeyLen int
	// AutoLockInterval is the duration after which the store auto-locks (0 = disabled).
	AutoLockInterval time.Duration
	// EnableAudit enables audit logging of all secret access.
	EnableAudit bool
	// EnableShamir enables Shamir's Secret Sharing for M-of-N admin access.
	// When false, the store uses simple single-passphrase unlocking.
	EnableShamir bool
}

// Secret represents an encrypted secret with metadata.
type Secret struct {
	// Ciphertext is the XChaCha20-Poly1305 encrypted value.
	Ciphertext []byte `json:"ct"`
	// Nonce is not stored separately - it's prepended to ciphertext (24 bytes for XChaCha20).
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the secret was last modified.
	UpdatedAt time.Time `json:"updated_at"`
	// AccessCount tracks how many times the secret has been accessed.
	AccessCount int `json:"access_count"`
	// LastAccess is when the secret was last retrieved.
	LastAccess time.Time `json:"last_access,omitempty"`
	// Version tracks key rotation (incremented on each update).
	Version int `json:"version"`
}

// NewStore creates a new secret store with the given configuration.
// If the database doesn't exist, it will be created.
func NewStore(config StoreConfig) (*Store, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	// Ensure directory exists
	dir := filepath.Dir(config.DBPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create secrets directory: %w", err)
	}

	// Open BoltDB with restricted permissions
	db, err := bbolt.Open(config.DBPath, 0600, &bbolt.Options{
		Timeout:      5 * time.Second,
		NoGrowSync:   false,
		FreelistType: bbolt.FreelistMapType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open secrets database: %w", err)
	}

	store := &Store{
		db:              db,
		locked:          true, // Start locked
		config:          config,
		autoLockStop:    make(chan struct{}),
		shamirEnabled:   config.EnableShamir,
		shamirThreshold: 0,
		shamirTotal:     0,
		shamir:          NewShamir(),
	}

	// Initialize buckets
	if err := store.initBuckets(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize buckets: %w", err)
	}

	// Load Shamir metadata if enabled and exists
	if config.EnableShamir {
		if err := store.loadShamirMetadata(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to load shamir metadata: %w", err)
		}
	}

	return store, nil
}

// OpenExisting opens an existing secret store without creating a new one.
func OpenExisting(config StoreConfig) (*Store, error) {
	if _, err := os.Stat(config.DBPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("secret store does not exist at %s", config.DBPath)
	}
	return NewStore(config)
}

// validateConfig ensures configuration parameters are valid.
func validateConfig(config *StoreConfig) error {
	if config.DBPath == "" {
		return fmt.Errorf("%w: DBPath is required", ErrInvalidConfig)
	}
	if config.ScryptN == 0 {
		config.ScryptN = 32768
	}
	if config.ScryptR == 0 {
		config.ScryptR = 8
	}
	if config.ScryptP == 0 {
		config.ScryptP = 1
	}
	if config.KeyLen == 0 {
		config.KeyLen = 32
	}
	if config.AutoLockInterval < 0 {
		return fmt.Errorf("%w: AutoLockInterval cannot be negative", ErrInvalidConfig)
	}
	return nil
}

// initBuckets creates required BoltDB buckets if they don't exist.
func (s *Store) initBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("secrets"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("metadata"))
		return err
	})
}

// SetAuditFunc sets the audit logging callback function.
func (s *Store) SetAuditFunc(fn func(action, key string, success bool, duration time.Duration)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditFn = fn
}

// Unlock derives the master key from passphrase using scrypt and unlocks the store.
// This must be called before any secret operations.
// For Shamir-enabled stores, use UnlockShamir instead.
func (s *Store) Unlock(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If Shamir is enabled in config, single-passphrase unlock is disabled
	if s.config.EnableShamir {
		return ErrShamirDisabled
	}

	if !s.locked {
		return ErrAlreadyUnlocked
	}

	// If Shamir is enabled, single-passphrase unlock is disabled
	if s.shamirEnabled && s.shamirThreshold > 0 {
		return ErrShamirDisabled
	}

	start := time.Now()

	// Load or create salt
	salt, err := s.getOrCreateSalt()
	if err != nil {
		return fmt.Errorf("failed to get salt: %w", err)
	}

	// Derive key using scrypt (memory-hard, suitable for passphrases)
	key, err := scrypt.Key(
		[]byte(passphrase),
		salt,
		s.config.ScryptN,
		s.config.ScryptR,
		s.config.ScryptP,
		s.config.KeyLen,
	)
	if err != nil {
		return fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	// Verify key against stored verification hash
	if err := s.verifyMasterKey(key); err != nil {
		// Perform dummy comparison to prevent timing attacks
		dummyKey := make([]byte, len(key))
		rand.Read(dummyKey)
		subtle.ConstantTimeCompare(key, dummyKey)
		secureZero(key)
		return ErrInvalidPassphrase
	}

	s.masterKey = key
	s.salt = salt
	s.locked = false
	s.updateActivity()

	// Start auto-lock timer if configured
	if s.config.AutoLockInterval > 0 {
		go s.autoLockRoutine()
	}

	s.audit("unlock", "", true, time.Since(start))
	return nil
}

// UnlockShamir reconstructs the master key from M-of-N shares using Shamir's Secret Sharing.
// Requires Shamir to be enabled in StoreConfig.
func (s *Store) UnlockShamir(encryptedShares [][]byte, passphrases []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.locked {
		return ErrAlreadyUnlocked
	}

	if !s.shamirEnabled {
		return ErrShamirDisabled
	}

	if len(encryptedShares) != len(passphrases) {
		return fmt.Errorf("mismatched shares and passphrases: %d shares, %d passphrases", len(encryptedShares), len(passphrases))
	}

	if len(encryptedShares) < s.shamirThreshold {
		return ErrShamirThreshold
	}

	start := time.Now()

	// Decrypt shares using passphrases
	decryptedShares := make([]*Share, len(encryptedShares))
	for i, encShare := range encryptedShares {
		shareBytes, err := s.DecryptShare(encShare, passphrases[i])
		if err != nil {
			return fmt.Errorf("failed to decrypt share %d: %w", i, err)
		}
		share, err := s.shamir.DeserializeShare(shareBytes)
		if err != nil {
			secureZero(shareBytes)
			return fmt.Errorf("failed to deserialize share %d: %w", i, err)
		}
		decryptedShares[i] = share
		secureZero(shareBytes)
	}

	// Combine shares to reconstruct master key
	masterKey, err := s.shamir.Combine(decryptedShares)
	if err != nil {
		return fmt.Errorf("shamir combine failed: %w", err)
	}

	if len(masterKey) != s.config.KeyLen {
		return fmt.Errorf("reconstructed key has wrong length: got %d, want %d", len(masterKey), s.config.KeyLen)
	}

	s.masterKey = masterKey
	s.locked = false
	s.updateActivity()

	if s.config.AutoLockInterval > 0 {
		go s.autoLockRoutine()
	}

	s.audit("unlock_shamir", "", true, time.Since(start))
	return nil
}

// InitializeShamir sets up M-of-N secret sharing for the master key.
// It encrypts the store with a new random key and returns encrypted shares for each admin.
// Requires EnableShamir=true in StoreConfig.
func (s *Store) InitializeShamir(threshold, total int, adminPassphrases []string) ([][]byte, error) {
	if !s.config.EnableShamir {
		return nil, ErrShamirDisabled
	}

	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, fmt.Errorf("invalid threshold/total: need 0 < threshold <= total")
	}
	if len(adminPassphrases) != total {
		return nil, fmt.Errorf("need exactly %d passphrases for %d admins", total, total)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate random master key
	masterKey := make([]byte, s.config.KeyLen)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Split into shares using Shamir's Secret Sharing
	shares, err := s.shamir.Split(masterKey, total, threshold)
	if err != nil {
		secureZero(masterKey)
		return nil, fmt.Errorf("shamir split failed: %w", err)
	}

	// Encrypt each share with its admin's passphrase
	encryptedShares := make([][]byte, total)
	for i, passphrase := range adminPassphrases {
		// Serialize share to bytes
		shareBytes := s.shamir.SerializeShare(shares[i])

		// Derive key from admin passphrase using Argon2id (stronger than scrypt for this use)
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			secureZero(masterKey)
			return nil, err
		}

		// Argon2id: time=3, memory=64MB, parallelism=4
		key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)

		// Encrypt share with XChaCha20-Poly1305
		cipher, err := NewCipherFromKey(key)
		if err != nil {
			secureZero(key)
			secureZero(masterKey)
			return nil, err
		}

		ciphertext, err := cipher.Encrypt(shareBytes)
		if err != nil {
			secureZero(key)
			secureZero(shareBytes)
			secureZero(masterKey)
			return nil, err
		}

		// Store: version(1) + salt(16) + ciphertext
		encryptedShares[i] = make([]byte, 0, 1+len(salt)+len(ciphertext))
		encryptedShares[i] = append(encryptedShares[i], 1)
		encryptedShares[i] = append(encryptedShares[i], salt...)
		encryptedShares[i] = append(encryptedShares[i], ciphertext...)

		// Clean up
		secureZero(key)
		secureZero(shareBytes)
	}

	// Store Shamir configuration
	s.shamirThreshold = threshold
	s.shamirTotal = total
	s.shamirEnabled = true

	// Save metadata about Shamir configuration
	if err := s.saveShamirMetadata(threshold, total); err != nil {
		secureZero(masterKey)
		return nil, fmt.Errorf("failed to save shamir metadata: %w", err)
	}

	// Store master key verification hash
	if err := s.storeVerificationHash(masterKey); err != nil {
		secureZero(masterKey)
		return nil, fmt.Errorf("failed to store verification hash: %w", err)
	}

	// Re-encrypt all existing secrets with new master key only if we have an old key
	// (i.e., store was previously unlocked). If locked, there's nothing to re-encrypt.
	if len(s.masterKey) > 0 {
		if err := s.reencryptAllWithKey(masterKey, s.masterKey); err != nil {
			secureZero(masterKey)
			return nil, fmt.Errorf("failed to reencrypt secrets: %w", err)
		}
	}

	s.masterKey = masterKey
	s.locked = false
	s.lastActivity = time.Now().Unix()

	return encryptedShares, nil
}

// DecryptShare decrypts an admin's share using their passphrase.
func (s *Store) DecryptShare(encryptedShare []byte, passphrase string) ([]byte, error) {
	if len(encryptedShare) < 18 {
		return nil, errors.New("invalid encrypted share format")
	}

	version := encryptedShare[0]
	if version != 1 {
		return nil, fmt.Errorf("unsupported share version: %d", version)
	}

	salt := encryptedShare[1:17]
	ciphertext := encryptedShare[17:]

	// Derive key
	key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)

	// Decrypt using XChaCha20-Poly1305
	cipher, err := NewCipherFromKey(key)
	if err != nil {
		secureZero(key)
		return nil, err
	}

	plaintext, err := cipher.Decrypt(ciphertext)

	secureZero(key)

	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	return plaintext, nil
}

// Lock clears the master key from memory and secures the store.
func (s *Store) Lock() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return nil
	}

	if s.autoLockStop != nil {
		close(s.autoLockStop)
		s.autoLockStop = make(chan struct{})
	}

	if s.masterKey != nil {
		secureZero(s.masterKey)
		s.masterKey = nil
	}

	s.locked = true
	s.audit("lock", "", true, 0)
	return nil
}

// IsLocked returns true if the store is currently locked.
func (s *Store) IsLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.locked
}

// IsShamirEnabled returns true if Shamir secret sharing is configured.
func (s *Store) IsShamirEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.EnableShamir || s.shamirThreshold > 0
}

// GetShamirConfig returns the current Shamir configuration (threshold, total).
// Returns (0, 0) if Shamir is not enabled.
func (s *Store) GetShamirConfig() (threshold, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.shamirThreshold, s.shamirTotal
}

// Get retrieves and decrypts a secret by key.
func (s *Store) Get(key string) (string, error) {
	start := time.Now()

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		s.audit("get", key, false, time.Since(start))
		return "", ErrStoreLocked
	}
	masterKey := make([]byte, len(s.masterKey))
	copy(masterKey, s.masterKey)
	s.updateActivity()
	s.mu.RUnlock()

	var secret Secret
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return ErrKeyNotFound
		}

		data := b.Get([]byte(key))
		if data == nil {
			return ErrKeyNotFound
		}

		return json.Unmarshal(data, &secret)
	})

	if err != nil {
		secureZero(masterKey)
		s.audit("get", key, false, time.Since(start))
		return "", err
	}

	plaintext, err := s.decrypt(secret.Ciphertext, masterKey)
	secureZero(masterKey)

	if err != nil {
		s.audit("get", key, false, time.Since(start))
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	// Update access metadata asynchronously
	go s.incrementAccessCount(key)

	s.audit("get", key, true, time.Since(start))
	return string(plaintext), nil
}

// GetBytes retrieves and decrypts a secret as bytes (for binary data).
func (s *Store) GetBytes(key string) ([]byte, error) {
	val, err := s.Get(key)
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

// Set encrypts and stores a secret.
func (s *Store) Set(key, value string) error {
	return s.SetBytes(key, []byte(value))
}

// SetBytes encrypts and stores binary data.
func (s *Store) SetBytes(key string, value []byte) error {
	start := time.Now()

	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		s.audit("set", key, false, time.Since(start))
		return ErrStoreLocked
	}
	masterKey := make([]byte, len(s.masterKey))
	copy(masterKey, s.masterKey)
	s.updateActivity()
	s.mu.RUnlock()

	defer secureZero(masterKey)

	// Check if key exists to preserve creation time
	var existing Secret
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return nil
		}
		data := b.Get([]byte(key))
		if data != nil {
			json.Unmarshal(data, &existing)
		}
		return nil
	})

	ciphertext, err := s.encrypt(value, masterKey)
	if err != nil {
		s.audit("set", key, false, time.Since(start))
		return fmt.Errorf("encryption failed: %w", err)
	}

	now := time.Now()
	secret := Secret{
		Ciphertext:  ciphertext,
		CreatedAt:   existing.CreatedAt,
		UpdatedAt:   now,
		AccessCount: existing.AccessCount,
		Version:     existing.Version + 1,
	}

	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = now
		secret.Version = 1
	}

	err = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return errors.New("secrets bucket not found")
		}

		data, err := json.Marshal(secret)
		if err != nil {
			return err
		}

		return b.Put([]byte(key), data)
	})

	if err != nil {
		s.audit("set", key, false, time.Since(start))
		return err
	}

	s.audit("set", key, true, time.Since(start))
	return nil
}

// Delete removes a secret from the store.
func (s *Store) Delete(key string) error {
	start := time.Now()
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		s.audit("delete", key, false, time.Since(start))
		return ErrStoreLocked
	}
	s.updateActivity()
	s.mu.RUnlock()

	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return ErrKeyNotFound
		}
		// Check if key exists before deleting
		if b.Get([]byte(key)) == nil {
			return ErrKeyNotFound
		}
		return b.Delete([]byte(key))
	})
	success := err == nil
	s.audit("delete", key, success, time.Since(start))
	return err
}

// List returns all secret keys (not values).
func (s *Store) List() ([]string, error) {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return nil, ErrStoreLocked
	}
	s.mu.RUnlock()

	var keys []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})

	return keys, err
}

// Exists checks if a secret key exists.
func (s *Store) Exists(key string) (bool, error) {
	s.mu.RLock()
	if s.locked {
		s.mu.RUnlock()
		return false, ErrStoreLocked
	}
	s.mu.RUnlock()

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return ErrKeyNotFound
		}
		if b.Get([]byte(key)) == nil {
			return ErrKeyNotFound
		}
		return nil
	})

	if err == ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Rotate re-encrypts all secrets with a new master key derived from newPassphrase.
// This should be called periodically or when an admin leaves.
// For Shamir-enabled stores, use RotateShamir instead.
func (s *Store) Rotate(newPassphrase string) error {
	if s.config.EnableShamir {
		return ErrShamirDisabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return ErrStoreLocked
	}

	start := time.Now()

	// Generate new salt
	newSalt := make([]byte, 16)
	if _, err := rand.Read(newSalt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive new master key
	newKey, err := scrypt.Key(
		[]byte(newPassphrase),
		newSalt,
		s.config.ScryptN,
		s.config.ScryptR,
		s.config.ScryptP,
		s.config.KeyLen,
	)
	if err != nil {
		return fmt.Errorf("scrypt failed: %w", err)
	}

	oldKey := make([]byte, len(s.masterKey))
	copy(oldKey, s.masterKey)

	// Re-encrypt all secrets
	if err := s.reencryptAllWithKey(newKey, oldKey); err != nil {
		secureZero(newKey)
		secureZero(oldKey)
		return err
	}
	secureZero(oldKey)

	// Update verification hash
	if err := s.storeVerificationHash(newKey); err != nil {
		secureZero(newKey)
		return err
	}

	// Update salt
	if err := s.storeSalt(newSalt); err != nil {
		secureZero(newKey)
		return err
	}

	// Clean up old key
	secureZero(s.masterKey)

	s.masterKey = newKey
	s.salt = newSalt

	s.audit("rotate", "", true, time.Since(start))
	return nil
}

// RotateShamir re-encrypts all secrets with a new master key and regenerates Shamir shares.
// Requires Shamir to be enabled.
func (s *Store) RotateShamir(newAdminPassphrases []string) ([][]byte, error) {
	if !s.shamirEnabled {
		return nil, ErrShamirDisabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.locked {
		return nil, ErrStoreLocked
	}

	if len(newAdminPassphrases) != s.shamirTotal {
		return nil, fmt.Errorf("need exactly %d passphrases for %d admins", s.shamirTotal, s.shamirTotal)
	}

	start := time.Now()

	// Generate new random master key
	newMasterKey := make([]byte, s.config.KeyLen)
	if _, err := rand.Read(newMasterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Split into new shares
	shares, err := s.shamir.Split(newMasterKey, s.shamirTotal, s.shamirThreshold)
	if err != nil {
		secureZero(newMasterKey)
		return nil, fmt.Errorf("shamir split failed: %w", err)
	}

	// Encrypt each new share
	encryptedShares := make([][]byte, s.shamirTotal)
	for i, passphrase := range newAdminPassphrases {
		shareBytes := s.shamir.SerializeShare(shares[i])

		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			secureZero(newMasterKey)
			return nil, err
		}

		key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
		cipher, err := NewCipherFromKey(key)
		if err != nil {
			secureZero(key)
			secureZero(newMasterKey)
			return nil, err
		}

		ciphertext, err := cipher.Encrypt(shareBytes)
		if err != nil {
			secureZero(key)
			secureZero(shareBytes)
			secureZero(newMasterKey)
			return nil, err
		}

		encryptedShares[i] = make([]byte, 0, 1+len(salt)+len(ciphertext))
		encryptedShares[i] = append(encryptedShares[i], 1)
		encryptedShares[i] = append(encryptedShares[i], salt...)
		encryptedShares[i] = append(encryptedShares[i], ciphertext...)

		secureZero(key)
		secureZero(shareBytes)
	}

	// Preserve old key for re-encryption
	oldKey := make([]byte, len(s.masterKey))
	copy(oldKey, s.masterKey)

	// Re-encrypt all secrets with new master key
	if err := s.reencryptAllWithKey(newMasterKey, oldKey); err != nil {
		secureZero(newMasterKey)
		secureZero(oldKey)
		return nil, err
	}
	secureZero(oldKey)

	// Update verification hash
	if err := s.storeVerificationHash(newMasterKey); err != nil {
		secureZero(newMasterKey)
		return nil, err
	}

	// Update master key and activity
	secureZero(s.masterKey)
	s.masterKey = newMasterKey
	s.updateActivity()

	s.audit("rotate_shamir", "", true, time.Since(start))
	return encryptedShares, nil
}

// Close closes the database and locks the store.
func (s *Store) Close() error {
	s.Lock()
	return s.db.Close()
}

// autoLockRoutine locks the store after period of inactivity.
func (s *Store) autoLockRoutine() {
	ticker := time.NewTicker(s.config.AutoLockInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lastNano := atomic.LoadInt64(&s.lastActivity)
			if time.Since(time.Unix(0, lastNano)) > s.config.AutoLockInterval {
				s.Lock()
				return
			}
		case <-s.autoLockStop:
			return
		}
	}
}

// updateActivity updates the last activity timestamp.
func (s *Store) updateActivity() {
	atomic.StoreInt64(&s.lastActivity, time.Now().UnixNano())
}

// reencryptAll re-encrypts all secrets with a new master key.
func (s *Store) reencryptAll(newKey []byte) error {
	oldKey := make([]byte, len(s.masterKey))
	copy(oldKey, s.masterKey)
	defer secureZero(oldKey)
	return s.reencryptAllWithKey(newKey, oldKey)
}

// reencryptAllWithKey re-encrypts all secrets using explicit oldKey and newKey.
// This avoids race conditions with s.masterKey being modified during iteration.
func (s *Store) reencryptAllWithKey(newKey, oldKey []byte) error {
	if len(oldKey) == 0 {
		return errors.New("old key is empty")
	}

	type secretUpdate struct {
		key    string
		secret Secret
	}

	var secretsToUpdate []secretUpdate

	// Collect and re-encrypt all secrets
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var secret Secret
			if err := json.Unmarshal(v, &secret); err != nil {
				return err
			}

			// Decrypt with explicit old key
			plaintext, err := s.decrypt(secret.Ciphertext, oldKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt %s: %w", string(k), err)
			}

			// Re-encrypt with explicit new key
			ciphertext, err := s.encrypt(plaintext, newKey)
			if err != nil {
				secureZero(plaintext)
				return fmt.Errorf("failed to encrypt %s: %w", string(k), err)
			}

			secureZero(plaintext)

			secret.Ciphertext = ciphertext
			secret.UpdatedAt = time.Now()
			secret.Version++

			secretsToUpdate = append(secretsToUpdate, secretUpdate{
				key:    string(k),
				secret: secret,
			})

			return nil
		})
	})
	if err != nil {
		return err
	}

	// Write updates
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return nil
		}

		for _, item := range secretsToUpdate {
			data, err := json.Marshal(item.secret)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(item.key), data); err != nil {
				return err
			}
		}
		return nil
	})
}

// encrypt encrypts plaintext using XChaCha20-Poly1305 with the given key.
// Returns ciphertext with nonce prepended (nonceSize + len(plaintext) + tagSize).
func (s *Store) encrypt(plaintext []byte, key []byte) ([]byte, error) {
	cipher, err := NewCipherFromKey(key)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(plaintext)
}

// decrypt decrypts ciphertext using XChaCha20-Poly1305 with the given key.
// Expects ciphertext with nonce prepended.
func (s *Store) decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	cipher, err := NewCipherFromKey(key)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(ciphertext)
}

// getOrCreateSalt retrieves existing salt or generates a new one.
func (s *Store) getOrCreateSalt() ([]byte, error) {
	var salt []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return nil
		}
		data := b.Get([]byte("salt"))
		if data != nil {
			// Copy the data to avoid lifetime issues with BoltDB-managed memory
			salt = append([]byte(nil), data...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if err := s.storeSalt(salt); err != nil {
			return nil, err
		}
	}
	return salt, nil
}

// storeSalt saves the salt to the database.
func (s *Store) storeSalt(salt []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		return b.Put([]byte("salt"), salt)
	})
}

// storeVerificationHash stores a hash of the master key for verification.
func (s *Store) storeVerificationHash(key []byte) error {
	// Create HMAC-like verification using derived key
	// We use a simple hash of key+fixed context
	h := argon2.IDKey(key, []byte("verification"), 1, 64*1024, 4, 32)

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		return b.Put([]byte("verify"), h)
	})
}

// verifyMasterKey checks if the derived key matches the stored verification.
func (s *Store) verifyMasterKey(key []byte) error {
	var storedHash []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		data := b.Get([]byte("verify"))
		if data != nil {
			storedHash = append([]byte(nil), data...)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// If no verification hash exists (first unlock), create one
	if storedHash == nil {
		return s.storeVerificationHash(key)
	}

	computedHash := argon2.IDKey(key, []byte("verification"), 1, 64*1024, 4, 32)

	if subtle.ConstantTimeCompare(computedHash, storedHash) != 1 {
		return ErrInvalidPassphrase
	}

	return nil
}

// saveShamirMetadata stores Shamir configuration.
func (s *Store) saveShamirMetadata(threshold, total int) error {
	data := fmt.Sprintf("%d:%d", threshold, total)
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return errors.New("metadata bucket not found")
		}
		return b.Put([]byte("shamir"), []byte(data))
	})
}

// loadShamirMetadata retrieves Shamir configuration.
func (s *Store) loadShamirMetadata() error {
	var data []byte

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("metadata"))
		if b == nil {
			return nil
		}
		data = b.Get([]byte("shamir"))
		return nil
	})

	if err != nil || data == nil {
		return nil // No Shamir configured
	}

	var threshold, total int
	if _, err := fmt.Sscanf(string(data), "%d:%d", &threshold, &total); err != nil {
		return err
	}

	s.shamirThreshold = threshold
	s.shamirTotal = total
	s.shamirEnabled = true
	return nil
}

// incrementAccessCount updates the access count for a secret.
func (s *Store) incrementAccessCount(key string) {
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("secrets"))
		if b == nil {
			return nil
		}

		data := b.Get([]byte(key))
		if data == nil {
			return nil
		}

		var secret Secret
		if err := json.Unmarshal(data, &secret); err != nil {
			return err
		}

		secret.AccessCount++
		secret.LastAccess = time.Now()

		newData, err := json.Marshal(secret)
		if err != nil {
			return err
		}

		return b.Put([]byte(key), newData)
	})
}

// audit logs an action if audit logging is enabled.
func (s *Store) audit(action, key string, success bool, duration time.Duration) {
	if s.auditFn != nil && s.config.EnableAudit {
		s.auditFn(action, key, success, duration)
	}
}

// secureZero wipes a byte slice from memory.
func secureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Global store instance for package-level access.
var globalStore *Store
var globalMu sync.RWMutex

// SetGlobalStore sets the global secret store instance.
func SetGlobalStore(store *Store) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalStore = store
}

// GetGlobalStore returns the global secret store instance.
func GetGlobalStore() *Store {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStore
}

// GetGlobal retrieves a secret from the global store.
func GetGlobal(key string) (string, error) {
	globalMu.RLock()
	store := globalStore
	globalMu.RUnlock()

	if store == nil {
		return "", errors.New("global secret store not initialized")
	}
	return store.Get(key)
}
