package revoke

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/oshodi"
	"github.com/olekukonko/ll"
)

const bucketName = "revoked"

// entry records a single revoked JTI and when it naturally expires.
// Entries are pruned once their token would have expired anyway.
type entry struct {
	JTI       string    `json:"jti"`
	Service   string    `json:"service"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Store keeps the revocation list in Oshodi and a memory cache for fast checks.
type Store struct {
	mu      sync.RWMutex
	entries map[string]entry
	path    string
	db      *oshodi.DB
	bucket  *oshodi.Bucket
	logger  *ll.Logger

	quit      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// New opens the Oshodi-backed revocation store. An existing revoked.json from
// older releases is imported once if the Oshodi bucket is empty.
func New(dataDir expect.Folder, logger *ll.Logger) (*Store, error) {
	path := dataDir.FilePath(def.DefaultRevokedDBName)
	db, err := oshodi.Open(path, oshodi.WithWAL(false), oshodi.WithCompression(4096, 3))
	if err != nil {
		return nil, fmt.Errorf("revoke: open store: %w", err)
	}
	s := &Store{
		entries: make(map[string]entry),
		path:    path,
		db:      db,
		bucket:  db.Bucket(bucketName),
		logger:  logger.Namespace("revoke"),
		quit:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if err := s.load(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.importLegacyJSON(dataDir)
	go s.pruneLoop()
	return s, nil
}

// IsRevoked returns true if the JTI is on the revocation list and has not yet expired.
func (s *Store) IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	s.mu.RLock()
	e, ok := s.entries[jti]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Now().Before(e.ExpiresAt)
}

// Refresh rebuilds the memory cache from Oshodi, picking up writes made by
// another owner of the store.
func (s *Store) Refresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

// Revoke adds a JTI to the list and persists it.
func (s *Store) Revoke(jti, service string, expiresAt time.Time) error {
	e := entry{JTI: jti, Service: service, ExpiresAt: expiresAt, RevokedAt: time.Now()}
	s.mu.Lock()
	s.entries[jti] = e
	s.mu.Unlock()

	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := s.bucket.Set([]byte(jti), raw); err != nil {
		return err
	}
	// Revocations are rare and security-sensitive: make the write durable
	// before reporting success.
	if err := s.db.Flush(); err != nil {
		return err
	}
	s.logger.Fields("jti", jti, "service", service).Info("token revoked")
	return nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() error {
	now := time.Now()
	loaded := make(map[string]entry)
	err := s.bucket.Scan(func(k, v []byte) bool {
		var e entry
		if err := json.Unmarshal(v, &e); err != nil {
			return true
		}
		if now.Before(e.ExpiresAt) {
			loaded[string(k)] = e
		}
		return true
	})
	if err != nil {
		return err
	}
	s.entries = loaded
	s.logger.Fields("count", len(s.entries)).Info("revoke: loaded revocation list")
	return nil
}

// importLegacyJSON imports the old revoked.json once, for upgrades only.
func (s *Store) importLegacyJSON(dataDir expect.Folder) {
	if len(s.entries) != 0 {
		return
	}
	data, err := os.ReadFile(dataDir.FilePath(def.DefaultRevokedName))
	if err != nil {
		return
	}
	var legacy []entry
	if err := json.Unmarshal(data, &legacy); err != nil {
		s.logger.Fields("err", err).Warn("revoke: failed to parse legacy revoked.json")
		return
	}
	now := time.Now()
	for _, e := range legacy {
		if !now.Before(e.ExpiresAt) {
			continue
		}
		raw, _ := json.Marshal(e)
		_ = s.bucket.Set([]byte(e.JTI), raw)
		s.entries[e.JTI] = e
	}
	_ = s.db.Flush()
	s.logger.Fields("count", len(s.entries)).Info("revoke: imported legacy revoked.json")
}

// DB returns the shared coordinator database. The caller must not close it.
func (s *Store) DB() *oshodi.DB { return s.db }

// Close flushes Oshodi and stops the prune loop.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.quit)
		<-s.done
		_ = s.db.Close()
	})
	return nil
}

func (s *Store) pruneLoop() {
	defer close(s.done)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.prune()
		case <-s.quit:
			s.prune()
			return
		}
	}
}

func (s *Store) prune() {
	now := time.Now()
	var expired []string
	s.mu.Lock()
	for jti, e := range s.entries {
		if !now.Before(e.ExpiresAt) {
			delete(s.entries, jti)
			expired = append(expired, jti)
		}
	}
	s.mu.Unlock()
	if len(expired) == 0 {
		return
	}
	for _, jti := range expired {
		_ = s.bucket.Delete([]byte(jti))
	}
	_ = s.db.Flush()
	s.logger.Fields("pruned", len(expired)).Info("revoke: pruned expired entries")
}
