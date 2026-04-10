package revoke

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

const filename = "revoked.json"

// entry records a single revoked JTI and when it naturally expires.
// Entries are pruned once their token would have expired anyway.
type entry struct {
	JTI       string    `json:"jti"`
	Service   string    `json:"service"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at"`
}

// Store holds the in-memory revocation list and persists it to disk.
type Store struct {
	mu        sync.RWMutex
	persistMu sync.Mutex
	entries   map[string]entry
	path      string
	logger    *ll.Logger
}

// New loads or creates the revocation store at dataDir/revoked.json.
func New(dataDir expect.Folder, logger *ll.Logger) (*Store, error) {
	s := &Store{
		entries: make(map[string]entry),
		path:    dataDir.FilePath(filename),
		logger:  logger.Namespace("revoke"),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
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
	// Entry past its natural expiry is harmless — prune loop will clean it up.
	return time.Now().Before(e.ExpiresAt)
}

// Revoke adds a JTI to the list and persists to disk.
// expiresAt should be the token's original expiry — entries are auto-pruned after that time.
func (s *Store) Revoke(jti, service string, expiresAt time.Time) error {
	s.mu.Lock()
	s.entries[jti] = entry{
		JTI:       jti,
		Service:   service,
		ExpiresAt: expiresAt,
		RevokedAt: time.Now(),
	}
	s.mu.Unlock()
	s.logger.Fields("jti", jti, "service", service).Info("token revoked")
	return s.persist()
}

// load reads the revocation file from disk, ignoring not-found errors.
func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries []entry
	if err := json.Unmarshal(data, &entries); err != nil {
		s.logger.Fields("err", err).Warn("revoke: failed to parse revoked.json, starting empty")
		return nil
	}
	now := time.Now()
	for _, e := range entries {
		if now.Before(e.ExpiresAt) {
			s.entries[e.JTI] = e
		}
	}
	s.logger.Fields("count", len(s.entries)).Info("revoke: loaded revocation list")
	return nil
}

// persist writes the current list to disk atomically.
// Add this field to Store struct

// Modify persist() to be concurrency-safe
func (s *Store) persist() error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	s.mu.RLock()
	entries := make([]entry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	// Use unique temp filename to avoid collisions
	tmp := fmt.Sprintf("%s.%d.tmp", s.path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// pruneLoop removes expired entries every hour and persists the cleaned list.
func (s *Store) pruneLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		s.prune()
	}
}

func (s *Store) prune() {
	now := time.Now()
	s.mu.Lock()
	pruned := 0
	for jti, e := range s.entries {
		if !now.Before(e.ExpiresAt) {
			delete(s.entries, jti)
			pruned++
		}
	}
	s.mu.Unlock()
	if pruned > 0 {
		s.logger.Fields("pruned", pruned).Info("revoke: pruned expired entries")
		_ = s.persist()
	}
}
