package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// TokenRecord is non-secret metadata for the admin "Recent tokens" table.
// The token itself is never stored.
type TokenRecord struct {
	User      string    `json:"user"`
	Scope     string    `json:"scope"`
	JTI       string    `json:"jti"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TokenRegistry struct {
	mu      sync.Mutex
	path    string
	records []TokenRecord
}

// OpenTokenRegistry loads the metadata registry. A missing file is empty.
func OpenTokenRegistry(path string) (*TokenRegistry, error) {
	if path == "" {
		return nil, nil
	}
	r := &TokenRegistry{path: path}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-reads metadata written by another process (for example the CLI).
func (r *TokenRegistry) Reload() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			r.records = nil
			return nil
		}
		return err
	}
	var records []TokenRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	r.records = records
	r.pruneLocked()
	return nil
}

// Add records a minted token (metadata only) and persists the registry.
func (r *TokenRegistry) Add(rec TokenRecord) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	r.pruneLocked()
	return r.persistLocked()
}

// List returns newest first. Callers must treat this as metadata, not proof of
// a live token; revocation is checked separately.
func (r *TokenRegistry) List() []TokenRecord {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TokenRecord, len(r.records))
	copy(out, r.records)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

func (r *TokenRegistry) pruneLocked() {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	kept := r.records[:0]
	for _, rec := range r.records {
		if rec.ExpiresAt.After(cutoff) {
			kept = append(kept, rec)
		}
	}
	r.records = kept
	if len(r.records) > 100 {
		r.records = r.records[len(r.records)-100:]
	}
}

func (r *TokenRegistry) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r.records, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
