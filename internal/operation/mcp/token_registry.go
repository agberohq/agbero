package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/agberohq/oshodi"
)

const RegistryBucket = "mcp_tokens"

// TokenRecord is non-secret metadata for the admin "Recent tokens" table.
// The token itself is never stored.
type TokenRecord struct {
	User      string    `json:"user"`
	Scope     string    `json:"scope"`
	JTI       string    `json:"jti"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenRegistry stores token metadata in the shared Oshodi control database.
// It never stores a JWT; only JTI/user/scope/timestamps.
type TokenRegistry struct {
	mu      sync.Mutex
	db      *oshodi.DB
	bucket  *oshodi.Bucket
	records []TokenRecord
}

// OpenTokenRegistryBucket opens the mcp_tokens bucket in the coordinator-owned
// Oshodi database.
func OpenTokenRegistryBucket(db *oshodi.DB) (*TokenRegistry, error) {
	if db == nil {
		return nil, fmt.Errorf("mcp token registry: database is required")
	}
	r := &TokenRegistry{db: db, bucket: db.Bucket(RegistryBucket)}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-reads metadata from Oshodi.
func (r *TokenRegistry) Reload() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	records := make([]TokenRecord, 0, 32)
	err := r.bucket.Scan(func(_, v []byte) bool {
		var rec TokenRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			return true
		}
		records = append(records, rec)
		return true
	})
	if err != nil {
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
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := r.bucket.Set([]byte(rec.JTI), raw); err != nil {
		return err
	}
	return r.db.Flush()
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
