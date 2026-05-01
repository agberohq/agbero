package stash

import (
	"net/http"
	"time"
)

type Entry struct {
	Body        []byte
	Headers     http.Header
	Status      int
	StoredAt    time.Time
	CreatedAt   time.Time
	TTL         time.Duration
	VaryHeaders map[string]string
	ContentType string

	// SurrogateTags holds CDN cache tags (e.g. "product:42", "category:books").
	// Used by PurgeByTag to selectively invalidate groups of cached responses.
	// Populated from the upstream Surrogate-Key or Cache-Tag response header.
	SurrogateTags []string
}

// HasTag reports whether this entry carries the given surrogate tag.
func (e *Entry) HasTag(tag string) bool {
	for _, t := range e.SurrogateTags {
		if t == tag {
			return true
		}
	}
	return false
}

// IsStale reports whether the entry has exceeded its TTL.
// An entry with a zero TTL is never considered stale.
func (e *Entry) IsStale() bool {
	if e.TTL <= 0 {
		return false
	}
	return time.Since(e.CreatedAt) > e.TTL
}
