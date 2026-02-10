package cache

import (
	"encoding/json"
	"sync/atomic"
)

// Item wraps the handler with usage tracking for the Reaper.
type Item struct {
	Handler      any          `json:"handler"`       // *core.RouteHandler
	LastAccessed atomic.Int64 `json:"last_accessed"` // UnixNano
}

// MarshalJSON makes atomic.Int64 serialize as a number (instead of {}).
func (r *Item) MarshalJSON() ([]byte, error) {
	type Alias Item
	return json.Marshal(&struct {
		LastAccessed int64 `json:"last_accessed"`
		*Alias
	}{
		LastAccessed: r.LastAccessed.Load(),
		Alias:        (*Alias)(r),
	})
}

// UnmarshalJSON restores LastAccessed into the atomic.Int64.
func (r *Item) UnmarshalJSON(b []byte) error {
	type Alias Item
	aux := &struct {
		LastAccessed int64 `json:"last_accessed"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	r.LastAccessed.Store(aux.LastAccessed)
	return nil
}
