package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

// KVHandler registers in-memory KV endpoints under /api/v1/kv.
// Data is lost on server restart - this is intentional for temporary state.
func KVHandler(s *Shared, r chi.Router) {
	kv := NewKV(s)

	r.Route("/kv", func(r chi.Router) {
		r.With(ValidateKeyParam).Get("/{key}", kv.get)
		r.With(ValidateKeyParam).Post("/{key}", kv.set)
		r.With(ValidateKeyParam).Delete("/{key}", kv.delete)
	})
}

// KV provides HTTP handlers for in-memory key-value storage.
// Uses mappo.Cache for high-performance, TTL-capable caching with automatic eviction.
type KV struct {
	cache  *mappo.Cache
	logger *ll.Logger
}

// NewKV initializes a KV instance with a sized cache.
// Defaults to 100,000 entries max with automatic LRU eviction.
func NewKV(cfg *Shared) *KV {
	return &KV{
		cache: mappo.NewCache(mappo.CacheOptions{
			MaximumSize: 100_000, // ~12MB max with 120KB histograms, but KV items are smaller
			OnDelete: func(key string, it *mappo.Item) {
				// Optional: log evictions or persist to disk
			},
		}),
		logger: cfg.Logger.Namespace("api/kv"),
	}
}

// kvValue wraps any value with metadata for the API response
type kvValue struct {
	Value     any       `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	TTL       int64     `json:"ttl_seconds,omitempty"` // 0 = no expiration
}

// get handles GET /api/v1/kv/:key - retrieve a value
func (kv *KV) get(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if key == "" {
		kv.errorResponse(w, http.StatusBadRequest, "key is required")
		return
	}

	item, ok := kv.cache.Load(key)
	if !ok {
		kv.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	val, ok := mappo.GetTyped[kvValue](item)
	if !ok {
		// Fallback for raw values stored directly
		val = kvValue{Value: item.Value, CreatedAt: time.Unix(0, item.LastAccessed.Load())}
	}

	// Calculate remaining TTL
	var ttlRemaining int64
	if !item.Exp.IsZero() {
		ttlRemaining = int64(item.Exp.Sub(time.Now()).Seconds())
		if ttlRemaining < 0 {
			ttlRemaining = 0
		}
	}

	kv.jsonResponse(w, http.StatusOK, map[string]any{
		"key":           key,
		"value":         val.Value,
		"created_at":    val.CreatedAt,
		"ttl_seconds":   ttlRemaining,
		"last_accessed": time.Unix(0, item.LastAccessed.Load()),
	})
}

// set handles POST /api/v1/kv/:key - store a value with optional TTL
func (kv *KV) set(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if key == "" {
		kv.errorResponse(w, http.StatusBadRequest, "key is required")
		return
	}

	var req struct {
		Value any   `json:"value"`
		TTL   int64 `json:"ttl_seconds"` // 0 = no expiration
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		kv.errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	val := kvValue{
		Value:     req.Value,
		CreatedAt: time.Now(),
	}

	var ttl time.Duration
	if req.TTL > 0 {
		ttl = time.Duration(req.TTL) * time.Second
	}

	item := &mappo.Item{
		Value: val,
	}
	item.LastAccessed.Store(time.Now().UnixNano())

	if ttl > 0 {
		kv.cache.StoreTTL(key, item, ttl)
	} else {
		kv.cache.Store(key, item)
	}

	kv.logger.Fields("key", key, "ttl", req.TTL).Debug("kv set")
	kv.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
		"key":    key,
	})
}

// delete handles DELETE /api/v1/kv/:key - remove a value
func (kv *KV) delete(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if key == "" {
		kv.errorResponse(w, http.StatusBadRequest, "key is required")
		return
	}

	_, existed := kv.cache.LoadAndDelete(key)
	if !existed {
		kv.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	kv.logger.Fields("key", key).Debug("kv delete")
	kv.jsonResponse(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"key":    key,
	})
}

// ValidateKeyParam is chi middleware that validates key format.
// Rejects empty keys and keys with path traversal attempts.
func ValidateKeyParam(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := chi.URLParam(r, "key")
		if key == "" {
			http.Error(w, `{"error":"key path parameter required"}`, http.StatusBadRequest)
			return
		}
		// Block path traversal
		for _, bad := range []string{"..", "/", "\\", "%"} {
			if contains(key, bad) {
				http.Error(w, `{"error":"invalid key format"}`, http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (kv *KV) errorResponse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (kv *KV) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		kv.logger.Error("failed to encode response", "err", err)
	}
}
