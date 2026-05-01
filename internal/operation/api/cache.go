package api

import (
	"encoding/json"
	"net/http"

	"github.com/agberohq/agbero/internal/pkg/stash"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// CacheHandler registers CDN cache management endpoints under /cache.
// Mirrors the FirewallHandler pattern exactly.
func CacheHandler(shared *Shared, r chi.Router) {
	ch := newCacheAPI(shared)
	r.Route("/cache", func(r chi.Router) {
		r.Get("/stats", ch.stats)
		r.Delete("/", ch.clearAll)
		r.Delete("/purge", ch.purgeByTag)
	})
}

type cacheAPI struct {
	store  stash.Store
	logger *ll.Logger
}

func newCacheAPI(shared *Shared) *cacheAPI {
	var logger *ll.Logger
	if shared.Logger != nil {
		logger = shared.Logger.Namespace("api/cache")
	}
	return &cacheAPI{
		store:  shared.CacheStore,
		logger: logger,
	}
}

func (c *cacheAPI) log() *ll.Logger { return c.logger }

// purgeByTag handles DELETE /cache/purge?tag=<tag>
func (c *cacheAPI) purgeByTag(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		http.Error(w, "query parameter 'tag' is required", http.StatusBadRequest)
		return
	}
	if c.store == nil {
		http.Error(w, "cache store not available", http.StatusNotImplemented)
		return
	}
	if err := c.store.Purge(tag); err != nil {
		if c.log() != nil {
			c.log().Fields("tag", tag, "error", err).Error("purge by tag failed")
		}
		http.Error(w, "purge failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if c.log() != nil {
		c.log().Fields("tag", tag).Info("admin: cache purged by tag")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "tag": tag})
}

// clearAll handles DELETE /cache
func (c *cacheAPI) clearAll(w http.ResponseWriter, r *http.Request) {
	if c.store == nil {
		http.Error(w, "cache store not available", http.StatusNotImplemented)
		return
	}
	if err := c.store.Clear(); err != nil {
		if c.log() != nil {
			c.log().Fields("error", err).Error("cache clear failed")
		}
		http.Error(w, "clear failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if c.log() != nil {
		c.log().Info("admin: cache cleared")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// stats handles GET /cache/stats
func (c *cacheAPI) stats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"available": c.store != nil})
}
