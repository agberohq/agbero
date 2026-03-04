package attic

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

type Entry struct {
	Body        []byte
	Headers     http.Header
	Status      int
	StoredAt    time.Time
	CreatedAt   time.Time
	VaryHeaders map[string]string
}

type CacheStore interface {
	Get(key string) (*Entry, bool)
	Set(key string, entry *Entry, ttl time.Duration)
	Delete(key string)
	Clear() error
	Close() error
}

type CacheMiddleware struct {
	store          CacheStore
	logger         *ll.Logger
	allowedMethods map[string]bool
	enabled        bool
	defaultTTL     time.Duration
}

func New(cfg *alaye.Cache, logger *ll.Logger) func(http.Handler) http.Handler {
	if !cfg.Enabled.Active() {
		return func(next http.Handler) http.Handler { return next }
	}
	var store CacheStore
	var err error
	switch cfg.Driver {
	case "memory", "":
		store, err = NewMemoryStore(cfg)
	case "redis":
		store, err = NewRedis(cfg, logger)
	default:
		logger.Error("unknown cache driver", "driver", cfg.Driver)
		return func(next http.Handler) http.Handler { return next }
	}
	if err != nil {
		logger.Error("failed to create cache store", "error", err)
		return func(next http.Handler) http.Handler { return next }
	}
	mw := &CacheMiddleware{
		store:          store,
		logger:         logger,
		allowedMethods: make(map[string]bool, len(cfg.Methods)),
		enabled:        true,
		defaultTTL:     cfg.TTL,
	}
	for _, m := range cfg.Methods {
		mw.allowedMethods[strings.ToUpper(m)] = true
	}
	return mw.Handler
}

func (m *CacheMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "MISS")

		if !m.enabled || !m.allowedMethods[r.Method] || !isRequestCacheable(r) {
			next.ServeHTTP(w, r)
			return
		}

		key := generateKey(r)
		if entry, ok := m.store.Get(key); ok {
			if serveCachedResponse(w, r, entry, m.logger) {
				return
			}
			m.store.Delete(key)
		}

		rec := newRecorder(w)
		next.ServeHTTP(rec, r)

		if !isResponseCacheable(rec.StatusCode(), rec.Header()) {
			return
		}

		varyHeaders := make(map[string]string)
		if vary := rec.Header().Get("Vary"); vary != "" {
			for _, field := range strings.Split(vary, ",") {
				field = strings.TrimSpace(field)
				if field != "*" && field != "" {
					varyHeaders[field] = r.Header.Get(field)
				}
			}
		}

		entry := &Entry{
			Body:        rec.Body(),
			Headers:     rec.Header().Clone(),
			Status:      rec.StatusCode(),
			CreatedAt:   time.Now(),
			StoredAt:    time.Now(),
			VaryHeaders: varyHeaders,
		}
		removeHopByHopHeaders(entry.Headers)
		ttl := m.getEffectiveTTL(rec.Header(), m.defaultTTL)
		if ttl > 0 {
			m.store.Set(key, entry, ttl)
		}
	})
}

func (m *CacheMiddleware) getEffectiveTTL(hdr http.Header, defaultTTL time.Duration) time.Duration {
	cc := hdr.Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		return 0
	}
	if maxAge := parseMaxAge(cc); maxAge > 0 {
		return maxAge
	}
	return defaultTTL
}

func (m *CacheMiddleware) Close() error {
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}

func serveCachedResponse(w http.ResponseWriter, r *http.Request, e *Entry, log *ll.Logger) bool {
	if !isResponseValidForRequest(e, r) {
		return false
	}
	w.Header().Set("X-Cache", "HIT")
	if age := int(time.Since(e.CreatedAt).Seconds()); age > 0 {
		w.Header().Set("Age", strconv.Itoa(age))
	}
	for k, vv := range e.Headers {
		for _, v := range vv {
			if k != "Age" && k != "X-Cache" {
				w.Header().Add(k, v)
			}
		}
	}
	if matchConditionalRequest(r, e) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	w.WriteHeader(e.Status)
	if _, err := w.Write(e.Body); err != nil && log != nil {
		log.Error("failed writing cached response", "error", err)
	}
	return true
}

func isRequestCacheable(r *http.Request) bool {
	cc := r.Header.Get("Cache-Control")
	return !strings.Contains(cc, "no-cache") && !strings.Contains(cc, "no-store")
}

func isResponseCacheable(status int, hdr http.Header) bool {
	if status < 200 || status >= 300 {
		return false
	}
	cc := hdr.Get("Cache-Control")
	if strings.Contains(cc, "no-store") ||
		strings.Contains(cc, "private") ||
		strings.Contains(cc, "no-cache") {
		return false
	}
	if hdr.Get("WWW-Authenticate") != "" {
		return false
	}
	return true
}

func isResponseValidForRequest(e *Entry, r *http.Request) bool {
	if v := e.Headers.Get("Vary"); v != "" {
		for _, f := range strings.Split(v, ",") {
			f = strings.TrimSpace(f)
			if f == "*" {
				return false
			}
			if r.Header.Get(f) != e.VaryHeaders[f] {
				return false
			}
		}
	}
	return true
}

func matchConditionalRequest(r *http.Request, e *Entry) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if etag := e.Headers.Get("ETag"); etag != "" && inm == etag {
			return true
		}
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if mod, err := time.Parse(http.TimeFormat, ims); err == nil {
			if !e.CreatedAt.After(mod) {
				return true
			}
		}
	}
	return false
}

func parseMaxAge(cc string) time.Duration {
	for _, p := range strings.Split(cc, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "max-age=") {
			if s, err := strconv.Atoi(p[8:]); err == nil {
				return time.Duration(s) * time.Second
			}
		}
	}
	return 0
}

func removeHopByHopHeaders(hdr http.Header) {
	hop := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers",
		"Transfer-Encoding", "Upgrade",
	}
	for _, h := range hop {
		hdr.Del(h)
	}
}
