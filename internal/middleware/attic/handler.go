package attic

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/pkg/stash"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

const headerXCache = "X-Cache"
const headerXCacheStatus = "X-Cache-Status"

type CacheMiddleware struct {
	store            stash.Store
	logger           *ll.Logger
	pool             *jack.Pool
	allowedMethods   map[string]bool
	enabled          bool
	defaultTTL       time.Duration
	keyScope         []string
	maxCacheableSize int64
	policy           *alaye.TTLPolicy
}

// Option configures optional fields on CacheMiddleware.
type Option func(*CacheMiddleware)

// WithPool provides an accountable jack.Pool for stale-while-revalidate.
// Pass resource.Background so the pool is properly drained on shutdown.
func WithPool(pool *jack.Pool) Option {
	return func(m *CacheMiddleware) { m.pool = pool }
}

// New builds the cache middleware.
func New(cfg *alaye.Cache, logger *ll.Logger, opts ...Option) func(http.Handler) http.Handler {
	if !cfg.Enabled.Active() {
		return func(next http.Handler) http.Handler { return next }
	}

	maxCacheable := cfg.MaxCacheableSize
	if maxCacheable == 0 {
		maxCacheable = def.CacheMaxBodySize
	}

	storeCfg := &stash.Config{
		Driver:           cfg.Driver,
		DefaultTTL:       cfg.TTL.StdDuration(),
		MaxItems:         def.DefaultCacheMaxItems,
		MaxCacheableSize: maxCacheable,
		Redis:            cfg.Redis,
		Policy:           &cfg.TTLPolicy,
	}

	store, err := stash.NewStore(storeCfg)
	if err != nil {
		if logger != nil {
			logger.Error("failed to create cache store", "error", err)
		}
		return func(next http.Handler) http.Handler { return next }
	}

	mw := &CacheMiddleware{
		store:            store,
		logger:           logger,
		allowedMethods:   make(map[string]bool, len(cfg.Methods)),
		enabled:          true,
		defaultTTL:       cfg.TTL.StdDuration(),
		keyScope:         cfg.TTLPolicy.KeyScope,
		maxCacheableSize: maxCacheable,
		policy:           &cfg.TTLPolicy,
	}
	for _, o := range opts {
		o(mw)
	}
	for _, m := range cfg.Methods {
		mw.allowedMethods[strings.ToUpper(m)] = true
	}
	return mw.Handler
}

func (m *CacheMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.enabled || !m.allowedMethods[r.Method] || !isRequestCacheable(r) {
			next.ServeHTTP(w, r)
			return
		}

		key := stash.Key(r, m.keyScope)
		if entry, ok := m.store.Get(key); ok {
			if entry.IsStale() {
				if m.policy.IsStaleWhileRevalidate() {
					age := time.Since(entry.CreatedAt)
					if age <= entry.TTL+m.policy.StaleWindow() {
						serveEntry(w, r, entry, "STALE", m.logger)
						m.revalidate(key, r, next)
						return
					}
				}
				m.store.Delete(key)
			} else {
				if serveCachedResponse(w, r, entry, m.logger) {
					return
				}
				m.store.Delete(key)
			}
		}

		rec := newRecorder(w, m.maxCacheableSize)
		next.ServeHTTP(rec, r)

		if !rec.Cacheable() {
			setCacheHeaders(w, "BYPASS")
			if m.logger != nil {
				m.logger.Debug("response body exceeds max_cacheable_size, bypassing cache",
					"limit", m.maxCacheableSize)
			}
			return
		}

		setCacheHeaders(w, "MISS")

		if !isResponseCacheable(rec.StatusCode(), rec.Header()) {
			return
		}

		ttl := effectiveTTL(rec.Header(), m.defaultTTL)
		if ttl <= 0 {
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

		entry := &stash.Entry{
			Body:          rec.Body(),
			Headers:       rec.Header().Clone(),
			Status:        rec.StatusCode(),
			CreatedAt:     time.Now(),
			StoredAt:      time.Now(),
			TTL:           ttl,
			VaryHeaders:   varyHeaders,
			ContentType:   rec.Header().Get("Content-Type"),
			SurrogateTags: parseSurrogateTags(rec.Header()),
		}
		removeHopByHopHeaders(entry.Headers)
		m.store.SetWithPolicy(key, entry, m.policy, ttl)
	})
}

// revalidate submits a background cache refresh to the jack pool.
// If no pool is configured, the next request will fetch fresh data
// once the stale window expires and the entry is evicted.
func (m *CacheMiddleware) revalidate(key string, r *http.Request, next http.Handler) {
	if m.pool == nil {
		return
	}
	clone := r.Clone(r.Context())
	maxSize := m.maxCacheableSize
	defaultTTL := m.defaultTTL
	store := m.store
	logger := m.logger

	_ = m.pool.Submit(jack.Func(func() error {
		rec := newRecorder(noopResponseWriter{}, maxSize)
		next.ServeHTTP(rec, clone)

		if !rec.Cacheable() || !isResponseCacheable(rec.StatusCode(), rec.Header()) {
			return nil
		}
		ttl := effectiveTTL(rec.Header(), defaultTTL)
		if ttl <= 0 {
			return nil
		}
		fresh := &stash.Entry{
			Body:          rec.Body(),
			Headers:       rec.Header().Clone(),
			Status:        rec.StatusCode(),
			CreatedAt:     time.Now(),
			StoredAt:      time.Now(),
			TTL:           ttl,
			ContentType:   rec.Header().Get("Content-Type"),
			SurrogateTags: parseSurrogateTags(rec.Header()),
		}
		removeHopByHopHeaders(fresh.Headers)
		store.SetWithPolicy(key, fresh, m.policy, ttl)
		if logger != nil {
			logger.Debug("stale-while-revalidate: refreshed", "key", key)
		}
		return nil
	}))
}

func (m *CacheMiddleware) Close() error {
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}

func setCacheHeaders(w http.ResponseWriter, status string) {
	w.Header().Set(headerXCache, status)
	w.Header().Set(headerXCacheStatus, status)
}

func parseSurrogateTags(hdr http.Header) []string {
	var tags []string
	for _, h := range []string{"Surrogate-Key", "Cache-Tag"} {
		if v := hdr.Get(h); v != "" {
			for _, t := range strings.Fields(v) {
				if t != "" {
					tags = append(tags, t)
				}
			}
		}
	}
	return tags
}

func serveCachedResponse(w http.ResponseWriter, r *http.Request, e *stash.Entry, log *ll.Logger) bool {
	if !isResponseValidForRequest(e, r) {
		return false
	}
	serveEntry(w, r, e, "HIT", log)
	return true
}

func serveEntry(w http.ResponseWriter, r *http.Request, e *stash.Entry, status string, log *ll.Logger) {
	setCacheHeaders(w, status)
	if age := int(time.Since(e.CreatedAt).Seconds()); age >= 0 {
		w.Header().Set("Age", strconv.Itoa(age))
	}
	for k, vv := range e.Headers {
		for _, v := range vv {
			if k != "Age" && k != headerXCache && k != headerXCacheStatus {
				w.Header().Add(k, v)
			}
		}
	}
	if matchConditionalRequest(r, e) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(e.Status)
	if _, err := w.Write(e.Body); err != nil && log != nil {
		log.Error("failed writing cached response", "error", err)
	}
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
	return hdr.Get("WWW-Authenticate") == ""
}

func isResponseValidForRequest(e *stash.Entry, r *http.Request) bool {
	if v := e.Headers.Get("Vary"); v != "" {
		for _, field := range strings.Split(v, ",") {
			field = strings.TrimSpace(field)
			if field == "*" {
				return false
			}
			if r.Header.Get(field) != e.VaryHeaders[field] {
				return false
			}
		}
	}
	return true
}

func matchConditionalRequest(r *http.Request, e *stash.Entry) bool {
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

func effectiveTTL(hdr http.Header, defaultTTL time.Duration) time.Duration {
	cc := hdr.Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		return 0
	}
	if maxAge := parseMaxAge(cc); maxAge > 0 {
		return maxAge
	}
	return defaultTTL
}

func parseMaxAge(cc string) time.Duration {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			if s, err := strconv.Atoi(part[8:]); err == nil {
				return time.Duration(s) * time.Second
			}
		}
	}
	return 0
}

func removeHopByHopHeaders(hdr http.Header) {
	for _, h := range []string{
		"Connection", "Keep-alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers",
		"Transfer-Encoding", "Upgrade",
	} {
		hdr.Del(h)
	}
}

type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header         { return http.Header{} }
func (noopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (noopResponseWriter) WriteHeader(int)             {}
