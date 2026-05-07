package ja3

import (
	"crypto/tls"
	"sync"
	"time"
)

// store is the package-level fingerprint store. It is a singleton because
// GetConfigForClient receives a *tls.ClientHelloInfo whose Conn field provides
// the remote address — the only key available at handshake time — and the
// firewall handler retrieves it by the same key from r.RemoteAddr.
var store = &fingerprintStore{
	entries: make(map[string]entry),
}

type entry struct {
	hash string
	raw  string
	at   time.Time
}

type fingerprintStore struct {
	mu      sync.RWMutex
	entries map[string]entry
}

const ttl = 30 * time.Second // connection setup completes well within this window

// set stores hash and raw fingerprint keyed by remoteAddr.
func (s *fingerprintStore) set(remoteAddr, hash, raw string) {
	s.mu.Lock()
	s.entries[remoteAddr] = entry{hash: hash, raw: raw, at: time.Now()}
	s.mu.Unlock()
}

// get retrieves the stored fingerprints for remoteAddr.
// Returns ("", "", false) if not found or expired.
func (s *fingerprintStore) get(remoteAddr string) (hash, raw string, ok bool) {
	s.mu.RLock()
	e, found := s.entries[remoteAddr]
	s.mu.RUnlock()
	if !found || time.Since(e.at) > ttl {
		return "", "", false
	}
	return e.hash, e.raw, true
}

// evict removes an entry. Called when the connection closes or on explicit cleanup.
func (s *fingerprintStore) evict(remoteAddr string) {
	s.mu.Lock()
	delete(s.entries, remoteAddr)
	s.mu.Unlock()
}

// sweep removes all entries older than ttl. Called periodically by the sweeper.
func (s *fingerprintStore) sweep() {
	now := time.Now()
	s.mu.Lock()
	for k, e := range s.entries {
		if now.Sub(e.at) > ttl {
			delete(s.entries, k)
		}
	}
	s.mu.Unlock()
}

func init() {
	// Background sweeper — prevents unbounded growth under high connection rates.
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			store.sweep()
		}
	}()
}

// InjectHello computes and stores the JA3 fingerprint for a ClientHello.
// Use this inside a GetConfigForClient wrapper when you do not need to clone
// the full tls.Config (e.g. when you are already inside a custom callback).
func InjectHello(hello *tls.ClientHelloInfo) {
	if hello == nil || hello.Conn == nil {
		return
	}
	hash := Compute(hello)
	raw := Raw(hello)
	store.set(hello.Conn.RemoteAddr().String(), hash, raw)
}

// InjectFingerprint wraps base *tls.Config so that every incoming TLS
// handshake stores the computed JA3 fingerprint in the package store,
// keyed by the connection's remote address.
//
// The firewall handler retrieves the fingerprint via Get(r.RemoteAddr)
// before rule evaluation.
//
// InjectFingerprint is safe to call on a nil base — it creates a minimal
// config in that case.
func InjectFingerprint(base *tls.Config) *tls.Config {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	orig := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello != nil && hello.Conn != nil {
			hash := Compute(hello)
			raw := Raw(hello)
			store.set(hello.Conn.RemoteAddr().String(), hash, raw)
		}
		if orig != nil {
			return orig(hello)
		}
		return nil, nil
	}
	return cfg
}

// Get returns the JA3 hash for a remote address previously captured during
// the TLS handshake. Returns ("", false) for plain HTTP connections or if
// the entry has expired.
func Get(remoteAddr string) (string, bool) {
	hash, _, ok := store.get(remoteAddr)
	return hash, ok
}

// GetRaw returns the unhashed JA3 string for a remote address. Useful for
// logging — the raw string shows which fields differ between clients.
func GetRaw(remoteAddr string) (string, bool) {
	_, raw, ok := store.get(remoteAddr)
	return raw, ok
}

// Evict removes the fingerprint entry for a remote address.
// Call this when a connection closes to free memory immediately rather
// than waiting for TTL expiry.
func Evict(remoteAddr string) {
	store.evict(remoteAddr)
}

// SetForTest seeds the fingerprint store directly. Only for use in tests —
// avoids the need for a real TLS handshake to populate the store.
func SetForTest(remoteAddr, hash string) {
	store.set(remoteAddr, hash, hash)
}
