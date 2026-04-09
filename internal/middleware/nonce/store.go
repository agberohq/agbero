package nonce

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/olekukonko/mappo"
)

const (
	// DefaultNonceTTL is how long a generated nonce remains valid.
	DefaultNonceTTL = time.Hour
	// NonceBytes is the length of the random nonce in bytes (32 → 64 hex chars).
	NonceBytes = 32
)

// nonceEntry holds a nonce value and the time it expires.
type nonceEntry struct {
	value   string
	expires time.Time
}

// Store is a lock-free, single-use nonce store backed by mappo.Concurrent.
//
// Each nonce is consumed on first use. Expired nonces are swept lazily on
// access and periodically by the background goroutine started via StartSweeper.
type Store struct {
	nonces *mappo.Concurrent[string, *nonceEntry]
	ttl    time.Duration
	now    atomic.Value // stores func() time.Time
}

// nowTime safely loads and calls the current time function.
func (s *Store) nowTime() time.Time {
	return s.now.Load().(func() time.Time)()
}

// NewStore creates a Store with the given TTL. Zero → DefaultNonceTTL.
func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	s := &Store{
		nonces: mappo.NewConcurrent[string, *nonceEntry](),
		ttl:    ttl,
	}
	s.now.Store(time.Now)
	return s
}

// Generate creates a cryptographically random nonce, stores it, and returns
// its hex-encoded value. The nonce expires after the store's TTL.
func (s *Store) Generate() (string, error) {
	b := make([]byte, NonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)
	s.nonces.Set(nonce, &nonceEntry{
		value:   nonce,
		expires: s.nowTime().Add(s.ttl),
	})
	return nonce, nil
}

// Consume validates and removes the nonce atomically.
// Returns true only if the nonce exists and has not expired.
// A consumed or unknown nonce returns false.
func (s *Store) Consume(nonce string) bool {
	if nonce == "" {
		return false
	}
	entry, ok := s.nonces.Get(nonce)
	if !ok {
		return false
	}
	s.nonces.Delete(nonce)
	valid := subtle.ConstantTimeCompare([]byte(entry.value), []byte(nonce)) == 1
	return valid && s.nowTime().Before(entry.expires)
}

// Len returns the number of nonces currently in the store. For tests and monitoring.
func (s *Store) Len() int {
	count := 0
	s.nonces.Range(func(_ string, _ *nonceEntry) bool {
		count++
		return true
	})
	return count
}

// sweep removes all expired nonces.
func (s *Store) sweep() {
	now := s.nowTime()
	s.nonces.Range(func(k string, e *nonceEntry) bool {
		if now.After(e.expires) {
			s.nonces.Delete(k)
		}
		return true
	})
}

// StartSweeper launches a background goroutine that cleans up expired nonces
// every interval. The goroutine exits when done is closed.
func (s *Store) StartSweeper(interval time.Duration, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.sweep()
			case <-done:
				return
			}
		}
	}()
}
