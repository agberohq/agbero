package nonce

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Store

func TestStore_GenerateAndConsume(t *testing.T) {
	s := NewStore(time.Minute)
	nonce, err := s.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(nonce) != NonceBytes*2 {
		t.Fatalf("nonce length: got %d want %d", len(nonce), NonceBytes*2)
	}
	if !s.Consume(nonce) {
		t.Fatal("first Consume must return true")
	}
	if s.Consume(nonce) {
		t.Fatal("second Consume must return false (single-use)")
	}
}

func TestStore_ConsumeUnknown(t *testing.T) {
	if NewStore(time.Minute).Consume("unknown") {
		t.Fatal("unknown nonce must return false")
	}
}

func TestStore_ConsumeEmpty(t *testing.T) {
	if NewStore(time.Minute).Consume("") {
		t.Fatal("empty nonce must return false")
	}
}

func TestStore_Expired(t *testing.T) {
	s := NewStore(time.Second)
	now := time.Now()
	s.now.Store(func() time.Time { return now })
	nonce, _ := s.Generate()
	s.now.Store(func() time.Time { return now.Add(2 * time.Second) })
	if s.Consume(nonce) {
		t.Fatal("expired nonce must return false")
	}
}

func TestStore_WithinTTL(t *testing.T) {
	s := NewStore(time.Hour)
	now := time.Now()
	s.now.Store(func() time.Time { return now })
	nonce, _ := s.Generate()
	s.now.Store(func() time.Time { return now.Add(30 * time.Minute) })
	if !s.Consume(nonce) {
		t.Fatal("nonce within TTL must return true")
	}
}

func TestStore_Uniqueness(t *testing.T) {
	s := NewStore(time.Minute)
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		n, err := s.Generate()
		if err != nil {
			t.Fatalf("Generate[%d]: %v", i, err)
		}
		if _, dup := seen[n]; dup {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		seen[n] = struct{}{}
	}
}

func TestStore_Len(t *testing.T) {
	s := NewStore(time.Minute)
	if s.Len() != 0 {
		t.Fatal("empty store must have Len 0")
	}
	s.Generate()
	s.Generate()
	if s.Len() != 2 {
		t.Fatalf("want Len 2, got %d", s.Len())
	}
}

func TestStore_Sweep(t *testing.T) {
	s := NewStore(time.Second)
	now := time.Now()
	s.now.Store(func() time.Time { return now })
	s.Generate()
	s.Generate()
	s.now.Store(func() time.Time { return now.Add(2 * time.Second) })
	s.sweep()
	if s.Len() != 0 {
		t.Fatalf("after sweep want Len 0, got %d", s.Len())
	}
}

func TestStore_SweepOnlyExpired(t *testing.T) {
	s := NewStore(time.Hour)
	now := time.Now()
	s.now.Store(func() time.Time { return now })
	old, _ := s.Generate()
	s.nonces.Set(old, &nonceEntry{value: old, expires: now.Add(time.Second)})
	s.Generate() // expires in 1h

	s.now.Store(func() time.Time { return now.Add(2 * time.Second) })
	s.sweep()
	if s.Len() != 1 {
		t.Fatalf("want 1 entry after partial sweep, got %d", s.Len())
	}
}

func TestStore_StartSweeper(t *testing.T) {
	s := NewStore(time.Millisecond)
	now := time.Now()
	s.now.Store(func() time.Time { return now })
	s.Generate()
	done := make(chan struct{})
	s.StartSweeper(5*time.Millisecond, done)
	s.now.Store(func() time.Time { return now.Add(time.Second) })
	time.Sleep(20 * time.Millisecond)
	close(done)
	if s.Len() != 0 {
		t.Fatalf("sweeper: want Len 0, got %d", s.Len())
	}
}

func TestStore_DefaultTTL(t *testing.T) {
	if NewStore(0).ttl != DefaultNonceTTL {
		t.Fatalf("zero TTL must default to %v", DefaultNonceTTL)
	}
}

// Guard helpers

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func serve(t *testing.T, h http.Handler, hdrs map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// meta

func TestMetaGuard_Valid(t *testing.T) {
	s := NewStore(time.Minute)
	nonce, _ := s.Generate()
	rr := serve(t, NewMetaGuard(s).Middleware(okHandler()),
		map[string]string{testNonceHeader: nonce})
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestMetaGuard_Missing(t *testing.T) {
	s := NewStore(time.Minute)
	rr := serve(t, NewMetaGuard(s).Middleware(okHandler()), nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestMetaGuard_SingleUse(t *testing.T) {
	s := NewStore(time.Minute)
	nonce, _ := s.Generate()
	h := NewMetaGuard(s).Middleware(okHandler())
	hdrs := map[string]string{testNonceHeader: nonce}
	if serve(t, h, hdrs).Code != http.StatusOK {
		t.Fatal("first use must succeed")
	}
	if serve(t, h, hdrs).Code != http.StatusUnauthorized {
		t.Fatal("second use must fail")
	}
}

func TestMetaGuard_Expired(t *testing.T) {
	s := NewStore(time.Millisecond)
	now := time.Now()
	s.now.Store(func() time.Time { return now })
	nonce, _ := s.Generate()
	s.now.Store(func() time.Time { return now.Add(time.Second) })
	rr := serve(t, NewMetaGuard(s).Middleware(okHandler()),
		map[string]string{testNonceHeader: nonce})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expired nonce: want 401, got %d", rr.Code)
	}
}

// token

func TestTokenGuard_Valid(t *testing.T) {
	g := NewTokenGuard(func(tok string) bool { return tok == "good" })
	rr := serve(t, g.Middleware(okHandler()),
		map[string]string{"Authorization": "Bearer good"})
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestTokenGuard_Invalid(t *testing.T) {
	g := NewTokenGuard(func(tok string) bool { return tok == "good" })
	rr := serve(t, g.Middleware(okHandler()),
		map[string]string{"Authorization": "Bearer bad"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestTokenGuard_Missing(t *testing.T) {
	g := NewTokenGuard(func(tok string) bool { return true })
	rr := serve(t, g.Middleware(okHandler()), nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestTokenGuard_NilVerifier(t *testing.T) {
	g := NewTokenGuard(nil)
	rr := serve(t, g.Middleware(okHandler()),
		map[string]string{"Authorization": "Bearer anything"})
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("nil verifier: want 500, got %d", rr.Code)
	}
}

// direct

func TestDirectGuard_WithCookie(t *testing.T) {
	g := NewDirectGuard()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: testSessionCookie, Value: "sess-value"})
	rr := httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestDirectGuard_Missing(t *testing.T) {
	rr := serve(t, NewDirectGuard().Middleware(okHandler()), nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestDirectGuard_EmptyCookie(t *testing.T) {
	g := NewDirectGuard()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: testSessionCookie, Value: ""})
	rr := httptest.NewRecorder()
	g.Middleware(okHandler()).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("empty cookie: want 401, got %d", rr.Code)
	}
}

// unknown method

func TestGuard_UnknownMethod(t *testing.T) {
	g := &Guard{method: "unknown"}
	rr := serve(t, g.Middleware(okHandler()), nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("unknown method: want 500, got %d", rr.Code)
	}
}

// local constants (mirror woos to avoid import cycle)

const (
	testNonceHeader   = "X-Agbero-Replay-Nonce"
	testSessionCookie = "agbero_sess"
)
