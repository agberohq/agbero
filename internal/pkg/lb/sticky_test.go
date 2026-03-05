package lb

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewStickySelector(t *testing.T) {
	t.Run("default TTL", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		s := NewSticky(base, 0, nil)
		if s.ttl != 30*time.Minute {
			t.Errorf("expected default TTL 30m, got %v", s.ttl)
		}
		s.Stop()
	})

	t.Run("custom TTL", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		s := NewSticky(base, time.Hour, nil)
		if s.ttl != time.Hour {
			t.Errorf("expected TTL 1h, got %v", s.ttl)
		}
		s.Stop()
	})
}

func TestPickWithSticky(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
	extractor := func(r *http.Request) string {
		if r == nil {
			return ""
		}
		return r.Header.Get("Session-ID")
	}
	s := NewSticky(base, time.Hour, extractor)
	defer s.Stop()

	t.Run("stick to first selected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-1")
		first := s.Pick(req, nil)
		if first == nil {
			t.Fatal("expected backend")
		}
		for i := 0; i < 10; i++ {
			if b := s.Pick(req, nil); b != first {
				t.Error("should stick to same backend")
			}
		}
	})

	t.Run("dead backend triggers reselection", func(t *testing.T) {
		b3 := newMockBackend(3, true, 1)
		b4 := newMockBackend(4, true, 1)
		base2 := NewSelector([]Backend{b3, b4}, StrategyRoundRobin)
		s2 := NewSticky(base2, time.Hour, extractor)
		defer s2.Stop()

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-dead")
		first := s2.Pick(req, nil)
		if first == nil {
			t.Fatal("expected backend")
		}

		if mock, ok := first.(*mockBackend); ok {
			mock.SetAlive(false)
		} else {
			t.Fatal("expected *mockBackend for testing")
		}

		second := s2.Pick(req, nil)
		if second == nil {
			t.Error("expected new backend after death")
		}
		if second == first {
			t.Error("should not return dead backend")
		}
	})
}

func TestStickyUpdate(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)

	extractor := func(r *http.Request) string { return "test-session" }
	s := NewSticky(base, time.Hour, extractor)
	defer s.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	s.Pick(req, nil)

	b3 := newMockBackend(3, true, 1)
	s.Update([]Backend{b3})

	if s.cache.Len() != 0 {
		t.Error("cache should be cleared after update")
	}
}

func TestStickyConcurrency(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)

	extractor := func(r *http.Request) string { return ClientIP(r) }
	s := NewSticky(base, time.Hour, extractor)
	defer s.Stop()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				s.Pick(req, nil)
			}
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
