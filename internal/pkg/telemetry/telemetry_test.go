package telemetry_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/pkg/telemetry"
)

// ── Store ────────────────────────────────────────────────────────────────────

func TestNewStore_CreatesDB(t *testing.T) {
	dir := t.TempDir()
	s, err := telemetry.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()

	if _, err := os.Stat(dir + "/telemetry.db"); err != nil {
		t.Fatalf("expected telemetry.db to exist: %v", err)
	}
}

func TestStore_RecordAndQuery(t *testing.T) {
	store := newTestStore(t)

	now := time.Now().Unix()
	samples := []telemetry.Sample{
		{Timestamp: now - 120, RequestsSec: 100, P99Ms: 2.1, ErrorRate: 0.0, ActiveBE: 2},
		{Timestamp: now - 60, RequestsSec: 120, P99Ms: 2.5, ErrorRate: 0.1, ActiveBE: 2},
		{Timestamp: now, RequestsSec: 115, P99Ms: 2.3, ErrorRate: 0.0, ActiveBE: 2},
	}

	for _, s := range samples {
		store.Record("example.localhost", s)
	}

	// Give the async write loop time to flush (ticker fires every 5s)
	time.Sleep(6 * time.Second)

	qr := telemetry.KnownRanges["30m"]
	got, err := store.Query("example.localhost", qr)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != len(samples) {
		t.Fatalf("expected %d samples, got %d", len(samples), len(got))
	}
}

func TestStore_QueryUnknownHost(t *testing.T) {
	store := newTestStore(t)

	qr := telemetry.KnownRanges["1h"]
	got, err := store.Query("never-recorded.localhost", qr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 samples for unknown host, got %d", len(got))
	}
}

func TestStore_QueryRespectsCutoff(t *testing.T) {
	store := newTestStore(t)

	now := time.Now().Unix()
	old := now - int64((2 * time.Hour).Seconds()) // 2 hours ago — outside 30m window
	recent := now - 60                            // 1 minute ago — inside

	store.Record("example.localhost", telemetry.Sample{Timestamp: old, RequestsSec: 999})
	store.Record("example.localhost", telemetry.Sample{Timestamp: recent, RequestsSec: 1})

	time.Sleep(6 * time.Second)

	qr := telemetry.KnownRanges["30m"]
	got, err := store.Query("example.localhost", qr)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, s := range got {
		if s.RequestsSec == 999 {
			t.Fatal("old sample (outside cutoff) was returned by Query")
		}
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 in-window sample, got %d", len(got))
	}
}

func TestStore_MultipleHosts(t *testing.T) {
	store := newTestStore(t)

	now := time.Now().Unix()
	store.Record("alpha.localhost", telemetry.Sample{Timestamp: now, RequestsSec: 10})
	store.Record("beta.localhost", telemetry.Sample{Timestamp: now, RequestsSec: 20})

	time.Sleep(6 * time.Second)

	hosts, err := store.Hosts()
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	want := map[string]bool{"alpha.localhost": false, "beta.localhost": false}
	for _, h := range hosts {
		want[h] = true
	}
	for h, seen := range want {
		if !seen {
			t.Errorf("expected host %q in Hosts() result", h)
		}
	}
}

func TestStore_DropsSamplesWhenBufferFull(t *testing.T) {
	// Record well beyond the 256-slot channel without sleeping.
	// Store must never block — excess writes are silently dropped.
	store := newTestStore(t)
	now := time.Now().Unix()
	for i := 0; i < 512; i++ {
		store.Record("flood.localhost", telemetry.Sample{Timestamp: now + int64(i)})
	}
	// Reaching here without deadlock or panic means the test passes.
}

func TestStore_DownSampling(t *testing.T) {
	store := newTestStore(t)

	// Truncate to the minute boundary to guarantee all 10 points
	// (which span 10 seconds) fall within the exact same 1-minute bucket.
	base := time.Now().Truncate(time.Minute).Add(-5 * time.Minute).Unix()
	for i := 0; i < 10; i++ {
		store.Record("ds.localhost", telemetry.Sample{
			Timestamp:   base + int64(i),
			RequestsSec: float64(i),
		})
	}
	time.Sleep(6 * time.Second)

	qr := telemetry.KnownRanges["30m"]
	got, err := store.Query("ds.localhost", qr)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 down-sampled point, got %d", len(got))
	}
}

func TestStore_CloseTwiceNoPanic(t *testing.T) {
	dir := t.TempDir()
	store, err := telemetry.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Close panicked: %v", r)
		}
	}()
	_ = store.Close()
}

// ── KnownRanges ──────────────────────────────────────────────────────────────

func TestKnownRanges_AllPresent(t *testing.T) {
	for _, k := range []string{"30m", "1h", "6h", "24h"} {
		if _, ok := telemetry.KnownRanges[k]; !ok {
			t.Errorf("KnownRanges missing key %q", k)
		}
	}
}

func TestKnownRanges_ResolutionFitsInDuration(t *testing.T) {
	for key, qr := range telemetry.KnownRanges {
		if qr.Resolution > qr.Duration {
			t.Errorf("range %q: resolution %v > duration %v", key, qr.Resolution, qr.Duration)
		}
		if qr.Label == "" {
			t.Errorf("range %q: Label is empty", key)
		}
	}
}

// ── Handler ───────────────────────────────────────────────────────────────────

func TestHandler_HistoryRequiresHost(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history?range=1h", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandler_HistoryRejectsInvalidRange(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history?host=example.localhost&range=999y", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandler_HistoryDefaultsToOneHour(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history?host=example.localhost", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandler_HistoryEmptyArrayNotNull(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history?host=nobody.localhost&range=1h", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"samples":[]`) {
		t.Fatalf("expected samples:[] in body, got: %s", rr.Body.String())
	}
}

func TestHandler_HostsEmptyArrayNotNull(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/hosts", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"hosts":[]`) {
		t.Fatalf("expected hosts:[] in body, got: %s", rr.Body.String())
	}
}

func TestHandler_RejectsPostOnHistory(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/history?host=x&range=1h", bytes.NewReader(nil))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestHandler_RejectsPostOnHosts(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/hosts", bytes.NewReader(nil))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestHandler_ContentTypeIsJSON(t *testing.T) {
	h := telemetry.Handler(newTestStore(t))
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/history?host=x&range=1h", nil)
	h.ServeHTTP(rr, req)
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json Content-Type, got %q", ct)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestStore(t *testing.T) *telemetry.Store {
	t.Helper()
	s, err := telemetry.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("newTestStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
