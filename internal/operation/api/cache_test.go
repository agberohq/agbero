package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/operation/api"
	"github.com/agberohq/agbero/internal/pkg/stash"
	"github.com/go-chi/chi/v5"
)

// fakeStore — in-process Store for testing without Redis

type fakeStore struct {
	entries map[string]*stash.Entry
	purged  []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{entries: make(map[string]*stash.Entry)}
}

func (f *fakeStore) Get(key string) (*stash.Entry, bool) {
	e, ok := f.entries[key]
	return e, ok
}

func (f *fakeStore) Set(key string, e *stash.Entry, ttl time.Duration) {
	f.entries[key] = e
}

// SetWithPolicy must match the Store interface exactly: *alaye.TTLPolicy not interface{}.
func (f *fakeStore) SetWithPolicy(key string, e *stash.Entry, _ *alaye.TTLPolicy, _ time.Duration) {
	f.entries[key] = e
}

func (f *fakeStore) Delete(key string) { delete(f.entries, key) }
func (f *fakeStore) Clear() error      { f.entries = make(map[string]*stash.Entry); return nil }
func (f *fakeStore) Close() error      { return nil }
func (f *fakeStore) Purge(tag string) error {
	f.purged = append(f.purged, tag)
	for k, e := range f.entries {
		if e.HasTag(tag) {
			delete(f.entries, k)
		}
	}
	return nil
}

// Compile-time interface check.
var _ stash.Store = (*fakeStore)(nil)

// Router helper

func newCacheRouter(store stash.Store) chi.Router {
	r := chi.NewRouter()
	shared := &api.Shared{CacheStore: store}
	api.CacheHandler(shared, r)
	return r
}

func doReq(t *testing.T, r chi.Router, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, path, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, path, nil)
	}
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// DELETE /cache/purge?tag=<tag>

func TestCachePurge_ByTag_Returns200(t *testing.T) {
	store := newFakeStore()
	store.entries["key1"] = &stash.Entry{
		Body:          []byte("content"),
		Status:        200,
		SurrogateTags: []string{"product:1"},
	}

	r := newCacheRouter(store)
	w := doReq(t, r, http.MethodDelete, "/cache/purge?tag=product:1", "")

	if w.Code != http.StatusOK {
		t.Errorf("purge: want 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestCachePurge_ByTag_RemovesMatchingEntries(t *testing.T) {
	store := newFakeStore()
	store.entries["a"] = &stash.Entry{SurrogateTags: []string{"user:99"}}
	store.entries["b"] = &stash.Entry{SurrogateTags: []string{"user:99", "product:1"}}
	store.entries["c"] = &stash.Entry{SurrogateTags: []string{"product:1"}}

	r := newCacheRouter(store)
	doReq(t, r, http.MethodDelete, "/cache/purge?tag=user:99", "")

	if _, ok := store.entries["a"]; ok {
		t.Error("entry a (tagged user:99) should be purged")
	}
	if _, ok := store.entries["b"]; ok {
		t.Error("entry b (tagged user:99) should be purged")
	}
	if _, ok := store.entries["c"]; !ok {
		t.Error("entry c (not tagged user:99) should remain")
	}
}

func TestCachePurge_ResponseBody_ContainsPurgedTag(t *testing.T) {
	store := newFakeStore()
	r := newCacheRouter(store)
	w := doReq(t, r, http.MethodDelete, "/cache/purge?tag=category:books", "")

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response should be valid JSON: %v", err)
	}
	if resp["tag"] != "category:books" {
		t.Errorf("response should include tag=category:books, got %v", resp["tag"])
	}
}

func TestCachePurge_MissingTag_Returns400(t *testing.T) {
	store := newFakeStore()
	r := newCacheRouter(store)
	w := doReq(t, r, http.MethodDelete, "/cache/purge", "")

	if w.Code != http.StatusBadRequest {
		t.Errorf("missing tag: want 400, got %d", w.Code)
	}
}

func TestCachePurge_EmptyTag_Returns400(t *testing.T) {
	store := newFakeStore()
	r := newCacheRouter(store)
	w := doReq(t, r, http.MethodDelete, "/cache/purge?tag=", "")

	if w.Code != http.StatusBadRequest {
		t.Errorf("empty tag: want 400, got %d", w.Code)
	}
}

func TestCachePurge_TagWithNoMatches_Returns200(t *testing.T) {
	store := newFakeStore()
	r := newCacheRouter(store)
	w := doReq(t, r, http.MethodDelete, "/cache/purge?tag=ghost:tag", "")

	if w.Code != http.StatusOK {
		t.Errorf("purge with no matches: want 200, got %d", w.Code)
	}
}

// DELETE /cache — clear all

func TestCacheClearAll_Returns200(t *testing.T) {
	store := newFakeStore()
	store.entries["x"] = &stash.Entry{Status: 200}
	store.entries["y"] = &stash.Entry{Status: 200}

	r := newCacheRouter(store)
	w := doReq(t, r, http.MethodDelete, "/cache", "")

	if w.Code != http.StatusOK {
		t.Errorf("clear all: want 200, got %d", w.Code)
	}
	if len(store.entries) != 0 {
		t.Errorf("all entries should be cleared, %d remain", len(store.entries))
	}
}

// GET /cache/stats

func TestCacheStats_Returns200WithJSON(t *testing.T) {
	store := newFakeStore()
	store.entries["k1"] = &stash.Entry{Status: 200}

	r := newCacheRouter(store)
	w := doReq(t, r, http.MethodGet, "/cache/stats", "")

	if w.Code != http.StatusOK {
		t.Errorf("stats: want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("stats: want application/json, got %q", ct)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("stats: response should be valid JSON: %v", err)
	}
}

// Wrong HTTP methods — 405

func TestCachePurge_WrongMethod_Returns405(t *testing.T) {
	store := newFakeStore()
	r := newCacheRouter(store)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		w := doReq(t, r, method, "/cache/purge?tag=x", "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s on /cache/purge: want 405, got %d", method, w.Code)
		}
	}
}
