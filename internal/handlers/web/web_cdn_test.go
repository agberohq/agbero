package web_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/handlers/web"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/olekukonko/ll"
)

// Helpers

func tmpWebRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func newWebHandler(t *testing.T, root string, route *alaye.Route) http.Handler {
	t.Helper()
	res := &resource.Resource{
		Logger: ll.New("test"),
	}
	return web.NewWeb(res, route, nil)
}

func makeRoute(root string) *alaye.Route {
	return &alaye.Route{
		Enabled: expect.Active,
		Path:    "/",
		Web: alaye.Web{
			Enabled: expect.Active,
			Root:    alaye.WebRoot(root),
		},
	}
}

func get(t *testing.T, h http.Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Accept-Ranges header — required for video/large file range support

func TestWeb_AcceptRanges_StaticFile(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"video.mp4": "fake-video-bytes",
	})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/video.mp4", nil)

	if got := w.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("want Accept-Ranges=bytes, got %q", got)
	}
}

func TestWeb_AcceptRanges_HTMLFile(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"index.html": "<html></html>",
	})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/index.html", nil)

	if got := w.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("HTML: want Accept-Ranges=bytes, got %q", got)
	}
}

func TestWeb_AcceptRanges_LargeFile(t *testing.T) {
	bigContent := strings.Repeat("A", 2*1024*1024) // 2MB
	root := tmpWebRoot(t, map[string]string{
		"big.bin": bigContent,
	})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/big.bin", nil)

	if got := w.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("large file: want Accept-Ranges=bytes, got %q", got)
	}
}

// Range request — partial content (206) for video seeking

func TestWeb_RangeRequest_PartialContent(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"movie.mp4": "0123456789ABCDEF", // 16 bytes
	})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/movie.mp4", map[string]string{
		"Range": "bytes=0-7",
	})

	if w.Code != http.StatusPartialContent {
		t.Errorf("range request: want 206, got %d", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if string(body) != "01234567" {
		t.Errorf("range body: want %q, got %q", "01234567", string(body))
	}
	if got := w.Header().Get("Content-Range"); !strings.HasPrefix(got, "bytes 0-7/") {
		t.Errorf("Content-Range: want bytes 0-7/*, got %q", got)
	}
}

func TestWeb_RangeRequest_TailRange(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"audio.mp3": "ABCDEFGHIJ", // 10 bytes
	})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/audio.mp3", map[string]string{
		"Range": "bytes=-5", // last 5 bytes
	})

	if w.Code != http.StatusPartialContent {
		t.Errorf("tail range: want 206, got %d", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if string(body) != "FGHIJ" {
		t.Errorf("tail range body: want FGHIJ, got %q", string(body))
	}
}

// CacheControl field override on Web block

func TestWeb_CacheControl_DefaultForNonFingerprintedAsset(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"style.css": "body{}",
	})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/style.css", nil)

	cc := w.Header().Get("Cache-Control")
	if cc == "" {
		t.Fatal("Cache-Control should be set for static asset")
	}
	// Default: public, max-age=300
	if !strings.Contains(cc, "public") {
		t.Errorf("default Cache-Control should contain 'public', got %q", cc)
	}
}

func TestWeb_CacheControl_CustomOverride(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"bundle.js": "var x=1",
	})
	route := makeRoute(root)
	route.Web.CacheControl = "public, max-age=86400, s-maxage=604800"

	h := newWebHandler(t, root, route)
	w := get(t, h, "/bundle.js", nil)

	cc := w.Header().Get("Cache-Control")
	if cc != "public, max-age=86400, s-maxage=604800" {
		t.Errorf("custom CacheControl: want override, got %q", cc)
	}
}

func TestWeb_CacheControl_FingerprintedFileIsImmutable(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"app.abc12345.js": "var x=1",
	})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/app.abc12345.js", nil)

	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Errorf("fingerprinted file: want immutable, got %q", cc)
	}
}

func TestWeb_CacheControl_NoCache_WhenRouteDisabled(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{
		"page.html": "<html/>",
	})
	route := makeRoute(root)
	route.Web.NoCache = expect.Active

	h := newWebHandler(t, root, route)
	w := get(t, h, "/page.html", nil)

	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("no_cache route: want no-store, got %q", cc)
	}
}

// MIME types for video/audio (CDN large-file support)

func TestWeb_MIME_VideoMP4(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{"clip.mp4": "data"})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/clip.mp4", nil)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "video/mp4") {
		t.Errorf("want video/mp4, got %q", ct)
	}
}

func TestWeb_MIME_VideoWebM(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{"clip.webm": "data"})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/clip.webm", nil)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "video/webm") {
		t.Errorf("want video/webm, got %q", ct)
	}
}

func TestWeb_MIME_AudioFLAC(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{"track.flac": "data"})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/track.flac", nil)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "audio/flac") {
		t.Errorf("want audio/flac, got %q", ct)
	}
}

func TestWeb_MIME_AudioAAC(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{"track.aac": "data"})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/track.aac", nil)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "audio/aac") {
		t.Errorf("want audio/aac, got %q", ct)
	}
}

// ETag — present on all static responses

func TestWeb_ETag_PresentOnStaticFile(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{"data.json": `{"ok":true}`})
	h := newWebHandler(t, root, makeRoute(root))
	w := get(t, h, "/data.json", nil)

	if etag := w.Header().Get("ETag"); etag == "" {
		t.Error("ETag should be present on static file response")
	}
}

func TestWeb_ETag_ConsistentAcrossRequests(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{"file.txt": "hello"})
	h := newWebHandler(t, root, makeRoute(root))

	w1 := get(t, h, "/file.txt", nil)
	w2 := get(t, h, "/file.txt", nil)

	if w1.Header().Get("ETag") != w2.Header().Get("ETag") {
		t.Error("ETag should be consistent across requests for unchanged file")
	}
}

func TestWeb_304_OnMatchingETag(t *testing.T) {
	root := tmpWebRoot(t, map[string]string{"page.html": "<html/>"})
	h := newWebHandler(t, root, makeRoute(root))

	// Get the ETag first
	w1 := get(t, h, "/page.html", nil)
	etag := w1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on first response")
	}

	// Second request with If-None-Match
	w2 := get(t, h, "/page.html", map[string]string{"If-None-Match": etag})
	if w2.Code != http.StatusNotModified {
		t.Errorf("matching ETag: want 304, got %d", w2.Code)
	}
}

// Dynamic gzip — does NOT read entire file into memory for large files

func TestWeb_LargeFile_NotBufferedForDynamicGzip(t *testing.T) {
	// A file larger than DynamicGzMaxSize should bypass in-memory gzip
	// and be streamed directly via http.ServeContent
	bigContent := strings.Repeat("Z", 11*1024*1024) // 11MB > 10MB limit
	root := tmpWebRoot(t, map[string]string{"huge.txt": bigContent})
	h := newWebHandler(t, root, makeRoute(root))

	w := get(t, h, "/huge.txt", map[string]string{
		"Accept-Encoding": "gzip",
	})

	// Should respond 200, not error — and NOT be gzip-encoded (file too large)
	if w.Code != http.StatusOK {
		t.Errorf("large file: want 200, got %d", w.Code)
	}
	// If Content-Encoding is gzip here it means we buffered the whole file — wrong
	if ce := w.Header().Get("Content-Encoding"); ce == "gzip" {
		t.Error("file over DynamicGzMaxSize should not be dynamically gzip-compressed (avoids full memory load)")
	}
}
