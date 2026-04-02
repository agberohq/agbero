package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/hub/resource"
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// newTestRoot returns a temporary directory. t.TempDir() cleans up automatically.
func newTestRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// writeFile writes content to path (relative to root), creating parents as needed.
func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", full, err)
	}
}

// writeGzip writes a valid gzip-compressed version of content at path.
func writeGzip(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	f, err := os.Create(full)
	if err != nil {
		t.Fatalf("create gzip %s: %v", full, err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	_ = gz.Close()
	_ = f.Close()
}

// routeOpt is a functional option for newHandler.
type routeOpt func(*alaye.Route)

// newHandler builds a *web handler pointing at rootPath with optional route tweaks.
// It calls NewWeb so all derived state (mdConverter, phpClientFactory, etc.) is
// properly initialised — exactly as in production.
func newHandler(t *testing.T, rootPath string, opts ...routeOpt) *web {
	t.Helper()
	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(rootPath),
		},
	}
	for _, o := range opts {
		o(route)
	}
	res := resource.New()
	return NewWeb(res, route, nil)
}

func withListing() routeOpt  { return func(r *alaye.Route) { r.Web.Listing = true } }
func withSPA() routeOpt      { return func(r *alaye.Route) { r.Web.SPA = true } }
func withMarkdown() routeOpt { return func(r *alaye.Route) { r.Web.Markdown.Enabled = alaye.Active } }
func withMarkdownBrowse() routeOpt {
	return func(r *alaye.Route) {
		r.Web.Markdown.Enabled = alaye.Active
		r.Web.Markdown.View = "browse"
	}
}
func withSyntaxHighlight() routeOpt {
	return func(r *alaye.Route) {
		r.Web.Markdown.Enabled = alaye.Active
		r.Web.Markdown.SyntaxHighlight.Enabled = alaye.Active
		// Theme defaults to "github" when empty — no need to set it in tests.
	}
}
func withTOC() routeOpt {
	return func(r *alaye.Route) {
		r.Web.Markdown.Enabled = alaye.Active
		r.Web.Markdown.TableOfContents = alaye.Active
	}
}

// do fires a request at h and returns the recorded response.
func do(t *testing.T, h http.Handler, method, path string, hdrs ...http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for _, hdr := range hdrs {
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func acceptGzip() http.Header {
	h := http.Header{}
	h.Set("Accept-Encoding", "gzip")
	return h
}

// decompressGzip reads and decompresses a gzip body from rr.
func decompressGzip(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	gr, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
	got, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	return string(got)
}

// Pure unit tests — no HTTP, no filesystem

func TestIsMarkdownPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"README.md", true},
		{"docs/guide.markdown", true},
		{"page.mdown", true},
		{"note.mkd", true},
		{"index.html", false},
		{"script.js", false},
		{"style.css", false},
		{"noext", false},
		{"UPPER.MD", true}, // case-insensitive
		{"file.MD", true},
	}
	for _, tc := range cases {
		if got := isMarkdownPath(tc.path); got != tc.want {
			t.Errorf("isMarkdownPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIsCompressibleMIME(t *testing.T) {
	yes := []string{
		"text/html", "text/css", "text/plain",
		"application/javascript", "application/json",
		"application/xml", "application/xhtml+xml",
		"application/wasm", "image/svg+xml",
	}
	no := []string{
		"image/png", "image/jpeg", "video/mp4",
		"application/octet-stream", "application/zip",
	}
	for _, mt := range yes {
		if !isCompressibleMIME(mt) {
			t.Errorf("isCompressibleMIME(%q) want true", mt)
		}
	}
	for _, mt := range no {
		if isCompressibleMIME(mt) {
			t.Errorf("isCompressibleMIME(%q) want false", mt)
		}
	}
}

func TestStrongETag_Format(t *testing.T) {
	tag := weakETag("/tmp/test.css", 1234, time.Unix(1700000000, 0))
	if !strings.HasPrefix(tag, `W/"`) || !strings.HasSuffix(tag, `"`) {
		t.Errorf("ETag format wrong: %s", tag)
	}
}

func TestStrongETag_DifferentSizes(t *testing.T) {
	mt := time.Unix(1700000000, 0)
	if weakETag("/a", 100, mt) == weakETag("/a", 200, mt) {
		t.Error("ETags must differ when size differs")
	}
}

func TestStrongETag_DifferentModTimes(t *testing.T) {
	if weakETag("/a", 100, time.Unix(1, 0)) == weakETag("/a", 100, time.Unix(2, 0)) {
		t.Error("ETags must differ when modtime differs")
	}
}

func TestBuildBreadcrumbs_Root(t *testing.T) {
	h := newHandler(t, t.TempDir())
	crumbs := h.buildBreadcrumbs("/")
	if len(crumbs) != 1 || crumbs[0].Name != "root" || crumbs[0].Href != "/" {
		t.Errorf("unexpected root breadcrumb: %+v", crumbs)
	}
}

func TestBuildBreadcrumbs_Deep(t *testing.T) {
	h := newHandler(t, t.TempDir())
	crumbs := h.buildBreadcrumbs("/docs/api/v2/")
	if len(crumbs) != 4 {
		t.Fatalf("want 4 crumbs, got %d: %+v", len(crumbs), crumbs)
	}
	if crumbs[0].Href != "/" {
		t.Errorf("first crumb href: want /, got %s", crumbs[0].Href)
	}
	if crumbs[3].Name != "v2" || crumbs[3].Href != "/docs/api/v2/" {
		t.Errorf("last crumb wrong: %+v", crumbs[3])
	}
}

func TestDetectContentType_HTML(t *testing.T) {
	f := writeTempFile(t, "<html><head></head><body>hello</body></html>")
	defer os.Remove(f.Name())
	mt := detectContentType(f)
	if !strings.HasPrefix(mt, "text/html") {
		t.Errorf("want text/html, got %s", mt)
	}
}

func TestDetectContentType_Empty(t *testing.T) {
	f := writeTempFile(t, "")
	defer os.Remove(f.Name())
	if detectContentType(f) != "application/octet-stream" {
		t.Error("empty file should be octet-stream")
	}
}

func writeTempFile(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp("", "webtest-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek temp: %v", err)
	}
	return f
}

// HTTP integration tests

func TestServeHTTP_MethodNotAllowed(t *testing.T) {
	h := newHandler(t, newTestRoot(t))
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rr := do(t, h, method, "/")
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: want 405, got %d", method, rr.Code)
		}
	}
}

func TestServeHTTP_HeadAllowed(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.html", "<html>hi</html>")
	h := newHandler(t, root)
	rr := do(t, h, http.MethodHead, "/")
	if rr.Code != http.StatusOK && rr.Code != http.StatusNotModified {
		t.Errorf("HEAD /: want 200/304, got %d", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD body must be empty, got %d bytes", rr.Body.Len())
	}
}

func TestServeHTTP_StaticFile(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "hello.txt", "hello world")
	h := newHandler(t, root)
	rr := do(t, h, http.MethodGet, "/hello.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if rr.Body.String() != "hello world" {
		t.Errorf("body mismatch: %q", rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type: want text/plain, got %s", ct)
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options: nosniff missing")
	}
}

func TestServeHTTP_NotFound(t *testing.T) {
	rr := do(t, newHandler(t, newTestRoot(t)), http.MethodGet, "/nonexistent.txt")
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", rr.Code)
	}
}

func TestServeHTTP_DotfileBlocked(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, ".secret", "hidden")
	rr := do(t, newHandler(t, root), http.MethodGet, "/.secret")
	if rr.Code != http.StatusForbidden {
		t.Errorf("dotfile: want 403, got %d", rr.Code)
	}
}

func TestServeHTTP_WellKnownAllowed(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, ".well-known/acme-challenge/token", "abc123")
	rr := do(t, newHandler(t, root), http.MethodGet, "/.well-known/acme-challenge/token")
	if rr.Code != http.StatusOK {
		t.Errorf(".well-known: want 200, got %d", rr.Code)
	}
}

func TestServeHTTP_PathTraversal(t *testing.T) {
	root := newTestRoot(t)
	h := newHandler(t, root)
	for _, path := range []string{"/../etc/passwd", "/../../secret"} {
		rr := do(t, h, http.MethodGet, path)
		if rr.Code == http.StatusOK {
			t.Errorf("traversal %q: must not return 200", path)
		}
	}
}

func TestServeHTTP_IndexHTML(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.html", "<html>home</html>")
	rr := do(t, newHandler(t, root), http.MethodGet, "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "home") {
		t.Error("index.html content missing")
	}
}

func TestServeHTTP_DirRedirect(t *testing.T) {
	root := newTestRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "docs/index.html", "<html>docs</html>")
	rr := do(t, newHandler(t, root), http.MethodGet, "/docs")
	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("dir without slash: want 301, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.HasSuffix(loc, "/docs/") {
		t.Errorf("redirect should end in /docs/, got %s", loc)
	}
}

func TestServeHTTP_DirForbiddenWhenListingDisabled(t *testing.T) {
	root := newTestRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	rr := do(t, newHandler(t, root), http.MethodGet, "/private/")
	if rr.Code != http.StatusForbidden {
		t.Errorf("unlisted dir: want 403, got %d", rr.Code)
	}
}

func TestServeHTTP_DirectoryListing(t *testing.T) {
	root := newTestRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "files/alpha.txt", "a")
	writeFile(t, root, "files/beta.txt", "b")
	h := newHandler(t, root, withListing())
	rr := do(t, h, http.MethodGet, "/files/")
	if rr.Code != http.StatusOK {
		t.Fatalf("listing: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alpha.txt") || !strings.Contains(body, "beta.txt") {
		t.Errorf("listing missing filenames; snippet: %.200s", body)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("listing Content-Type: want text/html, got %s", ct)
	}
}

func TestServeHTTP_DirectoryListing_HidesDotfiles(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, ".hidden", "secret")
	writeFile(t, root, "visible.txt", "hi")
	h := newHandler(t, root, withListing())
	rr := do(t, h, http.MethodGet, "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("listing root: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, ".hidden") {
		t.Error("listing must not expose dotfiles")
	}
	if !strings.Contains(body, "visible.txt") {
		t.Error("listing must show visible.txt")
	}
}

func TestServeHTTP_SPAFallback(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.html", "<html>spa</html>")
	h := newHandler(t, root, withSPA())
	rr := do(t, h, http.MethodGet, "/app/deep/route")
	if rr.Code != http.StatusOK {
		t.Fatalf("SPA fallback: want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "spa") {
		t.Error("SPA fallback should serve index.html")
	}
}

func TestServeHTTP_CacheControlImmutable(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "app._a1b2c3d4_.js", "console.log('hi')")
	rr := do(t, newHandler(t, root), http.MethodGet, "/app._a1b2c3d4_.js")
	cc := rr.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Errorf("fingerprinted asset should be immutable: %s", cc)
	}
}

func TestServeHTTP_CacheControlHTML(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "page.html", "<html></html>")
	rr := do(t, newHandler(t, root), http.MethodGet, "/page.html")
	cc := rr.Header().Get("Cache-Control")
	if !strings.Contains(cc, "must-revalidate") {
		t.Errorf("HTML should have must-revalidate: %s", cc)
	}
	if strings.Contains(cc, "immutable") {
		t.Errorf("HTML must not be immutable: %s", cc)
	}
}

func TestServeHTTP_ETagPresent(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "data.json", `{"ok":true}`)
	rr := do(t, newHandler(t, root), http.MethodGet, "/data.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Error("ETag header must be set")
	}
	if !strings.HasPrefix(etag, `W/"`) {
		t.Errorf("ETag must be weak (W/\"...\"), got %s", etag)
	}
}

func TestServeHTTP_ConditionalGet304(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "style.css", "body{}")
	h := newHandler(t, root)

	rr1 := do(t, h, http.MethodGet, "/style.css")
	etag := rr1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag from first request")
	}

	req := httptest.NewRequest(http.MethodGet, "/style.css", nil)
	req.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)

	if rr2.Code != http.StatusNotModified {
		t.Errorf("conditional GET: want 304, got %d", rr2.Code)
	}
	if rr2.Body.Len() != 0 {
		t.Error("304 response must have no body")
	}
}

func TestServeHTTP_PrecompressedGzip(t *testing.T) {
	root := newTestRoot(t)
	original := "body { color: red; }"
	writeFile(t, root, "style.css", original)
	writeGzip(t, root, "style.css.gz", original)
	h := newHandler(t, root)

	rr := do(t, h, http.MethodGet, "/style.css", acceptGzip())
	if rr.Code != http.StatusOK {
		t.Fatalf("pre-gz: want 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Error("pre-gz: Content-Encoding must be gzip")
	}
	if got := decompressGzip(t, rr); got != original {
		t.Errorf("decompressed mismatch: got %q", got)
	}
}

func TestServeHTTP_NoGzipWhenNotAccepted(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "style.css", "body{}")
	writeGzip(t, root, "style.css.gz", "body{}")
	rr := do(t, newHandler(t, root), http.MethodGet, "/style.css") // no Accept-Encoding
	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Error("must not serve gzip when not accepted")
	}
}

func TestServeHTTP_DynamicGzip(t *testing.T) {
	root := newTestRoot(t)
	// Must be >= dynamicGzMinSize (1024 bytes) to trigger on-the-fly compression.
	js := strings.Repeat("console.log('hello world');\n", 50) // ~1400 bytes
	writeFile(t, root, "app.js", js)
	h := newHandler(t, root)

	rr := do(t, h, http.MethodGet, "/app.js", acceptGzip())
	if rr.Code != http.StatusOK {
		t.Fatalf("dynamic gz: want 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("dynamic gz: Content-Encoding must be gzip, got %q", rr.Header().Get("Content-Encoding"))
	}
	if got := decompressGzip(t, rr); got != js {
		t.Errorf("dynamic gz: content mismatch (%d bytes vs %d expected)", len(got), len(js))
	}
}

func TestServeHTTP_DynamicGzip_SmallFileSkipped(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "tiny.js", "var x=1;") // well below 1024 bytes
	rr := do(t, newHandler(t, root), http.MethodGet, "/tiny.js", acceptGzip())
	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Error("tiny file must not be dynamically gzip'd")
	}
}

func TestServeHTTP_DynamicGzip_NonCompressibleSkipped(t *testing.T) {
	root := newTestRoot(t)
	// Large enough, but PNG is not a compressible MIME type.
	png := bytes.Repeat([]byte{0x89, 0x50, 0x4e, 0x47}, 512)
	if err := os.WriteFile(filepath.Join(root, "image.png"), png, 0o644); err != nil {
		t.Fatal(err)
	}
	rr := do(t, newHandler(t, root), http.MethodGet, "/image.png", acceptGzip())
	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Error("PNG must not be dynamically gzip'd")
	}
}

func TestServeHTTP_Markdown_Rendered(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "README.md", "# Hello\n\nThis is **bold**.")
	h := newHandler(t, root, withMarkdown())
	rr := do(t, h, http.MethodGet, "/README.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("markdown: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<h1") {
		t.Error("markdown: expected <h1> in output")
	}
	if !strings.Contains(body, "<strong>") {
		t.Error("markdown: expected <strong> in output")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("markdown: Content-Type must be text/html, got %s", ct)
	}
}

func TestServeHTTP_Markdown_DisabledServesRaw(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "README.md", "# Hello")
	// Markdown renderer not enabled — raw source should be served.
	rr := do(t, newHandler(t, root), http.MethodGet, "/README.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "<h1") {
		t.Error("markdown disabled: must not render HTML")
	}
	if !strings.Contains(body, "# Hello") {
		t.Error("markdown disabled: must serve raw source")
	}
}

func TestServeHTTP_Markdown_GFMTable(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "table.md", "| A | B |\n|---|---|\n| 1 | 2 |\n")
	h := newHandler(t, root, withMarkdown())
	rr := do(t, h, http.MethodGet, "/table.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<table") {
		t.Error("GFM table: expected <table> in output")
	}
}

func TestServeHTTP_Markdown_AllExtensions(t *testing.T) {
	root := newTestRoot(t)
	for _, name := range []string{"doc.markdown", "doc.mdown", "doc.mkd"} {
		writeFile(t, root, name, "# "+name)
	}
	h := newHandler(t, root, withMarkdown())
	for _, name := range []string{"doc.markdown", "doc.mdown", "doc.mkd"} {
		rr := do(t, h, http.MethodGet, "/"+name)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d", name, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "<h1") {
			t.Errorf("%s: expected rendered HTML", name)
		}
	}
}

// TestServeHTTP_Markdown_DownloadQueryBypassesRenderer verifies that
// ?download causes the raw Markdown source to be served as a file download
// instead of being rendered as HTML.
func TestServeHTTP_Markdown_SyntaxHighlight(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "code.md", "```go\npackage main\n\nfunc main() {}\n```")
	h := newHandler(t, root, withSyntaxHighlight())
	rr := do(t, h, http.MethodGet, "/code.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("highlight: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// Chroma emits <span style="color:#..."> inline token colours.
	if !strings.Contains(body, "<span") {
		t.Error("syntax highlight: expected Chroma <span> elements in output")
	}
	// chromaPreWrapper emits <pre class="chroma"> with no inline style.
	// Extract only the opening <pre...> tag and verify it carries no style attribute.
	preStart := strings.Index(body, "<pre")
	if preStart != -1 {
		preEnd := strings.Index(body[preStart:], ">")
		if preEnd != -1 {
			preTag := body[preStart : preStart+preEnd+1]
			if strings.Contains(preTag, `style="`) {
				t.Errorf("syntax highlight: <pre> must have no inline style, got: %s", preTag)
			}
		}
	}
}

func TestServeHTTP_Markdown_SyntaxHighlight_Disabled_NoSpans(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "code.md", "```go\npackage main\n\nfunc main() {}\n```")
	h := newHandler(t, root, withMarkdown()) // highlight off
	rr := do(t, h, http.MethodGet, "/code.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// Without highlighting: plain <pre><code>, no Chroma spans.
	if !strings.Contains(body, "<pre>") && !strings.Contains(body, "<pre ") {
		t.Error("code block must still be wrapped in <pre>")
	}
	if strings.Contains(body, `class="chroma"`) || strings.Contains(body, `style="color`) {
		t.Error("highlight disabled: must not contain Chroma output")
	}
}

func TestServeHTTP_Markdown_TOC(t *testing.T) {
	root := newTestRoot(t)
	md := "# Alpha\n\n## Beta\n\n### Gamma\n\nsome text"
	writeFile(t, root, "doc.md", md)
	h := newHandler(t, root, withTOC())
	rr := do(t, h, http.MethodGet, "/doc.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("toc: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// goldmark-toc injects a "Table of Contents" heading followed by a <ul>
	// list of anchor links. It does not wrap in <nav>.
	if !strings.Contains(body, "Table of Contents") {
		t.Error("TOC: expected 'Table of Contents' heading in output")
	}
	// The TOC list must contain anchor links to the headings.
	if !strings.Contains(body, "Alpha") || !strings.Contains(body, "Beta") {
		t.Error("TOC: expected heading names in TOC list")
	}
	// Links must reference heading anchors (href="#...").
	if !strings.Contains(body, `href="#`) {
		t.Error("TOC: expected anchor href links in output")
	}
}

func TestServeHTTP_Markdown_TOC_Disabled_NoTOC(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "doc.md", "# Alpha\n\n## Beta\n\nsome text")
	h := newHandler(t, root, withMarkdown()) // TOC off
	rr := do(t, h, http.MethodGet, "/doc.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "Table of Contents") {
		t.Error("TOC disabled: must not contain TOC heading")
	}
}

func TestServeHTTP_Markdown_NormalView_NoChrome(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "README.md", "# Hello\n\nThis is **bold**.")
	h := newHandler(t, root, withMarkdown()) // default: normal view
	rr := do(t, h, http.MethodGet, "/README.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("normal view: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<h1") {
		t.Error("normal view: markdown must be rendered")
	}
	// Normal view must NOT contain browse-mode chrome.
	if strings.Contains(body, "breadcrumb") {
		t.Error("normal view: must not contain breadcrumb navigation")
	}
	if strings.Contains(body, "?download") {
		t.Error("normal view: must not contain raw download link")
	}
	if strings.Contains(body, "toggleTheme") {
		t.Error("normal view: must not contain theme toggle")
	}
}

func TestServeHTTP_Markdown_BrowseView_HasChrome(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "README.md", "# Hello\n\nThis is **bold**.")
	h := newHandler(t, root, withMarkdownBrowse())
	rr := do(t, h, http.MethodGet, "/README.md")
	if rr.Code != http.StatusOK {
		t.Fatalf("browse view: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<h1") {
		t.Error("browse view: markdown must be rendered")
	}
	// Browse view must contain all navigation chrome.
	if !strings.Contains(body, "breadcrumb") {
		t.Error("browse view: must contain breadcrumb navigation")
	}
	if !strings.Contains(body, "?download") {
		t.Error("browse view: must contain raw download link")
	}
	if !strings.Contains(body, "toggleTheme") {
		t.Error("browse view: must contain theme toggle")
	}
}

func TestServeHTTP_Markdown_DownloadQueryBypassesRenderer(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "README.md", "# Hello\n\nThis is **bold**.")
	h := newHandler(t, root, withMarkdown())

	rr := do(t, h, http.MethodGet, "/README.md?download")
	if rr.Code != http.StatusOK {
		t.Fatalf("?download: want 200, got %d", rr.Code)
	}

	// Must serve raw Markdown, not HTML.
	body := rr.Body.String()
	if strings.Contains(body, "<h1") {
		t.Error("?download: must not render HTML")
	}
	if !strings.Contains(body, "# Hello") {
		t.Error("?download: must contain raw Markdown source")
	}

	// Must set Content-Disposition: attachment.
	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment") {
		t.Errorf("?download: Content-Disposition must be attachment, got %q", cd)
	}
	if !strings.Contains(cd, "README.md") {
		t.Errorf("?download: Content-Disposition must include filename, got %q", cd)
	}
}

// TestServeHTTP_DownloadQuery_StaticFile verifies ?download works on any file,
// not just Markdown — the filename must appear in Content-Disposition.
func TestServeHTTP_DownloadQuery_StaticFile(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "report.pdf", "%PDF-1.4")
	rr := do(t, newHandler(t, root), http.MethodGet, "/report.pdf?download")
	if rr.Code != http.StatusOK {
		t.Fatalf("?download static: want 200, got %d", rr.Code)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment") {
		t.Errorf("?download static: Content-Disposition must be attachment, got %q", cd)
	}
	if !strings.Contains(cd, "report.pdf") {
		t.Errorf("?download static: filename missing from Content-Disposition, got %q", cd)
	}
}

// TestServeHTTP_DownloadQuery_SkipsGzip ensures ?download never returns a
// gzip-compressed body even when the client accepts gzip and a .gz sidecar exists.
func TestServeHTTP_DownloadQuery_SkipsGzip(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "style.css", "body{}")
	writeGzip(t, root, "style.css.gz", "body{}")
	rr := do(t, newHandler(t, root), http.MethodGet, "/style.css?download", acceptGzip())
	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Error("?download must not serve gzip encoding")
	}
}

func TestServeHTTP_XContentTypeOptions(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "data.bin", "\x00\x01\x02\x03")
	rr := do(t, newHandler(t, root), http.MethodGet, "/data.bin")
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options: nosniff must be set on all responses")
	}
}

func TestServeHTTP_MIMEFallbackNeverEmpty(t *testing.T) {
	root := newTestRoot(t)
	// .xyz has no registered MIME type — must fall back rather than return "".
	writeFile(t, root, "file.xyz", strings.Repeat("x", 100))
	rr := do(t, newHandler(t, root), http.MethodGet, "/file.xyz")
	ct := rr.Header().Get("Content-Type")
	if ct == "" {
		t.Error("Content-Type must never be empty")
	}
	t.Logf("Content-Type for .xyz: %s", ct)
}

func TestServeHTTP_VaryHeader_Gzip(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "style.css", "body{}")
	writeGzip(t, root, "style.css.gz", "body{}")
	rr := do(t, newHandler(t, root), http.MethodGet, "/style.css", acceptGzip())
	vary := rr.Header().Get("Vary")
	if !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("gzip response must have Vary: Accept-Encoding, got %q", vary)
	}
}

// index.md rendering

func TestServeHTTP_IndexMd_RenderedWhenMarkdownEnabled(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.md", "# Welcome\n\nThis is the home page.")
	h := newHandler(t, root, withMarkdown(), func(r *alaye.Route) {
		r.Web.Index = []string{"index.md"}
	})
	rr := do(t, h, http.MethodGet, "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("index.md: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<h1") {
		t.Error("index.md: expected rendered <h1> in output")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("index.md: Content-Type must be text/html, got %s", ct)
	}
}

func TestServeHTTP_IndexMd_RawWhenMarkdownDisabled(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.md", "# Welcome")
	h := newHandler(t, root, func(r *alaye.Route) {
		r.Web.Index = []string{"index.md"}
	})
	rr := do(t, h, http.MethodGet, "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "<h1") {
		t.Error("index.md with markdown disabled: must not render HTML")
	}
}

func TestServeHTTP_IndexMd_DownloadBypassesRenderer(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.md", "# Welcome")
	h := newHandler(t, root, withMarkdown(), func(r *alaye.Route) {
		r.Web.Index = []string{"index.md"}
	})
	rr := do(t, h, http.MethodGet, "/?download")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "<h1") {
		t.Error("?download on index.md must serve raw source, not rendered HTML")
	}
}

// ?refresh cache busting

func TestServeHTTP_Refresh_NoCacheHeader(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "style.css", "body{}")
	h := newHandler(t, root)
	rr := do(t, h, http.MethodGet, "/style.css?refresh")
	if rr.Code != http.StatusOK {
		t.Fatalf("?refresh: want 200, got %d", rr.Code)
	}
	cc := rr.Header().Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("?refresh: Cache-Control must be no-store, got %q", cc)
	}
}

func TestServeHTTP_Refresh_NoConditional304(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "app.js", "var x=1;")
	h := newHandler(t, root)

	// Get the ETag from a normal request.
	rr1 := do(t, h, http.MethodGet, "/app.js")
	etag := rr1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on first request")
	}

	// Same ETag + ?refresh must NOT return 304 — full body required.
	req := httptest.NewRequest(http.MethodGet, "/app.js?refresh", nil)
	req.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code == http.StatusNotModified {
		t.Error("?refresh: must not return 304 even with a matching ETag")
	}
	if rr2.Code != http.StatusOK {
		t.Errorf("?refresh: want 200, got %d", rr2.Code)
	}
}

func TestServeHTTP_Refresh_Markdown(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "README.md", "# Hello")
	h := newHandler(t, root, withMarkdown())
	rr := do(t, h, http.MethodGet, "/README.md?refresh")
	if rr.Code != http.StatusOK {
		t.Fatalf("?refresh on md: want 200, got %d", rr.Code)
	}
	cc := rr.Header().Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("?refresh on md: Cache-Control must be no-store, got %q", cc)
	}
	if !strings.Contains(rr.Body.String(), "<h1") {
		t.Error("?refresh on md: content must still be rendered")
	}
}
func TestServeHTTP_HiddenDirBlocked(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, ".git/config", "[core]")
	rr := do(t, newHandler(t, root), http.MethodGet, "/.git/config")
	if rr.Code == http.StatusOK {
		t.Error(".git/config must not be accessible")
	}
}
