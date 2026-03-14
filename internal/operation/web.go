package operation

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/cook"
	"github.com/dustin/go-humanize"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
	"github.com/yookoala/gofast"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting/v2"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldhtml "github.com/yuin/goldmark/renderer/html"
	goldtoc "go.abhg.dev/goldmark/toc"
)

//go:embed web/dir.html
var webDirHTML string

// mdPageHTML is the built-in HTML wrapper for rendered Markdown in normal view.
// Embedding lets UI developers edit web/md.html without touching Go code.
//
//go:embed web/md.html
var mdPageHTML string

// mdBrowseHTML is the browse-mode wrapper: breadcrumbs, raw link, theme toggle.
// Used when route.Web.Markdown.View == "browse".
//
//go:embed web/md_browse.html
var mdBrowseHTML string

var (
	dirTmpl      = template.Must(template.New("dir").Parse(webDirHTML))
	mdPageTmpl   = template.Must(template.New("md").Parse(mdPageHTML))
	mdBrowseTmpl = template.Must(template.New("md-browse").Parse(mdBrowseHTML))

	gzExistsCache = mappo.NewCache(mappo.CacheOptions{
		MaximumSize: woos.CacheMax,
	})

	// dynamicGzCache holds in-memory gzip-compressed content for hot assets.
	// mappo is lock-free; no mutex required.
	// key: reqPath, value: *dynamicGzEntry
	dynamicGzCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: 256})

	fingerprintRe = regexp.MustCompile(`(?i)(?:[._-])[a-f0-9]{8,}(?:[._-])`)

	// gzWriterPool reduces allocations for on-the-fly gzip compression.
	gzWriterPool = sync.Pool{
		New: func() any {
			w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
			return w
		},
	}
)

const (
	gzCacheTTL = 60 * time.Second

	// phpTimeout is the maximum duration to wait for a PHP-FPM response.
	phpTimeout = 30 * time.Second

	// dynamicGzMinSize is the minimum file size (bytes) eligible for on-the-fly gzip.
	dynamicGzMinSize = 1024

	// dynamicGzMaxCacheSize is the largest compressed body kept in memory.
	dynamicGzMaxCacheSize = 512 * 1024

	// dynamicGzTTL is how long a dynamic gz entry lives in the memory cache.
	dynamicGzTTL = 60 * time.Second
)

// compressibleMIME lists MIME type prefixes eligible for on-the-fly gzip.
var compressibleMIME = []string{
	"text/",
	"application/javascript",
	"application/json",
	"application/xml",
	"application/xhtml+xml",
	"application/wasm",
	"image/svg+xml",
}

// markdownExts is the set of extensions that trigger Markdown rendering.
var markdownExts = map[string]bool{
	".md":       true,
	".markdown": true,
	".mdown":    true,
	".mkd":      true,
}

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

type dirItem struct {
	Name    string
	IsDir   bool
	Size    string
	ModTime string
	URL     string
	Ext     string
	MIME    string
}

type crumb struct {
	Name string
	Href string
}

// dynamicGzEntry holds a dynamically compressed response body and its metadata.
type dynamicGzEntry struct {
	data    []byte
	modTime time.Time
	size    int64 // original uncompressed size, used for ETag
}

// -----------------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------------

type web struct {
	route            *alaye.Route
	logger           *ll.Logger
	cookMgr          *cook.Manager
	phpClientFactory gofast.ClientFactory
	res              *resource.Manager

	// mdConverter is non-nil when Markdown rendering is enabled for this route.
	mdConverter goldmark.Markdown

	// mdBrowse is true when the route sets view = "browse" for Markdown.
	// It selects the shell template (breadcrumbs, raw link, theme toggle)
	// instead of the clean content-only template.
	mdBrowse bool

	// mdHighlight is true when SyntaxHighlight is active. Passed to templates
	// so they can suppress the --code-bg CSS variable override on pre.chroma:
	// Chroma's own inline background must win when a theme is in use.
	mdHighlight bool
}

func NewWeb(res *resource.Manager, logger *ll.Logger, route *alaye.Route, cookMgr *cook.Manager) *web {
	h := &web{
		route:   route,
		logger:  logger.Namespace("web"),
		cookMgr: cookMgr,
		res:     res,
	}

	// --- PHP setup ---
	if route != nil && route.Web.PHP.Status.Active() {
		network, address := "tcp", "127.0.0.1:9000"
		if strings.TrimSpace(route.Web.PHP.Address) != "" {
			addr := strings.TrimSpace(route.Web.PHP.Address)
			if strings.HasPrefix(addr, "unix:") {
				network = "unix"
				address = strings.TrimSpace(strings.TrimPrefix(addr, "unix:"))
			} else {
				network = "tcp"
				address = addr
			}
		}
		connFactory := gofast.SimpleConnFactory(network, address)
		h.phpClientFactory = gofast.SimpleClientFactory(connFactory)
		h.logger.Fields("route", route.Path, "php", true, "php_net", network, "php_addr", address).Info("PHP configured")
	}

	// --- Markdown renderer setup ---
	if route != nil && route.Web.Markdown.Enabled.Active() {
		exts := []goldmark.Extender{
			extension.GFM,         // tables, strikethrough, task lists
			extension.Footnote,    // [^1] footnotes
			extension.Typographer, // smart quotes / em-dashes
		}

		// SyntaxHighlight: wrap fenced code blocks with Chroma inline styles.
		// The operator chooses a theme via SyntaxHighlight.Theme (e.g. "github",
		// "dracula", "monokai"). Chroma emits <span style="color:#..."> directly
		// so the chosen theme is self-contained — no template CSS needed.
		// Full theme list: https://xyproto.github.io/splash/docs/
		if route.Web.Markdown.SyntaxHighlight.Enabled.Active() {
			theme := strings.TrimSpace(route.Web.Markdown.SyntaxHighlight.Theme)
			if theme == "" {
				theme = "github" // sensible default for light backgrounds
			}
			exts = append(exts, highlighting.NewHighlighting(
				highlighting.WithStyle(theme),
				highlighting.WithGuessLanguage(true),
			))
		}

		// TableOfContents: inject a <nav> list before the first heading.
		// goldmark-toc walks the AST after parsing; WithAutoHeadingID is required
		// so the generated anchor hrefs resolve to real heading IDs.
		if route.Web.Markdown.TableOfContents.Active() {
			exts = append(exts, &goldtoc.Extender{})
		}

		opts := []goldmark.Option{
			goldmark.WithExtensions(exts...),
			goldmark.WithParserOptions(
				parser.WithAutoHeadingID(), // anchor IDs on every heading
			),
		}
		if route.Web.Markdown.UnsafeHTML.Active() {
			// Explicit operator opt-in: pass raw HTML in Markdown source through
			// unescaped. Only enable when the Markdown source is fully trusted.
			opts = append(opts, goldmark.WithRendererOptions(goldhtml.WithUnsafe()))
		}
		h.mdConverter = goldmark.New(opts...)
		h.mdBrowse = strings.EqualFold(strings.TrimSpace(route.Web.Markdown.View), "browse")
		h.mdHighlight = route.Web.Markdown.SyntaxHighlight.Enabled.Active()
		h.logger.Fields("route", route.Path, "markdown", true,
			"view", route.Web.Markdown.View,
			"toc", route.Web.Markdown.TableOfContents.Active(),
			"highlight", route.Web.Markdown.SyntaxHighlight.Enabled.Active(),
			"theme", route.Web.Markdown.SyntaxHighlight.Theme,
			"unsafe_html", route.Web.Markdown.UnsafeHTML.Active()).Info("Markdown renderer configured")
	}

	return h
}

// -----------------------------------------------------------------------------
// ServeHTTP
// -----------------------------------------------------------------------------

func (h *web) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	browserPath := r.URL.Path
	if v := r.Context().Value(woos.CtxOriginalPath); v != nil {
		if s, ok := v.(string); ok {
			browserPath = s
		}
	}

	rootPath := h.resolveRootPath()
	if rootPath == "" {
		http.Error(w, "Deployment in progress...", http.StatusServiceUnavailable)
		return
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		h.logger.Fields("err", err, "root", rootPath).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer root.Close()

	reqPath := strings.TrimPrefix(r.URL.Path, "/")
	if reqPath == "" {
		reqPath = "."
	}
	cleanedPath := filepath.Clean(reqPath)

	if strings.HasPrefix(cleanedPath, "..") || strings.HasPrefix(cleanedPath, string(filepath.Separator)+"..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	pathParts := strings.SplitSeq(cleanedPath, string(filepath.Separator))
	for part := range pathParts {
		if part == "." || part == ".." || part == "" {
			continue
		}
		if strings.HasPrefix(part, ".") && part != ".well-known" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	reqPath = cleanedPath

	// --- ?download: force raw download for any file, bypassing Markdown rendering ---
	// e.g. GET /README.md?download  →  serves the raw .md source as a download
	wantsDownload := r.URL.Query().Has("download")

	// --- ?refresh: bust the HTTP cache and evict any in-memory gz entry ---
	// Useful after a config change (e.g. switching view = "normal" → "browse")
	// where the handler has been reloaded by the LB but the browser holds a
	// cached response. ?refresh forces a clean re-fetch with no 304.
	// Works on any path: /README.md?refresh, /docs/?refresh, /app.js?refresh.
	wantsRefresh := r.URL.Query().Has("refresh")
	if wantsRefresh {
		// Evict any cached dynamic gz entry so the freshly rebuilt response
		// is also re-compressed, not served from stale memory.
		dynamicGzCache.Delete(reqPath)
	}

	// --- PHP (Fix #1: context timeout so disconnected clients release FPM workers) ---
	if strings.HasSuffix(strings.ToLower(reqPath), ".php") {
		if h.phpClientFactory == nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		ff, err := root.Open(reqPath)
		if err == nil {
			info, serr := ff.Stat()
			_ = ff.Close()
			if serr == nil && !info.IsDir() {
				ctx, cancel := context.WithTimeout(r.Context(), phpTimeout)
				defer cancel()
				rWithCtx := r.WithContext(ctx)

				sess := gofast.Chain(
					gofast.BasicParamsMap,
					gofast.MapHeader,
					gofast.MapRemoteHost,
					gofast.NewPHPFS(rootPath),
				)(gofast.BasicSession)

				gofast.NewHandler(sess, h.phpClientFactory).ServeHTTP(w, rWithCtx)

				if ctxErr := ctx.Err(); ctxErr != nil {
					h.logger.Fields("path", reqPath, "err", ctxErr,
						"method", r.Method, "ua", r.UserAgent()).Warn("PHP request context expired or cancelled")
				}
				return
			}
		}
	}

	// --- Pre-compressed .gz sidecar (Fix #2: open first; cache is hint only) ---
	if !wantsDownload && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gzPath, gzOrigPath := h.resolveGzipPath(reqPath)
		if h.gzMayExist(gzPath) {
			fGz, err := root.Open(gzPath)
			if err == nil {
				defer fGz.Close()
				infoGz, statErr := fGz.Stat()
				if statErr == nil && !infoGz.IsDir() {
					h.gzSetExists(gzPath, true)
					if h.setCommonHeaders(w, r, gzOrigPath, infoGz.ModTime(), infoGz.Size(), true) {
						return
					}
					origType := getMimeType(gzOrigPath)
					if origType == "" {
						origType = "application/octet-stream"
					}
					w.Header().Set("Content-Type", origType)
					w.Header().Set("Content-Encoding", "gzip")
					w.Header().Add("Vary", "Accept-Encoding")
					w.Header().Set("X-Content-Type-Options", "nosniff")
					http.ServeContent(w, r, gzPath, infoGz.ModTime(), fGz)
					return
				}
			} else if errors.Is(err, fs.ErrNotExist) {
				h.gzSetExists(gzPath, false)
			}
		}
	}

	// --- Open requested path ---
	f, err := root.Open(reqPath)
	if err != nil {
		h.handleOpenError(w, r, root, reqPath, err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		h.logger.Fields("err", err, "path", reqPath).Error("stat failed after open")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// --- Directory ---
	if info.IsDir() {
		h.serveDir(w, r, root, f, reqPath, browserPath)
		return
	}

	// --- Markdown renderer ---
	// Skip rendering when ?download is present: serve the raw source file instead.
	if !wantsDownload && h.mdConverter != nil && isMarkdownPath(reqPath) {
		h.serveMarkdown(w, r, root, reqPath, browserPath, info)
		return
	}

	// When ?download is present, force Content-Disposition: attachment so the
	// browser downloads the file rather than displaying it.
	if wantsDownload {
		w.Header().Set("Content-Disposition", "attachment; filename="+url.PathEscape(filepath.Base(reqPath)))
	}

	// --- On-the-fly gzip for compressible assets with no .gz sidecar (Fix #5) ---
	if !wantsDownload && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && info.Size() >= dynamicGzMinSize {
		if mt := getMimeType(reqPath); isCompressibleMIME(mt) {
			if h.serveDynamicGzip(w, r, reqPath, f, info, mt) {
				return
			}
			// Dynamic gzip failed — re-open file (f was consumed) and fall through.
			f.Close()
			f, err = root.Open(reqPath)
			if err != nil {
				h.logger.Fields("err", err, "path", reqPath).Error("re-open after dynamic gz failed")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer f.Close()
		}
	}

	// --- Static file ---
	if h.setCommonHeaders(w, r, reqPath, info.ModTime(), info.Size(), false) {
		return
	}
	mt := getMimeType(reqPath)
	if mt == "" {
		mt = detectContentType(f) // Fix #6: sniff from content bytes
	}
	w.Header().Set("Content-Type", mt)
	w.Header().Set("X-Content-Type-Options", "nosniff") // Fix #6: block browser sniffing
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// -----------------------------------------------------------------------------
// Markdown rendering
// -----------------------------------------------------------------------------

// isMarkdownPath reports whether path carries a recognised Markdown extension.
func isMarkdownPath(path string) bool {
	return markdownExts[strings.ToLower(filepath.Ext(path))]
}

// serveMarkdown reads, converts, and writes a Markdown file as HTML.
// The full output is always buffered before the first byte is sent so that
// a conversion or template error can still return a clean HTTP 500.
func (h *web) serveMarkdown(w http.ResponseWriter, r *http.Request, root *os.Root, reqPath, browserPath string, info fs.FileInfo) {
	f, err := root.Open(reqPath)
	if err != nil {
		h.logger.Fields("err", err, "path", reqPath).Error("markdown: open failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	src, err := io.ReadAll(f)
	if err != nil {
		h.logger.Fields("err", err, "path", reqPath).Error("markdown: read failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var mdBuf bytes.Buffer
	if err := h.mdConverter.Convert(src, &mdBuf); err != nil {
		h.logger.Fields("err", err, "path", reqPath).Error("markdown: conversion failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Try operator-supplied custom template first.
	if h.route.Web.Markdown.Template != "" {
		if ok := h.serveMarkdownWithTemplate(w, root, reqPath, info, mdBuf.String()); ok {
			return
		}
		// Custom template failed — fall through to built-in wrapper.
		h.logger.Fields("path", reqPath, "template", h.route.Web.Markdown.Template).
			Warn("markdown: custom template failed, using built-in")
	}

	data := struct {
		Title           string
		Content         template.HTML
		ModTime         string
		Breadcrumb      []crumb
		SyntaxHighlight bool
	}{
		Title:           filepath.Base(reqPath),
		Content:         template.HTML(mdBuf.String()), //nolint:gosec // goldmark output is the intended HTML
		ModTime:         info.ModTime().Format("2006-01-02 15:04:05"),
		Breadcrumb:      h.buildBreadcrumbs(browserPath),
		SyntaxHighlight: h.mdHighlight,
	}

	tmpl := mdPageTmpl
	if h.mdBrowse {
		tmpl = mdBrowseTmpl
	}

	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		h.logger.Fields("err", err, "path", reqPath).Error("markdown: built-in template execute failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Has("refresh") {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Bytes())
}

// serveMarkdownWithTemplate renders converted Markdown through the operator-
// supplied HTML template stored at h.route.Web.Markdown.Template.
// Returns true only if the response was written successfully.
func (h *web) serveMarkdownWithTemplate(
	w http.ResponseWriter,
	root *os.Root,
	reqPath string,
	info fs.FileInfo,
	htmlContent string,
) bool {
	tf, err := root.Open(h.route.Web.Markdown.Template)
	if err != nil {
		h.logger.Fields("err", err, "template", h.route.Web.Markdown.Template).
			Warn("markdown: cannot open custom template")
		return false
	}
	defer tf.Close()

	tmplSrc, err := io.ReadAll(tf)
	if err != nil {
		h.logger.Fields("err", err, "template", h.route.Web.Markdown.Template).
			Warn("markdown: cannot read custom template")
		return false
	}

	tmpl, err := template.New("md-custom").Parse(string(tmplSrc))
	if err != nil {
		h.logger.Fields("err", err, "template", h.route.Web.Markdown.Template).
			Warn("markdown: cannot parse custom template")
		return false
	}

	data := struct {
		Title   string
		Content template.HTML
		Path    string
		ModTime string
	}{
		Title:   filepath.Base(reqPath),
		Content: template.HTML(htmlContent), //nolint:gosec
		Path:    reqPath,
		ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
	}

	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		h.logger.Fields("err", err, "template", h.route.Web.Markdown.Template).
			Warn("markdown: custom template execute failed")
		return false
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Bytes())
	return true
}

// -----------------------------------------------------------------------------
// Directory handling
// -----------------------------------------------------------------------------

func (h *web) serveDir(w http.ResponseWriter, r *http.Request, root *os.Root, f *os.File, reqPath, browserPath string) {
	if !strings.HasSuffix(browserPath, "/") {
		http.Redirect(w, r, browserPath+"/", http.StatusMovedPermanently)
		return
	}

	indexName := "index.html"
	if h.route.Web.Index != "" {
		indexName = h.route.Web.Index
	}

	indexPath := filepath.Join(reqPath, indexName)
	indexFile, err := root.Open(indexPath)
	if err == nil {
		defer indexFile.Close()
		indexInfo, err := indexFile.Stat()
		if err == nil && !indexInfo.IsDir() {
			// If the configured index file is a Markdown file and the renderer
			// is active, hand it to serveMarkdown exactly as a direct file request
			// would. ?download bypasses rendering the same way it does elsewhere.
			wantsDownload := r.URL.Query().Has("download")
			if !wantsDownload && h.mdConverter != nil && isMarkdownPath(indexName) {
				h.serveMarkdown(w, r, root, indexPath, browserPath, indexInfo)
				return
			}
			if h.setCommonHeaders(w, r, indexName, indexInfo.ModTime(), indexInfo.Size(), false) {
				return
			}
			mt := getMimeType(indexName)
			if mt == "" {
				mt = "application/octet-stream"
			}
			w.Header().Set("Content-Type", mt)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			http.ServeContent(w, r, indexName, indexInfo.ModTime(), indexFile)
			return
		}
	}

	if h.route.Web.Listing {
		h.serveDirectoryListing(w, r, f, browserPath)
		return
	}

	http.Error(w, "Forbidden", http.StatusForbidden)
}

// serveDirectoryListing renders a directory index into a buffer before writing
// (Fix #8) so that a template failure can still return a clean HTTP 500.
func (h *web) serveDirectoryListing(w http.ResponseWriter, r *http.Request, f *os.File, displayPath string) {
	entries, err := f.ReadDir(-1)
	if err != nil {
		h.logger.Fields("err", err, "path", displayPath).Error("failed to read directory")
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	items := make([]dirItem, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if entry.IsDir() && strings.HasSuffix(name, ".d") {
			continue
		}
		if name == woos.DefaultConfigName {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		size := "-"
		if !entry.IsDir() {
			size = humanize.Bytes(uint64(info.Size()))
		}

		mt := "-"
		if !entry.IsDir() {
			mt = getMimeType(name)
			if mt == "" {
				mt = "application/octet-stream"
			}
		}

		items = append(items, dirItem{
			Name:    name,
			IsDir:   entry.IsDir(),
			Size:    size,
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			URL:     url.PathEscape(name),
			Ext:     strings.ToLower(filepath.Ext(name)),
			MIME:    mt,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return items[i].Name < items[j].Name
	})

	data := struct {
		Path       string
		ShowParent bool
		Items      []dirItem
		FileCount  int
		Breadcrumb []crumb
	}{
		Path:       displayPath,
		ShowParent: displayPath != "/",
		Items:      items,
		FileCount:  len(items),
		Breadcrumb: h.buildBreadcrumbs(displayPath),
	}

	// Buffer first — if Execute fails we can still write a 500 (Fix #8).
	var buf bytes.Buffer
	if err := dirTmpl.Execute(&buf, data); err != nil {
		h.logger.Fields("err", err, "path", displayPath).Error("directory listing template execute failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// -----------------------------------------------------------------------------
// Dynamic gzip (Fix #5)
// -----------------------------------------------------------------------------

// serveDynamicGzip compresses f on the fly and writes the gzip response.
// The compressed body is cached in memory (mappo is lock-free; no mutex needed).
// Returns true if the response was fully written; false to fall back to plain.
func (h *web) serveDynamicGzip(
	w http.ResponseWriter,
	r *http.Request,
	reqPath string,
	f *os.File,
	info fs.FileInfo,
	mimeType string,
) bool {
	// mappo is lock-free — direct Load/Store with no external mutex.
	cached, ok := dynamicGzCache.Load(reqPath)

	var entry *dynamicGzEntry
	if ok {
		if e, valid := zulu.GetCache[*dynamicGzEntry](cached); valid {
			entry = e
		}
	}

	if entry == nil {
		raw, err := os.ReadFile(f.Name())
		if err != nil {
			h.logger.Fields("err", err, "path", reqPath).Warn("dynamic gzip: read failed")
			return false
		}

		var buf bytes.Buffer
		gz := gzWriterPool.Get().(*gzip.Writer)
		gz.Reset(&buf)
		if _, err := gz.Write(raw); err != nil {
			gz.Close()
			gzWriterPool.Put(gz)
			h.logger.Fields("err", err, "path", reqPath).Warn("dynamic gzip: compress failed")
			return false
		}
		if err := gz.Close(); err != nil {
			gzWriterPool.Put(gz)
			h.logger.Fields("err", err, "path", reqPath).Warn("dynamic gzip: flush failed")
			return false
		}
		gzWriterPool.Put(gz)

		entry = &dynamicGzEntry{
			data:    buf.Bytes(),
			modTime: info.ModTime(),
			size:    info.Size(),
		}

		if len(entry.data) <= dynamicGzMaxCacheSize {
			dynamicGzCache.StoreTTL(reqPath, &mappo.Item{Value: entry}, dynamicGzTTL)
		}
	}

	if h.setCommonHeaders(w, r, reqPath, entry.modTime, entry.size, true) {
		return true // 304 Not Modified
	}

	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Add("Vary", "Accept-Encoding")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, reqPath, entry.modTime, bytes.NewReader(entry.data))
	return true
}

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

// handleOpenError translates an os.Root.Open failure into the appropriate
// HTTP response and log entry (Fix #7: tiered logging by error type).
func (h *web) handleOpenError(w http.ResponseWriter, r *http.Request, root *os.Root, reqPath string, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// SPA fallback: serve the index for any unknown path.
		if h.route.Web.SPA {
			indexName := "index.html"
			if h.route.Web.Index != "" {
				indexName = h.route.Web.Index
			}
			if indexFile, iErr := root.Open(indexName); iErr == nil {
				defer indexFile.Close()
				if iInfo, sErr := indexFile.Stat(); sErr == nil {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("Cache-Control", "no-cache")
					http.ServeContent(w, r, indexName, iInfo.ModTime(), indexFile)
					return
				}
			}
		}

		h.logger.Fields("path", reqPath).Stack("file not found (404)")
		http.Error(w, "Not Found", http.StatusNotFound)

	case errors.Is(err, fs.ErrPermission):

		h.logger.Fields("path", reqPath, "method", r.Method, "ua", r.UserAgent()).
			Warn("permission denied serving file")
		http.Error(w, "Forbidden", http.StatusForbidden)

	default:

		h.logger.Fields("err", err, "path", reqPath, "method", r.Method).
			Error("unexpected error opening file")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

func (h *web) resolveRootPath() string {
	if h.route.Web.Git.Enabled.Active() && h.cookMgr != nil {
		return h.cookMgr.CurrentPath(h.route.Web.Git.ID)
	}
	return h.route.Web.Root.String() // WebRoot.String() returns "." when unset
}

func (h *web) resolveGzipPath(reqPath string) (gzPath, origPath string) {
	origPath = reqPath
	gzPath = reqPath + ".gz"
	if reqPath == "." {
		indexName := "index.html"
		if h.route.Web.Index != "" {
			indexName = h.route.Web.Index
		}
		origPath = indexName
		gzPath = indexName + ".gz"
	}
	return gzPath, origPath
}

// gzMayExist returns true when the cache holds no confirmed-negative entry.
// Unknown keys default to true (optimistic — attempt the open).
func (h *web) gzMayExist(gzPath string) bool {
	it, ok := gzExistsCache.Load(gzPath)
	if !ok {
		return true
	}
	v, ok := zulu.GetCache[bool](it)
	if !ok {
		return true
	}
	return v
}

// gzSetExists records a confirmed existence state for a .gz sidecar.
// TTL is jittered ±2.5 s to prevent thundering-herd on cache expiry.
func (h *web) gzSetExists(gzPath string, exists bool) {
	jitter := time.Duration(time.Now().UnixNano()%int64(5*time.Second)) - 2500*time.Millisecond
	ttl := gzCacheTTL + jitter
	if ttl < time.Second {
		ttl = time.Second
	}
	gzExistsCache.StoreTTL(gzPath, &mappo.Item{Value: exists}, ttl)
}

// setCommonHeaders writes Cache-Control, ETag, and Vary, then evaluates
// If-None-Match. Returns true (writing 304) when the client is current.
func (h *web) setCommonHeaders(
	w http.ResponseWriter,
	r *http.Request,
	reqPath string,
	modTime time.Time,
	size int64,
	isGzipVariant bool,
) (notModified bool) {
	// ?refresh forces a clean response: no-store so the browser does not cache
	// this response, and skip the 304 check so we always send the full body.
	if r.URL.Query().Has("refresh") {
		w.Header().Set("Cache-Control", "no-store")
		if isGzipVariant {
			w.Header().Add("Vary", "Accept-Encoding")
		}
		return false
	}

	ext := strings.ToLower(filepath.Ext(reqPath))

	var cacheControl string
	switch {
	case ext == ".html" || ext == "" || strings.HasSuffix(r.URL.Path, "/"):
		cacheControl = "public, max-age=0, must-revalidate"
	case fingerprintRe.FindStringIndex(filepath.Base(reqPath)) != nil:
		cacheControl = "public, max-age=31536000, immutable"
	default:
		cacheControl = "public, max-age=300"
	}
	w.Header().Set("Cache-Control", cacheControl)

	if isGzipVariant {
		w.Header().Add("Vary", "Accept-Encoding")
	}

	etag := strongETag(reqPath, size, modTime)
	w.Header().Set("ETag", etag)

	if inm := r.Header.Get("If-None-Match"); inm != "" && ifNoneMatchHas(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	return false
}

func (h *web) buildBreadcrumbs(displayPath string) []crumb {
	p := strings.Trim(displayPath, "/")
	if p == "" {
		return []crumb{{Name: "root", Href: "/"}}
	}
	parts := strings.Split(p, "/")
	out := make([]crumb, 0, len(parts)+1)
	out = append(out, crumb{Name: "root", Href: "/"})
	var cur strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur.WriteString("/" + part)
		out = append(out, crumb{Name: part, Href: cur.String() + "/"})
	}
	return out
}

// isCompressibleMIME reports whether mt is worth gzip-compressing on the fly.
func isCompressibleMIME(mt string) bool {
	for _, prefix := range compressibleMIME {
		if strings.HasPrefix(mt, prefix) {
			return true
		}
	}
	return false
}

// detectContentType reads up to 512 bytes from f to sniff the MIME type,
// then seeks back to the start. Falls back to "application/octet-stream".
func detectContentType(f *os.File) string {
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	_, _ = f.Seek(0, 0)
	if n > 0 {
		return http.DetectContentType(buf[:n])
	}
	return "application/octet-stream"
}

// strongETag builds a weak ETag incorporating file size, modification time,
// and inode (Fix #9). Falls back to 0 on platforms without inode support.
func strongETag(path string, size int64, modTime time.Time) string {
	raw := fmt.Sprintf("%d-%d-%d", size, modTime.UnixNano(), inodeOf(path))
	return fmt.Sprintf(`W/"%x"`, fnv64a(raw))
}

// fnv64a is a non-cryptographic FNV-1a 64-bit hash used for ETag generation.
func fnv64a(s string) uint64 {
	const (
		offset64 uint64 = 14695981039346656037
		prime64  uint64 = 1099511628211
	)
	h := offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

// inodeOf returns the inode number for path, or 0 if unavailable.
func inodeOf(path string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}
