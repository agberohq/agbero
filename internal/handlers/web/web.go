package web

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
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
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/cook"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
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

//go:embed html/dir.html
var webDirHTML string

//go:embed html/md.html
var mdPageHTML string

//go:embed html/md_browse.html
var mdBrowseHTML string

var (
	dirTmpl      = template.Must(template.New("dir").Parse(webDirHTML))
	mdPageTmpl   = template.Must(template.New("md").Parse(mdPageHTML))
	mdBrowseTmpl = template.Must(template.New("md-browse").Parse(mdBrowseHTML))

	gzExistsCache = mappo.NewCache(mappo.CacheOptions{
		MaximumSize: woos.CacheMax,
	})

	dynamicGzCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: 256})

	fingerprintRe = regexp.MustCompile(`(?i)(?:[._-])[a-f0-9]{8,}(?:[._-])`)

	gzWriterPool = sync.Pool{
		New: func() any {
			w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
			return w
		},
	}
)

const (
	gzCacheTTL            = 60 * time.Second
	phpTimeout            = 30 * time.Second
	dynamicGzMinSize      = 1024
	dynamicGzMaxCacheSize = 512 * 1024
	dynamicGzTTL          = 60 * time.Second
)

var compressibleMIME = []string{
	"text/",
	"application/javascript",
	"application/json",
	"application/xml",
	"application/xhtml+xml",
	"application/wasm",
	"image/svg+xml",
}

var markdownExts = map[string]bool{
	".md":       true,
	".markdown": true,
	".mdown":    true,
	".mkd":      true,
}

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

type dynamicGzEntry struct {
	data    []byte
	modTime time.Time
	size    int64
}

type web struct {
	route            *alaye.Route
	res              *resource.Resource
	cookMgr          *cook.Manager
	phpClientFactory gofast.ClientFactory
	mdConverter      goldmark.Markdown
	mdBrowse         bool
}

// NewWeb constructs a web handler for the given route.
// Logger is sourced from res.Logger; no separate logger parameter is needed.
func NewWeb(res *resource.Resource, route *alaye.Route, cookMgr *cook.Manager) *web {
	h := &web{
		route:   route,
		res:     res,
		cookMgr: cookMgr,
	}

	logger := res.Logger.Namespace("web")

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
		logger.Fields("route", route.Path, "php", true, "php_net", network, "php_addr", address).Info("PHP configured")
	}

	if route != nil && route.Web.Markdown.Enabled.Active() {
		exts := []goldmark.Extender{
			extension.GFM,
			extension.Footnote,
			extension.Typographer,
		}

		if route.Web.Markdown.SyntaxHighlight.Enabled.Active() {
			theme := strings.TrimSpace(route.Web.Markdown.SyntaxHighlight.Theme)
			if theme == "" {
				theme = "github"
			}
			exts = append(exts, highlighting.NewHighlighting(
				highlighting.WithStyle(theme),
				highlighting.WithGuessLanguage(true),
				// WithPreWrapper intercepts Chroma's <pre> at the formatter level.
				// Chroma passes the inline styleAttr it would have written to Start();
				// chromaPreWrapper discards it and emits a plain class-only element,
				// so background and color are fully owned by the template CSS variables.
				highlighting.WithFormatOptions(
					chromahtml.WithPreWrapper(chromaPreWrapper{}),
				),
			))
		}

		if route.Web.Markdown.TableOfContents.Active() {
			exts = append(exts, &goldtoc.Extender{})
		}

		opts := []goldmark.Option{
			goldmark.WithExtensions(exts...),
			goldmark.WithParserOptions(
				parser.WithAutoHeadingID(),
			),
		}
		if route.Web.Markdown.UnsafeHTML.Active() {
			opts = append(opts, goldmark.WithRendererOptions(goldhtml.WithUnsafe()))
		}

		h.mdConverter = goldmark.New(opts...)
		h.mdBrowse = strings.EqualFold(strings.TrimSpace(route.Web.Markdown.View), "browse")
		logger.Fields(
			"route", route.Path,
			"view", route.Web.Markdown.View,
			"toc", route.Web.Markdown.TableOfContents.Active(),
			"highlight", route.Web.Markdown.SyntaxHighlight.Enabled.Active(),
			"theme", route.Web.Markdown.SyntaxHighlight.Theme,
			"unsafe_html", route.Web.Markdown.UnsafeHTML.Active(),
		).Info("markdown renderer configured")
	}

	return h
}

func (h *web) logger() *ll.Logger {
	return h.res.Logger.Namespace("web")
}

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
		h.logger().Fields("err", err, "root", rootPath).Error("failed to open web root")
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
	wantsDownload := r.URL.Query().Has("download")

	if r.URL.Query().Has("refresh") {
		dynamicGzCache.Delete(reqPath)
	}

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
					h.logger().Fields("path", reqPath, "err", ctxErr,
						"method", r.Method, "ua", r.UserAgent()).Warn("PHP request context expired or cancelled")
				}
				return
			}
		}
	}

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

	f, err := root.Open(reqPath)
	if err != nil {
		h.handleOpenError(w, r, root, reqPath, err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		h.logger().Fields("err", err, "path", reqPath).Error("stat failed after open")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
		h.serveDir(w, r, root, f, reqPath, browserPath)
		return
	}

	if !wantsDownload && h.mdConverter != nil && isMarkdownPath(reqPath) {
		h.serveMarkdown(w, r, root, reqPath, browserPath, info)
		return
	}

	if wantsDownload {
		w.Header().Set("Content-Disposition", "attachment; filename="+url.PathEscape(filepath.Base(reqPath)))
	}

	if !wantsDownload && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && info.Size() >= dynamicGzMinSize {
		if mt := getMimeType(reqPath); isCompressibleMIME(mt) {
			if h.serveDynamicGzip(w, r, reqPath, f, info, mt) {
				return
			}
			f.Close()
			f, err = root.Open(reqPath)
			if err != nil {
				h.logger().Fields("err", err, "path", reqPath).Error("re-open after dynamic gz failed")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer f.Close()
		}
	}

	if h.setCommonHeaders(w, r, reqPath, info.ModTime(), info.Size(), false) {
		return
	}
	mt := getMimeType(reqPath)
	if mt == "" {
		mt = detectContentType(f)
	}
	w.Header().Set("Content-Type", mt)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// serveMarkdown converts a Markdown file to HTML and writes the response.
// Output is fully buffered before writing so template failures return a clean 500.
func (h *web) serveMarkdown(w http.ResponseWriter, r *http.Request, root *os.Root, reqPath, browserPath string, info fs.FileInfo) {
	f, err := root.Open(reqPath)
	if err != nil {
		h.logger().Fields("err", err, "path", reqPath).Error("markdown: open failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	src, err := io.ReadAll(f)
	if err != nil {
		h.logger().Fields("err", err, "path", reqPath).Error("markdown: read failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var mdBuf bytes.Buffer
	if err := h.mdConverter.Convert(src, &mdBuf); err != nil {
		h.logger().Fields("err", err, "path", reqPath).Error("markdown: conversion failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if h.route.Web.Markdown.Template != "" {
		if ok := h.serveMarkdownWithTemplate(w, root, reqPath, info, mdBuf.String()); ok {
			return
		}
		h.logger().Fields("path", reqPath, "template", h.route.Web.Markdown.Template).
			Warn("markdown: custom template failed, using built-in")
	}

	data := struct {
		Title      string
		Content    template.HTML
		ModTime    string
		Breadcrumb []crumb
	}{
		Title:      filepath.Base(reqPath),
		Content:    template.HTML(mdBuf.String()), //nolint:gosec
		ModTime:    info.ModTime().Format("2006-01-02 15:04:05"),
		Breadcrumb: h.buildBreadcrumbs(browserPath),
	}

	tmpl := mdPageTmpl
	if h.mdBrowse {
		tmpl = mdBrowseTmpl
	}

	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		h.logger().Fields("err", err, "path", reqPath).Error("markdown: template execute failed")
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

// serveMarkdownWithTemplate renders converted Markdown using an operator-supplied template.
// Returns true only when the response was written successfully.
func (h *web) serveMarkdownWithTemplate(w http.ResponseWriter, root *os.Root, reqPath string, info fs.FileInfo, htmlContent string) bool {
	tf, err := root.Open(h.route.Web.Markdown.Template)
	if err != nil {
		h.logger().Fields("err", err, "template", h.route.Web.Markdown.Template).
			Warn("markdown: cannot open custom template")
		return false
	}
	defer tf.Close()

	tmplSrc, err := io.ReadAll(tf)
	if err != nil {
		h.logger().Fields("err", err, "template", h.route.Web.Markdown.Template).
			Warn("markdown: cannot read custom template")
		return false
	}

	tmpl, err := template.New("md-custom").Parse(string(tmplSrc))
	if err != nil {
		h.logger().Fields("err", err, "template", h.route.Web.Markdown.Template).
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
		h.logger().Fields("err", err, "template", h.route.Web.Markdown.Template).
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

// serveDir handles directory requests: redirect, index file, listing, or 403.
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

// serveDirectoryListing renders the directory index into a buffer before writing,
// ensuring a template failure can still return a clean HTTP 500.
func (h *web) serveDirectoryListing(w http.ResponseWriter, r *http.Request, f *os.File, displayPath string) {
	entries, err := f.ReadDir(-1)
	if err != nil {
		h.logger().Fields("err", err, "path", displayPath).Error("failed to read directory")
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

	var buf bytes.Buffer
	if err := dirTmpl.Execute(&buf, data); err != nil {
		h.logger().Fields("err", err, "path", displayPath).Error("directory listing template execute failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// serveDynamicGzip compresses the file on the fly and writes the gzip response.
// Results are cached in memory; mappo is lock-free so no mutex is needed.
func (h *web) serveDynamicGzip(w http.ResponseWriter, r *http.Request, reqPath string, f *os.File, info fs.FileInfo, mimeType string) bool {
	cached, ok := dynamicGzCache.Load(reqPath)

	var entry *dynamicGzEntry
	if ok {
		if e, valid := zulu.GetCache[*dynamicGzEntry](cached); valid {
			entry = e
		}
	}

	if entry == nil {
		raw, err := io.ReadAll(f)
		if err != nil {
			h.logger().Fields("err", err, "path", reqPath).Warn("dynamic gzip: read failed")
			return false
		}

		var buf bytes.Buffer
		gz := gzWriterPool.Get().(*gzip.Writer)
		gz.Reset(&buf)
		if _, err := gz.Write(raw); err != nil {
			gz.Close()
			gzWriterPool.Put(gz)
			h.logger().Fields("err", err, "path", reqPath).Warn("dynamic gzip: compress failed")
			return false
		}
		if err := gz.Close(); err != nil {
			gzWriterPool.Put(gz)
			h.logger().Fields("err", err, "path", reqPath).Warn("dynamic gzip: flush failed")
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
		return true
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

// handleOpenError maps os.Root.Open failures to HTTP responses with tiered logging.
func (h *web) handleOpenError(w http.ResponseWriter, r *http.Request, root *os.Root, reqPath string, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
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
		//h.logger().Fields("path", reqPath).Stack("file not found (404)")
		http.Error(w, "Not Found", http.StatusNotFound)

	case errors.Is(err, fs.ErrPermission):
		h.logger().Fields("path", reqPath, "method", r.Method, "ua", r.UserAgent()).
			Warn("permission denied serving file")
		http.Error(w, "Forbidden", http.StatusForbidden)

	default:
		h.logger().Fields("err", err, "path", reqPath, "method", r.Method).
			Error("unexpected error opening file")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *web) resolveRootPath() string {
	if h.route.Web.Git.Enabled.Active() && h.cookMgr != nil {
		return h.cookMgr.CurrentPath(h.route.Web.Git.ID)
	}
	return h.route.Web.Root.String()
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
// Unknown keys default to true so the file open is always attempted first.
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

// gzSetExists records the confirmed existence state for a pre-compressed sidecar.
// TTL is jittered ±2.5 s to prevent thundering-herd on cache expiry.
func (h *web) gzSetExists(gzPath string, exists bool) {
	jitter := time.Duration(time.Now().UnixNano()%int64(5*time.Second)) - 2500*time.Millisecond
	ttl := max(gzCacheTTL+jitter, time.Second)
	gzExistsCache.StoreTTL(gzPath, &mappo.Item{Value: exists}, ttl)
}

// setCommonHeaders writes Cache-Control, ETag, and Vary and evaluates If-None-Match.
// Returns true and writes 304 when the client already holds a current copy.
func (h *web) setCommonHeaders(w http.ResponseWriter, r *http.Request, reqPath string, modTime time.Time, size int64, isGzipVariant bool) (notModified bool) {
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

	etag := weakETag(reqPath, size, modTime)
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

// chromaPreWrapper implements chromahtml.PreWrapper, replacing Chroma's default
// <pre style="color:...;background-color:..."> with a plain class-only element.
// Inline styles on <pre> cannot be overridden by CSS variables even with !important,
// so discarding styleAttr gives the template's pre.chroma rule full control.
type chromaPreWrapper struct{}

func (chromaPreWrapper) Start(code bool, _ string) string {
	if code {
		return `<pre class="chroma"><code>`
	}
	return `<pre class="chroma">`
}

func (chromaPreWrapper) End(code bool) string {
	if code {
		return `</code></pre>`
	}
	return `</pre>`
}
