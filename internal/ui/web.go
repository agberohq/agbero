package ui

import (
	_ "embed"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/dustin/go-humanize"
	"github.com/olekukonko/ll"
	"github.com/yookoala/gofast"
)

//go:embed web/dir.html
var dirListing string
var tmpl = template.Must(template.New("dir").Parse(dirListing))

// Ensure critical web types are registered
func init() {
	types := map[string]string{
		".html":        "text/html; charset=utf-8",
		".css":         "text/css; charset=utf-8",
		".js":          "application/javascript; charset=utf-8",
		".json":        "application/json; charset=utf-8",
		".xml":         "text/xml; charset=utf-8",
		".svg":         "image/svg+xml",
		".txt":         "text/plain; charset=utf-8",
		".png":         "image/png",
		".jpg":         "image/jpeg",
		".jpeg":        "image/jpeg",
		".gif":         "image/gif",
		".webp":        "image/webp",
		".ico":         "image/x-icon",
		".woff2":       "font/woff2",
		".wasm":        "application/wasm",
		".md":          "text/markdown",
		".mjs":         "text/javascript; charset=utf-8",
		".webmanifest": "application/manifest+json",
		".pdf":         "application/pdf",
		".csv":         "text/csv; charset=utf-8",
		".avif":        "image/avif",
		".mp4":         "video/mp4",
		".mp3":         "audio/mpeg",
		".woff":        "font/woff",
		".zip":         "application/zip",
	}

	for ext, mimeType := range types {
		_ = mime.AddExtensionType(ext, mimeType)
	}
}

var (
	mimeCache sync.Map // ext -> type

	// Cache for gzip existence checks to avoid filesystem "miss" cost on every request.
	// We use a short TTL so if you deploy new .gz admin, the server will discover them soon.
	gzExistsCache sync.Map // string -> gzCacheEntry
)

type gzCacheEntry struct {
	Exists bool
	Exp    time.Time
}

const gzCacheTTL = 60 * time.Second

type dirItem struct {
	Name    string
	IsDir   bool
	Size    string
	ModTime string
	URL     string

	// For UI: faster + reliable icons and "Type" column.
	Ext  string // ".pdf"
	MIME string // "application/pdf"
}

type crumb struct {
	Name string // label shown to user
	Href string // absolute path (ends with "/")
}

func buildBreadcrumbs(displayPath string) []crumb {
	// displayPath is r.URL.Path (starts with "/")
	p := strings.Trim(displayPath, "/")
	if p == "" {
		return []crumb{{Name: "root", Href: "/"}}
	}

	parts := strings.Split(p, "/")
	out := make([]crumb, 0, len(parts)+1)
	out = append(out, crumb{Name: "root", Href: "/"})

	var cur string
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur += "/" + part
		out = append(out, crumb{Name: part, Href: cur + "/"})
	}
	return out
}

type webHandler struct {
	route  *alaye.Route
	logger *ll.Logger

	php http.Handler // nil if disabled
}

func New(logger *ll.Logger, route *alaye.Route) *webHandler {
	h := &webHandler{
		route:  route,
		logger: logger,
	}

	// PHP FastCGI support (value-type config; no pointers).
	if route != nil && route.Web.PHP.Enabled {
		root := route.Web.Root.String()

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
		clientFactory := gofast.SimpleClientFactory(connFactory)

		sess := gofast.Chain(
			gofast.BasicParamsMap,
			gofast.MapHeader,
			gofast.MapRemoteHost,
		)(gofast.BasicSession)

		h.php = gofast.NewHandler(
			gofast.NewPHPFS(root)(sess),
			clientFactory,
		)

		h.logger.Fields("route", route.Path, "php", true, "php_net", network, "php_addr", address, "root", root).Info("PHP")
	}

	return h
}

func (h *webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	rootPath := h.route.Web.Root.String()
	if rootPath == "" {
		rootPath = "."
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		h.logger.Fields("err", err, "root", rootPath).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer root.Close()

	// FIX: Clean the path to resolve ".." and "." before processing
	cleanedPath := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if cleanedPath == "." || cleanedPath == "/" {
		cleanedPath = "."
	}

	// Validation logic after cleaning
	pathParts := strings.Split(cleanedPath, string(filepath.Separator))
	for _, part := range pathParts {
		if part == "." || part == ".." || part == "" {
			continue
		}

		// Block hidden files/dirs (.git, .env)
		// Block config directories (hosts.d, certs.d, etc.)
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".d") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	reqPath := cleanedPath
	phpEnabled := h.php != nil

	if strings.HasSuffix(strings.ToLower(reqPath), ".php") && !phpEnabled {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if phpEnabled && strings.HasSuffix(strings.ToLower(reqPath), ".php") {
		ff, err := root.Open(reqPath)
		if err == nil {
			info, serr := ff.Stat()
			_ = ff.Close()
			if serr == nil && !info.IsDir() {
				h.php.ServeHTTP(w, r)
				return
			}
		}
	}

	if clientAcceptsGzip(r) {
		gzPath, gzOrigPath := h.resolveGzipPath(reqPath)
		if h.gzMayExist(gzPath) {
			fGz, err := root.Open(gzPath)
			if err == nil {
				defer fGz.Close()
				infoGz, err := fGz.Stat()
				if err == nil && !infoGz.IsDir() {
					if h.setCommonHeaders(w, r, gzOrigPath, infoGz.ModTime(), infoGz.Size(), true) {
						return
					}
					origType := getMimeType(gzOrigPath)
					if origType != "" {
						w.Header().Set("Content-Type", origType)
					}
					w.Header().Set("Content-Encoding", "gzip")
					w.Header().Add("Vary", "Accept-Encoding")
					http.ServeContent(w, r, gzPath, infoGz.ModTime(), fGz)
					h.gzSetExists(gzPath, true)
					return
				}
				h.gzSetExists(gzPath, false)
			} else if errors.Is(err, fs.ErrNotExist) {
				h.gzSetExists(gzPath, false)
			}
		}
	}

	f, err := root.Open(reqPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "Not Found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
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
				if h.setCommonHeaders(w, r, indexName, indexInfo.ModTime(), indexInfo.Size(), false) {
					return
				}
				w.Header().Set("Content-Type", getMimeType(indexName))
				http.ServeContent(w, r, indexName, indexInfo.ModTime(), indexFile)
				return
			}
		}
		if h.route.Web.Listing {
			h.serveDirectoryListing(w, r, f, browserPath)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if h.setCommonHeaders(w, r, reqPath, info.ModTime(), info.Size(), false) {
		return
	}
	w.Header().Set("Content-Type", getMimeType(reqPath))
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func (h *webHandler) serveDirectoryListing(w http.ResponseWriter, r *http.Request, f *os.File, displayPath string) {
	entries, err := f.ReadDir(-1)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	items := make([]dirItem, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()

		// 1. Hide dotfiles
		if strings.HasPrefix(name, ".") {
			continue
		}

		// 2. Hide Security/Config Directories (hosts.d, certs.d, etc.)
		if entry.IsDir() && strings.HasSuffix(name, ".d") {
			continue
		}

		// 3. Hide Config File
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

		ext := strings.ToLower(filepath.Ext(name))

		// NOTE: This is extension-based MIME (no file reads) => fast.
		mimeType := "-"
		if !entry.IsDir() {
			mimeType = getMimeType(name)
		}

		items = append(items, dirItem{
			Name:    name,
			IsDir:   entry.IsDir(),
			Size:    size,
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			URL:     url.PathEscape(name),
			Ext:     ext,
			MIME:    mimeType,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return items[i].Name < items[j].Name
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// dirListing pages should revalidate often.
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")

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
		Breadcrumb: buildBreadcrumbs(displayPath),
	}

	if err := tmpl.Execute(w, data); err != nil {
		h.logger.Error("template execute error: ", err)
	}
}

func getMimeType(path string) string {
	ext := filepath.Ext(path)
	if v, ok := mimeCache.Load(ext); ok {
		return v.(string)
	}

	ctype := mime.TypeByExtension(ext)

	if ctype == "" {
		ctype = "application/octet-stream"
	} else if (strings.HasPrefix(ctype, "text/") ||
		strings.Contains(ctype, "javascript") ||
		strings.Contains(ctype, "json")) &&
		!strings.Contains(ctype, "charset") {
		ctype += "; charset=utf-8"
	}

	mimeCache.Store(ext, ctype)
	return ctype
}

func clientAcceptsGzip(r *http.Request) bool {
	ae := r.Header.Get("Accept-Encoding")
	return strings.Contains(ae, "gzip")
}

func (h *webHandler) resolveGzipPath(reqPath string) (gzPath string, origPath string) {
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

func (h *webHandler) gzMayExist(gzPath string) bool {
	now := time.Now()
	if v, ok := gzExistsCache.Load(gzPath); ok {
		e := v.(gzCacheEntry)
		if now.Before(e.Exp) {
			return e.Exists
		}
		gzExistsCache.Delete(gzPath)
	}
	return true
}

func (h *webHandler) gzSetExists(gzPath string, exists bool) {
	gzExistsCache.Store(gzPath, gzCacheEntry{
		Exists: exists,
		Exp:    time.Now().Add(gzCacheTTL),
	})
}

var fingerprintRe = regexp.MustCompile(`(?i)(?:[._-])[a-f0-9]{8,}(?:[._-])`)

func (h *webHandler) setCommonHeaders(
	w http.ResponseWriter,
	r *http.Request,
	reqPath string,
	modTime time.Time,
	size int64,
	isGzipVariant bool,
) (notModified bool) {
	ext := strings.ToLower(filepath.Ext(reqPath))

	cacheControl := "public, max-age=0, must-revalidate"
	if ext == ".html" || ext == "" || strings.HasSuffix(r.URL.Path, "/") {
		cacheControl = "public, max-age=0, must-revalidate"
	} else {
		base := filepath.Base(reqPath)
		isFingerprinted := fingerprintRe.FindStringIndex(base) != nil
		if isFingerprinted {
			cacheControl = "public, max-age=31536000, immutable"
		} else {
			cacheControl = "public, max-age=300"
		}
	}
	w.Header().Set("Cache-Control", cacheControl)

	if isGzipVariant {
		w.Header().Add("Vary", "Accept-Encoding")
	}

	etag := weakETag(size, modTime)
	w.Header().Set("ETag", etag)

	inm := r.Header.Get("If-None-Match")
	if inm != "" && ifNoneMatchHas(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}

	return false
}

func weakETag(size int64, modTime time.Time) string {
	return `W/"` + strconv.FormatInt(size, 10) + "-" + strconv.FormatInt(modTime.UnixNano(), 10) + `"`
}

func ifNoneMatchHas(inm string, etag string) bool {
	if strings.TrimSpace(inm) == "*" {
		return true
	}
	parts := strings.Split(inm, ",")
	for _, p := range parts {
		if strings.TrimSpace(p) == etag {
			return true
		}
	}
	return false
}
