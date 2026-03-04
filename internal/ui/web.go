package ui

import (
	_ "embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"github.com/dustin/go-humanize"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
	"github.com/yookoala/gofast"
)

//go:embed web/dir.html
var webHtml string

var (
	// tmpl parses the embedded directory listing template once at startup.
	// Template execution is safe for concurrent use.
	tmpl = template.Must(template.New("web").Parse(webHtml))

	// gzExistsCache caches the existence of pre-compressed .gz files to reduce
	// filesystem stat calls. Cache entries expire after gzCacheTTL.
	gzExistsCache = mappo.NewCache(mappo.CacheOptions{
		MaximumSize: woos.CacheMax,
	})

	// fingerprintRe matches common fingerprint patterns in filenames
	// (e.g., styles.a1b2c3d4.css, main-8f9a0e1f.js) to enable aggressive caching.
	fingerprintRe = regexp.MustCompile(`(?i)(?:[._-])[a-f0-9]{8,}(?:[._-])`)
)

const gzCacheTTL = 60 * time.Second

// dirItem represents a single entry in a directory listing.
type dirItem struct {
	Name    string // display name
	IsDir   bool
	Size    string // human-readable size
	ModTime string // formatted modification time
	URL     string // URL-encoded path component

	Ext  string // file extension (lowercase)
	MIME string // detected MIME type
}

// crumb represents a breadcrumb navigation item.
type crumb struct {
	Name string // label shown to user
	Href string // absolute path (ends with "/")
}

// web implements the HTTP handler for serving static files and directories.
// It supports PHP-FPM, pre-compressed gzip files, directory listings,
// and SPA fallback routing.
type web struct {
	route  *alaye.Route // route configuration
	logger *ll.Logger

	php http.Handler // nil if PHP is disabled
}

// NewWeb creates a new web handler for the given route.
// If PHP is enabled in the route configuration, it sets up a FastCGI client.
func NewWeb(logger *ll.Logger, route *alaye.Route) *web {
	h := &web{
		route:  route,
		logger: logger.Namespace("web"),
	}

	// PHP FastCGI support using value-type config (no pointers).
	if route != nil && route.Web.PHP.Status.Active() {
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

// ServeHTTP implements http.Handler for static file serving.
// It handles security checks, PHP execution, gzip pre-compression,
// directory listings, and SPA fallback routing.
func (h *web) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only GET and HEAD are supported. HEAD is handled automatically by http.ServeContent.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Use the original path from context if available (e.g., after host routing).
	browserPath := r.URL.Path
	if v := r.Context().Value(woos.CtxOriginalPath); v != nil {
		if s, ok := v.(string); ok {
			browserPath = s
		}
	}

	// Default to current directory if root is not explicitly set.
	rootPath := "."
	if h.route.Web.Root.IsSet() {
		rootPath = h.route.Web.Root.String()
	}

	// os.OpenRoot (Go 1.21+) provides kernel-level path traversal protection.
	// All subsequent file operations are automatically confined to this root.
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		h.logger.Fields("err", err, "root", rootPath).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer root.Close()

	// Clean and validate the request path.
	reqPath := strings.TrimPrefix(r.URL.Path, "/")
	if reqPath == "" {
		reqPath = "."
	}
	cleanedPath := filepath.Clean(reqPath)

	// Defense-in-depth: explicit traversal check.
	if strings.HasPrefix(cleanedPath, "..") || strings.HasPrefix(cleanedPath, string(filepath.Separator)+"..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Dotfile protection: hide .git, .env, etc., but allow .well-known.
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
	phpEnabled := h.php != nil

	// PHP handling for .php files.
	if strings.HasSuffix(strings.ToLower(reqPath), ".php") {
		if !phpEnabled {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		// Verify file exists before passing to PHP-FPM.
		ff, err := root.Open(reqPath)
		if err == nil {
			info, serr := ff.Stat()
			_ = ff.Close()
			if serr == nil && !info.IsDir() {
				h.php.ServeHTTP(w, r)
				return
			}
		}
		// If open failed, fall through to 404/Error below.
	}

	// Check for pre-compressed gzip version if client accepts it.
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
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

	// Open the requested file.
	f, err := root.Open(reqPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if h.route.Web.SPA {
				indexName := "index.html"
				if h.route.Web.Index != "" {
					indexName = h.route.Web.Index
				}

				// SPA fallback: serve the index file for any non-existent path.
				indexFile, iErr := root.Open(indexName)
				if iErr == nil {
					defer indexFile.Close()
					info, sErr := indexFile.Stat()
					if sErr == nil {
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						w.Header().Set("Cache-Control", "no-cache")
						http.ServeContent(w, r, indexName, info.ModTime(), indexFile)
						return
					}
				}
			}

			http.Error(w, "Not Found", http.StatusNotFound)
		} else if errors.Is(err, fs.ErrPermission) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		} else {
			h.logger.Fields("err", err, "path", reqPath).Debug("file open failed")
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

	// Directory handling.
	if info.IsDir() {
		// Enforce trailing slash for directories.
		if !strings.HasSuffix(browserPath, "/") {
			http.Redirect(w, r, browserPath+"/", http.StatusMovedPermanently)
			return
		}

		indexName := "index.html"
		if h.route.Web.Index != "" {
			indexName = h.route.Web.Index
		}

		// Check for index file.
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

		// Directory listing if enabled.
		if h.route.Web.Listing {
			h.serveDirectoryListing(w, r, f, browserPath)
			return
		}

		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Serve static file.
	if h.setCommonHeaders(w, r, reqPath, info.ModTime(), info.Size(), false) {
		return
	}
	w.Header().Set("Content-Type", getMimeType(reqPath))
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// serveDirectoryListing renders an HTML directory listing.
func (h *web) serveDirectoryListing(w http.ResponseWriter, r *http.Request, f *os.File, displayPath string) {
	entries, err := f.ReadDir(-1)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	items := make([]dirItem, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()

		// Security filters for directory listings.
		if strings.HasPrefix(name, ".") {
			continue // Hide dotfiles
		}
		if entry.IsDir() && strings.HasSuffix(name, ".d") {
			continue // Hide security/config directories
		}
		if name == woos.DefaultConfigName {
			continue // Hide config file
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

	// Sort directories first, then files alphabetically.
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return items[i].Name < items[j].Name
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
		Breadcrumb: h.buildBreadcrumbs(displayPath),
	}

	if err := tmpl.Execute(w, data); err != nil {
		h.logger.Error("template execute error: ", err)
	}
}

// resolveGzipPath determines the gzip path and original path for a request.
func (h *web) resolveGzipPath(reqPath string) (gzPath string, origPath string) {
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

// gzMayExist checks the cache for gzip file existence, defaulting to true if not cached.
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

// gzSetExists caches the existence of a gzip file.
func (h *web) gzSetExists(gzPath string, exists bool) {
	gzExistsCache.StoreTTL(gzPath, &mappo.Item{Value: exists}, gzCacheTTL)
}

// setCommonHeaders sets cache control, ETag, and handles conditional requests.
// Returns true if the response was 304 Not Modified.
func (h *web) setCommonHeaders(
	w http.ResponseWriter,
	r *http.Request,
	reqPath string,
	modTime time.Time,
	size int64,
	isGzipVariant bool,
) (notModified bool) {
	ext := strings.ToLower(filepath.Ext(reqPath))

	// Different caching strategies based on file type.
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

// buildBreadcrumbs creates a breadcrumb navigation trail from a path.
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
