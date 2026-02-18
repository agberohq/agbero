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
	"git.imaxinacion.net/aibox/agbero/internal/pkg/cache"
	"github.com/dustin/go-humanize"
	"github.com/olekukonko/ll"
	"github.com/yookoala/gofast"
)

//go:embed web/dir.html
var webHtml string
var (
	tmpl = template.Must(template.New("web").Parse(webHtml))

	gzExistsCache = cache.New(cache.Options{
		MaximumSize: woos.CacheMax,
	})

	fingerprintRe = regexp.MustCompile(`(?i)(?:[._-])[a-f0-9]{8,}(?:[._-])`)
)

const gzCacheTTL = 60 * time.Second

type dirItem struct {
	Name    string
	IsDir   bool
	Size    string
	ModTime string
	URL     string

	Ext  string
	MIME string
}

type crumb struct {
	Name string // label shown to user
	Href string // absolute path (ends with "/")
}

type web struct {
	route  *alaye.Route
	logger *ll.Logger

	php http.Handler // nil if disabled
}

func NewWeb(logger *ll.Logger, route *alaye.Route) *web {
	h := &web{
		route:  route,
		logger: logger.Namespace("web"),
	}

	// PHP FastCGI support (value-type config; no pointers).
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

func (h *web) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Method Check
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Resolve Host/Path Context
	browserPath := r.URL.Path
	if v := r.Context().Value(woos.CtxOriginalPath); v != nil {
		if s, ok := v.(string); ok {
			browserPath = s
		}
	}

	// 3. Resolve Root Directory
	// Defensive: h.route.Web should not be nil here if constructed correctly,
	// but strictly speaking, pointers can be nil.
	rootPath := "."
	if h.route.Web.Root.IsSet() {
		rootPath = h.route.Web.Root.String()
	}

	// 4. Secure Open (Prevent breakout)
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		h.logger.Fields("err", err, "root", rootPath).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer root.Close()

	// 5. Clean & Validate Path
	reqPath := strings.TrimPrefix(r.URL.Path, "/")
	if reqPath == "" {
		reqPath = "."
	}
	cleanedPath := filepath.Clean(reqPath)

	// Explicit Traversal Check: If clean path tries to go up, block it.
	if strings.HasPrefix(cleanedPath, "..") || strings.HasPrefix(cleanedPath, string(filepath.Separator)+"..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Dotfile Protection (Hide .git, .env, etc.)
	pathParts := strings.Split(cleanedPath, string(filepath.Separator))
	for _, part := range pathParts {
		if part == "." || part == ".." || part == "" {
			continue
		}
		// Allow .well-known but block other dotfiles
		if strings.HasPrefix(part, ".") && part != ".well-known" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	reqPath = cleanedPath
	phpEnabled := h.php != nil

	// 6. PHP Handling
	if strings.HasSuffix(strings.ToLower(reqPath), ".php") {
		if !phpEnabled {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		// Verify file exists before passing to PHP-FPM
		ff, err := root.Open(reqPath)
		if err == nil {
			info, serr := ff.Stat()
			_ = ff.Close()
			if serr == nil && !info.IsDir() {
				h.php.ServeHTTP(w, r)
				return
			}
		}
		// If open failed, fall through to 404/Error below
	}

	// 7. Gzip Pre-compression Lookup
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

	// 8. Open Requested File
	f, err := root.Open(reqPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
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

	// 9. Directory Handling (Index or Listing)
	if info.IsDir() {
		// Enforce trailing slash for directories
		if !strings.HasSuffix(browserPath, "/") {
			http.Redirect(w, r, browserPath+"/", http.StatusMovedPermanently)
			return
		}

		indexName := "index.html"
		if h.route.Web.Index != "" {
			indexName = h.route.Web.Index
		}

		// Check for Index File
		indexPath := filepath.Join(reqPath, indexName)
		indexFile, err := root.Open(indexPath)
		if err == nil {
			defer indexFile.Close()
			indexInfo, err := indexFile.Stat()
			if err == nil && !indexInfo.IsDir() {
				// Serve Index
				if h.setCommonHeaders(w, r, indexName, indexInfo.ModTime(), indexInfo.Size(), false) {
					return
				}
				w.Header().Set("Content-Type", getMimeType(indexName))
				http.ServeContent(w, r, indexName, indexInfo.ModTime(), indexFile)
				return
			}
		}

		// Directory Listing
		if h.route.Web.Listing {
			h.serveDirectoryListing(w, r, f, browserPath)
			return
		}

		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 10. Serve Static File
	if h.setCommonHeaders(w, r, reqPath, info.ModTime(), info.Size(), false) {
		return
	}
	w.Header().Set("Content-Type", getMimeType(reqPath))
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func (h *web) serveDirectoryListing(w http.ResponseWriter, r *http.Request, f *os.File, displayPath string) {
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
	// webHtml pages should revalidate often.
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

func (h *web) gzMayExist(gzPath string) bool {
	it, ok := gzExistsCache.Load(gzPath)
	if !ok {
		return true
	}
	v, ok := cache.Get[bool](it)
	if !ok {
		return true
	}
	return v
}

func (h *web) gzSetExists(gzPath string, exists bool) {
	gzExistsCache.StoreTTL(gzPath, &cache.Item{Value: exists}, gzCacheTTL)
}

func (h *web) setCommonHeaders(
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

func (h *web) buildBreadcrumbs(displayPath string) []crumb {
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
