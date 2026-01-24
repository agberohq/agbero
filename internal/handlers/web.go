package handlers

import (
	_ "embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/dustin/go-humanize"
	"github.com/olekukonko/ll"
)

// Directory Listing Logic
//
//go:embed dir.html
var dirListingHTML string

var tmpl = template.Must(template.New("dir").Parse(dirListingHTML))

type dirItem struct {
	Name    string
	IsDir   bool
	Size    string
	ModTime string
	URL     string
}

type webHandler struct {
	route  *alaye.Route
	logger *ll.Logger
}

var mimeCache sync.Map // ext -> type

func (h *webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Resolve Root Directory (Securely)
	rootPath := h.route.Web.Root.String()
	if rootPath == "" {
		rootPath = "."
	}

	// os.OpenRoot (Go 1.24+) ensures we cannot escape this directory
	// regardless of what path is passed to it later.
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		h.logger.Fields("err", err, "root", rootPath).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer root.Close()

	// 2. Resolve Request Path
	reqPath := strings.TrimPrefix(r.URL.Path, "/")
	if reqPath == "" {
		reqPath = "."
	}

	// 3. Try Serving Gzip (Optimized)
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gzPath := reqPath + ".gz"
		if reqPath == "." {
			indexName := "index.html"
			if h.route.Web.Index != "" {
				indexName = h.route.Web.Index
			}
			gzPath = indexName + ".gz"
		}

		fGz, err := root.Open(gzPath)
		if err == nil {
			defer fGz.Close()
			infoGz, err := fGz.Stat()
			if err == nil && !infoGz.IsDir() {
				origType := getMimeType(strings.TrimSuffix(gzPath, ".gz"))
				if origType != "" {
					w.Header().Set("Content-Type", origType)
				}
				w.Header().Set("Content-Encoding", "gzip")
				http.ServeContent(w, r, gzPath, infoGz.ModTime(), fGz)
				return
			}
		}
	}

	// 4. Open Target File (Securely via root handle)
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

	// 5. Handle Directory
	if info.IsDir() {
		// Try Index File
		indexName := "index.html"
		if h.route.Web.Index != "" {
			indexName = h.route.Web.Index
		}

		// Use root.Open again for the index to ensure safety
		indexFile, err := root.Open(filepath.Join(reqPath, indexName))
		if err == nil {
			defer indexFile.Close()
			indexInfo, err := indexFile.Stat()
			if err == nil && !indexInfo.IsDir() {
				ctype := getMimeType(indexName)
				if ctype != "" {
					w.Header().Set("Content-Type", ctype)
				}
				http.ServeContent(w, r, indexName, indexInfo.ModTime(), indexFile)
				return
			}
		}

		// No Index Found. Check if Directory Listing is enabled.
		if h.route.Web.Directory {
			h.serveDirectoryListing(w, r, f, "/"+strings.TrimPrefix(reqPath, "."))
			return
		}

		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 6. Serve File
	ctype := getMimeType(reqPath)
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func (h *webHandler) serveDirectoryListing(w http.ResponseWriter, r *http.Request, f *os.File, displayPath string) {
	entries, err := f.ReadDir(-1)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	var items []dirItem
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
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

		items = append(items, dirItem{
			Name:    entry.Name(),
			IsDir:   entry.IsDir(),
			Size:    size,
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			URL:     url.PathEscape(entry.Name()),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return items[i].Name < items[j].Name
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	data := struct {
		Path       string
		ShowParent bool
		Items      []dirItem
	}{
		Path:       displayPath,
		ShowParent: displayPath != "/",
		Items:      items,
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

	// Expanded mime type mapping
	var ctype string
	switch strings.ToLower(ext) {
	case ".html", ".htm":
		ctype = "text/html; charset=utf-8"
	case ".css":
		ctype = "text/css; charset=utf-8"
	case ".js", ".mjs":
		ctype = "application/javascript; charset=utf-8"
	case ".json":
		ctype = "application/json; charset=utf-8"
	case ".png":
		ctype = "image/png"
	case ".jpg", ".jpeg":
		ctype = "image/jpeg"
	case ".gif":
		ctype = "image/gif"
	case ".svg":
		ctype = "image/svg+xml"
	case ".webp":
		ctype = "image/webp"
	case ".pdf":
		ctype = "application/pdf"
	case ".txt", ".md":
		ctype = "text/plain; charset=utf-8"
	case ".xml":
		ctype = "application/xml"
	case ".wasm":
		ctype = "application/wasm"
	case ".mp4":
		ctype = "video/mp4"
	case ".webm":
		ctype = "video/webm"
	default:
		ctype = "application/octet-stream"
	}

	if ctype != "" {
		mimeCache.Store(ext, ctype)
	}
	return ctype
}
