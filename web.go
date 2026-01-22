package agbero

import (
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request, web *woos.Web) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Clean Path
	reqPath := filepath.Clean(r.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, string(os.PathSeparator))
	if reqPath == "" || reqPath == "." {
		reqPath = "."
	}

	// 2. Open Root (Safe confinement)
	// web.Root.String() handles the default "." if empty
	dir, err := os.OpenRoot(web.Root.String())
	if err != nil {
		s.logger.Fields("err", err, "root", web.Root.String()).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer dir.Close()

	// 3. Open Requested File
	f, err := dir.Open(reqPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Not found", http.StatusNotFound)
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 4. Directory Handling (Index only, no listing)
	if info.IsDir() {
		indexName := "index.html"
		if web.Index != "" {
			indexName = web.Index
		}

		// Re-open index relative to the dir
		indexPath := filepath.Join(reqPath, indexName)
		fIndex, err := dir.Open(indexPath)
		if err != nil {
			// Dir exists but no index -> Forbidden
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		defer fIndex.Close()

		infoIndex, err := fIndex.Stat()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		f = fIndex
		info = infoIndex
		reqPath = indexPath
	}

	// 5. Serve Content
	ctype := mime.TypeByExtension(filepath.Ext(reqPath))
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}

	http.ServeContent(w, r, reqPath, info.ModTime(), f)
}
