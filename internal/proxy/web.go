package proxy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/config"
)

func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request, web *config.Web) {
	// Security: Prevent directory traversal
	if strings.Contains(r.URL.Path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Build file path
	path := filepath.Join(web.Root, r.URL.Path)

	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Try with index file
			if web.Index != "" {
				path = filepath.Join(web.Root, web.Index)
			} else {
				path = filepath.Join(web.Root, "index.html")
			}
			info, err = os.Stat(path)
			if err != nil {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
		} else {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
	}

	// Serve file
	if info.IsDir() {
		// List directory (simple version)
		s.serveDirectory(w, r, path, web)
		return
	}

	http.ServeFile(w, r, path)
}

func (s *Server) serveDirectory(w http.ResponseWriter, r *http.Request, dir string, web *config.Web) {
	// Check for index file first
	indexFile := "index.html"
	if web.Index != "" {
		indexFile = web.Index
	}

	indexPath := filepath.Join(dir, indexFile)
	if _, err := os.Stat(indexPath); err == nil {
		http.ServeFile(w, r, indexPath)
		return
	}

	// Simple directory listing
	files, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "Cannot read directory", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<html><body><ul>"))

	for _, file := range files {
		name := file.Name()
		if file.IsDir() {
			name += "/"
		}
		w.Write([]byte("<li><a href=\"" + name + "\">" + name + "</a></li>"))
	}

	w.Write([]byte("</ul></body></html>"))
}
