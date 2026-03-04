package operation

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed admin/*
var adminFS embed.FS

// Admin returns an http.Handler that serves the UI files.
// It handles SPA routing (serving index.html for unknown paths if needed,
// though Agbero is mostly a dashboard, so static file serving is usually enough).
func Admin() http.Handler {
	// Strip the "dist" prefix so requests for "/admin/..." map correctly
	fsys, err := fs.Sub(adminFS, "admin")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(fsys))
}
