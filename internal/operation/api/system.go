package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

func SystemHandler(s *Shared, r chi.Router) {
	h := &System{shared: s, logger: s.Logger.Namespace("api/system")}
	r.Route("/system", func(r chi.Router) {
		r.Get("/", h.info)
	})
}

type System struct {
	shared *Shared
	logger *ll.Logger
}

type SystemInfo struct {
	Version   string      `json:"version"`
	Commit    string      `json:"commit"`
	BuildDate string      `json:"build_date"`
	GoVersion string      `json:"go_version"`
	OS        string      `json:"os"`
	Arch      string      `json:"arch"`
	Update    *UpdateInfo `json:"update,omitempty"`
}

type UpdateInfo struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// info handles GET /api/v1/system.
//
// Returns static build info and the cached update check result.
// The update check runs once at startup in a background goroutine —
// this endpoint just reads the cached result, so it is always fast
// and never triggers a network call.
func (s *System) info(w http.ResponseWriter, r *http.Request) {
	resp := SystemInfo{
		Version:   woos.Version,
		Commit:    woos.Commit,
		BuildDate: woos.Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	if s.shared.UpdateChecker != nil {
		resp.Update = &UpdateInfo{
			Current:   s.shared.UpdateChecker.GetCurrent(),
			Latest:    s.shared.UpdateChecker.GetLatest(),
			Available: s.shared.UpdateChecker.IsAvailable(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("failed to encode system info", "err", err)
	}
}
