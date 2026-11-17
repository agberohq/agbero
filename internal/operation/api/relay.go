package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// RelayHandler exposes the live relay runtime. It is read-only.
func RelayHandler(shared *Shared, r chi.Router) {
	if shared.Relay == nil {
		return
	}
	r.Get("/relay", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"servers": shared.Relay.Snapshot(),
		})
	})
}
