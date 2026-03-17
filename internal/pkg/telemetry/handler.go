package telemetry

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Handler returns an http.Handler that serves the telemetry history API.
//
// Routes:
//
//	GET /history?host=example.localhost&range=1h
//	GET /hosts   — list all hosts that have data
//
// Mount it in admin.go under a protected path, e.g.:
//
//	mux.Handle("/telemetry/", protect(http.StripPrefix("/telemetry", telemetry.Handler(store))))
func Handler(store *Store) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "host parameter required", http.StatusBadRequest)
			return
		}

		rangeKey := r.URL.Query().Get("range")
		if rangeKey == "" {
			rangeKey = "1h"
		}

		qr, ok := KnownRanges[rangeKey]
		if !ok {
			http.Error(w, "invalid range; use 30m, 1h, 6h, or 24h", http.StatusBadRequest)
			return
		}

		samples, err := store.Query(host, qr)
		if err != nil {
			http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Always return an array, never null
		if samples == nil {
			samples = []Sample{}
		}

		resp := struct {
			Host    string   `json:"host"`
			Range   string   `json:"range"`
			Samples []Sample `json:"samples"`
		}{
			Host:    host,
			Range:   qr.Label,
			Samples: samples,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		hosts, err := store.Hosts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if hosts == nil {
			hosts = []string{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hosts": hosts})
	})

	return mux
}
