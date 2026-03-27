package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// SecretsHandler registers the secrets utility API endpoint under the /secrets prefix on the provided chi.Router.
// Caller should apply authentication middleware via r.Use() before or within the route group.
func SecretsHandler(s *Shared, r chi.Router) {
	sec := NewSecrets(s)

	r.Route("/secrets", func(r chi.Router) {
		r.Post("/", sec.generate)
	})
}

// Secrets provides HTTP handlers for password hashing, random key generation, and token minting operations.
// It encapsulates the security ppk and logger for administrative secret utilities.
type Secrets struct {
	ppk    *security.PPK
	logger *ll.Logger
}

// NewSecrets initializes a Secrets instance with shared application dependencies.
// It configures the logger namespace and prepares the handler for secret operations.
func NewSecrets(cfg *Shared) *Secrets {
	return &Secrets{
		ppk:    cfg.PPK,
		logger: cfg.Logger.Namespace("api"),
	}
}

// generate handles POST requests to perform secret-related operations: hash, password, key, or token generation.
// It parses the action from the request body, validates input, and returns the result as JSON.
func (sec *Secrets) generate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action   string `json:"action"`
		Password string `json:"password"`
		Length   int    `json:"length"`
		Service  string `json:"service"`
		TTL      string `json:"ttl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	pw := security.NewPassword()

	switch req.Action {
	case "hash":
		if req.Password == "" {
			http.Error(w, "Password is required for hashing", http.StatusBadRequest)
			return
		}
		hash, err := pw.Hash(req.Password)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"hash": hash})

	case "password":
		length := req.Length
		if length <= 0 {
			length = 32
		}
		password, hash, err := pw.Make(length)
		if err != nil {
			http.Error(w, "Failed to generate password", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"password": password,
			"hash":     hash,
		})

	case "key":
		length := req.Length
		if length <= 0 {
			length = 32
		}
		key, err := pw.Generate(length)
		if err != nil {
			http.Error(w, "Failed to generate random key", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"key": key})

	case "token":
		if sec.ppk == nil {
			http.Error(w, "Security ppk (internal_auth_key) not configured", http.StatusNotImplemented)
			return
		}
		if req.Service == "" {
			http.Error(w, "Service name is required to mint token", http.StatusBadRequest)
			return
		}

		ttl := 365 * 24 * time.Hour
		if req.TTL != "" {
			parsed, err := time.ParseDuration(req.TTL)
			if err != nil {
				http.Error(w, "Invalid TTL duration format (e.g. use '24h', '30m')", http.StatusBadRequest)
				return
			}
			ttl = parsed
		}

		token, err := sec.ppk.Mint(req.Service, ttl)
		if err != nil {
			http.Error(w, "Failed to mint token", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"token":      token,
			"service":    req.Service,
			"expires_in": ttl.String(),
		})

	default:
		http.Error(w, "Unknown action. Supported actions: hash, password, key, token", http.StatusBadRequest)
	}
}
