// totp.go - fixed to use the existing GetUserSecret method
package api

import (
	"encoding/json"
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/pkg/expect"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// TOTPHandler registers all TOTP API endpoints under the /totp prefix on the provided chi.Router.
// Caller should apply authentication middleware via r.Use() before or within the route group.
func TOTPHandler(s *Shared, r chi.Router) {
	t := NewTOTP(s)

	r.Route("/totp", func(r chi.Router) {
		r.Post("/setup", t.setup)
		r.Get("/{user}/qr.svg", t.qrSVG)
		r.Get("/{user}/qr.png", t.qrPNG)
		r.Post("/{user}/verify", t.verify)
	})
}

// TOTP provides HTTP handlers for TOTP secret generation and QR code provisioning.
// It uses the shared config accessor to support hot-reload of admin settings.
type TOTP struct {
	shared *Shared
	logger *ll.Logger
}

// NewTOTP initializes a TOTP instance with shared application dependencies.
// It stores a config accessor function for thread-safe admin config reads.
func NewTOTP(cfg *Shared) *TOTP {
	return &TOTP{
		shared: cfg,
		logger: cfg.Logger.Namespace("api/totp"),
	}
}

// setup handles POST requests to generate a new TOTP secret for the authenticated user.
// It returns the provisioning URI and inline SVG QR code for immediate admin UI rendering.
func (t *TOTP) setup(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.GetClaims(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, ok := claims["user"].(string)
	if !ok || user == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := t.shared.State().Global.Admin.TOTP
	if cfg.Enabled.NotActive() {
		http.Error(w, "TOTP not enabled in configuration", http.StatusNotImplemented)
		return
	}

	// Use the existing GetUserSecret method to check if already configured
	if _, exists := cfg.GetUserSecret(user); exists {
		http.Error(w, "TOTP already configured for this user", http.StatusConflict)
		return
	}

	secret, uri, err := t.generateSecret(cfg, user)
	if err != nil {
		t.logger.Fields("user", user, "err", err).Error("failed to generate TOTP secret")
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	t.logger.Fields("user", user).Warn("TOTP secret generated but not persisted — use keeper set to make it durable")

	qr, qrErr := setup.TOTPProvisioningQR(uri)

	resp := map[string]string{
		"secret":  secret,
		"uri":     uri,
		"message": "Scan QR code with Google Authenticator, Authy, or similar app",
	}
	if qrErr == nil {
		resp["qr_svg"] = qr.SVG
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// qrSVG handles GET requests to return a user's TOTP QR code as a standalone SVG image.
// It builds the QR via shared logic and sets the appropriate Content-Type header.
func (t *TOTP) qrSVG(w http.ResponseWriter, r *http.Request) {
	qr, ok := t.buildQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(qr.SVG)) //nolint:errcheck
}

// qrPNG handles GET requests to return a user's TOTP QR code as a downloadable PNG image.
// It builds the QR via shared logic and sets Content-Disposition for file download.
func (t *TOTP) qrPNG(w http.ResponseWriter, r *http.Request) {
	qr, ok := t.buildQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", `attachment; filename="totp-qr.png"`)
	w.WriteHeader(http.StatusOK)
	w.Write(qr.PNG) //nolint:errcheck
}

// verify handles POST requests to validate a TOTP code for a user.
func (t *TOTP) verify(w http.ResponseWriter, r *http.Request) {
	user := chi.URLParam(r, "user")
	if user == "" {
		http.Error(w, "User required", http.StatusBadRequest)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Code == "" {
		http.Error(w, "Code required", http.StatusBadRequest)
		return
	}

	if t.VerifyCode(user, req.Code) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"valid": true,
			"user":  user,
		})
	} else {
		http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
	}
}

// VerifyCode checks a TOTP code for a username against the current admin config.
// It is exported for use by login handlers and returns false if TOTP is disabled or unset.
func (t *TOTP) VerifyCode(username, code string) bool {
	cfg := t.shared.State().Global.Admin.TOTP
	if !cfg.Enabled.Active() {
		return false
	}

	// Use the existing GetUserSecret method which handles alaye.Value resolution
	secret, ok := cfg.GetUserSecret(username)
	if !ok || secret == "" {
		return false
	}

	// Verify the code
	gen := t.generatorFrom(cfg)
	return gen.VerifyCode(secret, code)
}

// buildQR generates a QR code for a user's TOTP secret, handling validation and errors.
// It returns the QR result and a boolean indicating success for caller branching logic.
func (t *TOTP) buildQR(w http.ResponseWriter, r *http.Request) (*ui.QRResult, bool) {
	v := expect.New(chi.URLParam(r, "user"))
	user, err := v.Username()
	if err != nil {
		http.Error(w, "invalid user path parameter", http.StatusBadRequest)
		return nil, false
	}

	cfg := t.shared.State().Global.Admin.TOTP

	// Use the existing GetUserSecret method
	secret, ok := cfg.GetUserSecret(user)
	if !ok || secret == "" {
		http.Error(w, "TOTP not configured for "+user, http.StatusNotFound)
		return nil, false
	}

	gen := t.generatorFrom(cfg)
	uri := gen.GetProvisioningURI(secret, user)

	qr, err := setup.TOTPProvisioningQR(uri)
	if err != nil {
		http.Error(w, "QR generation failed: "+err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	return qr, true
}

// generateSecret creates a new TOTP secret and provisioning URI for a given username.
// It delegates to the configured TOTPGenerator and returns values for storage and display.
func (t *TOTP) generateSecret(totpCfg alaye.TOTP, username string) (secret, uri string, err error) {
	gen := t.generatorFrom(totpCfg)
	secret, err = gen.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	uri = gen.GetProvisioningURI(secret, username)
	return secret, uri, nil
}

// generatorFrom constructs a TOTPGenerator instance from admin config settings.
// It maps alaye.TOTP fields to security.TOTPConfig for consistent generator initialization.
func (t *TOTP) generatorFrom(cfg alaye.TOTP) *security.TOTPGenerator {
	return security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Window:    cfg.WindowSize,
		Issuer:    cfg.Issuer,
	})
}
