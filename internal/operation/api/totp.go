package api

import (
	"encoding/json"
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// TOTPHandler handles TOTP setup, QR generation, and code verification.
// It is mounted by admin.go's registerAdminRoutes.
//
// The handler reads TOTP config from the global Admin config under a
// read-lock supplied by the caller via the GlobalFn accessor — this
// avoids a direct reference to Server while keeping the hot-reload safe.
type TOTPHandler struct {
	// GlobalFn returns the current Admin config snapshot under whatever
	// lock the caller holds. Called on every request so reloads are picked up.
	GlobalFn func() alaye.Admin

	logger *ll.Logger
}

// NewTOTPHandler constructs a TOTPHandler.
// globalFn must be safe to call concurrently — typically a closure over
// a sync.RWMutex-protected field on Server.
func NewTOTPHandler(globalFn func() alaye.Admin, logger *ll.Logger) *TOTPHandler {
	return &TOTPHandler{
		GlobalFn: globalFn,
		logger:   logger,
	}
}

// Mount registers all TOTP routes on r.  Auth middleware is applied by the caller.
func (h *TOTPHandler) Mount(r chi.Router) {
	r.Post("/api/totp/setup", h.setup)
	r.Get("/api/totp/{user}/qr.svg", h.qrSVG)
	r.Get("/api/totp/{user}/qr.png", h.qrPNG)
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

// setup generates a new TOTP secret for the authenticated user, stores it
// (currently in-memory via the config secret field), and returns the
// provisioning URI plus an inline SVG QR code so the admin UI can render
// it without a second round-trip.
//
// Note: the secret is not yet persisted to the keeper — the caller must
// follow up with a keeper set if they want it durable.  A warning is logged.
func (h *TOTPHandler) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := r.Context().Value("user").(string)
	if !ok || user == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := h.GlobalFn()

	if cfg.TOTP.Enabled.NotActive() {
		http.Error(w, "TOTP not enabled in configuration", http.StatusNotImplemented)
		return
	}
	if _, exists := cfg.TOTP.GetUserSecret(user); exists {
		http.Error(w, "TOTP already configured for this user", http.StatusConflict)
		return
	}

	secret, uri, err := h.generateSecret(cfg.TOTP, user)
	if err != nil {
		h.logger.Fields("user", user, "err", err).Error("failed to generate TOTP secret")
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	h.logger.Fields("user", user).Warn("TOTP secret generated but not persisted — use keeper set to make it durable")

	// Generate QR inline so the admin UI can render it immediately.
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

// qrSVG returns a scannable SVG QR code for a user's existing TOTP secret.
// The secret is looked up from the current admin TOTP config (which may
// reference a keeper value via ss://).
func (h *TOTPHandler) qrSVG(w http.ResponseWriter, r *http.Request) {
	qr, ok := h.buildQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(qr.SVG)) //nolint:errcheck
}

// qrPNG returns the QR code as a PNG for printing or saving.
func (h *TOTPHandler) qrPNG(w http.ResponseWriter, r *http.Request) {
	qr, ok := h.buildQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", `attachment; filename="totp-qr.png"`)
	w.WriteHeader(http.StatusOK)
	w.Write(qr.PNG) //nolint:errcheck
}

// buildQR is the shared resolution + QR generation path for both image endpoints.
func (h *TOTPHandler) buildQR(w http.ResponseWriter, r *http.Request) (*ui.QRResult, bool) {
	user := chi.URLParam(r, "user")
	if user == "" {
		http.Error(w, "user path parameter required", http.StatusBadRequest)
		return nil, false
	}

	cfg := h.GlobalFn()

	secret, ok := cfg.TOTP.GetUserSecret(user)
	if !ok || secret == "" {
		http.Error(w, "TOTP not configured for "+user, http.StatusNotFound)
		return nil, false
	}

	gen := h.generatorFrom(cfg.TOTP)
	uri := gen.GetProvisioningURI(secret, user)

	qr, err := setup.TOTPProvisioningQR(uri)
	if err != nil {
		http.Error(w, "QR generation failed: "+err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	return qr, true
}

// --------------------------------------------------------------------------
// Helpers used by admin.go via method calls on Server
// --------------------------------------------------------------------------

// VerifyCode verifies a TOTP code for username against the current config.
// Exported so admin.go's handleLogin can call it after extracting the handler.
func (h *TOTPHandler) VerifyCode(username, code string) bool {
	cfg := h.GlobalFn()
	if !cfg.TOTP.Enabled.Active() {
		return false
	}
	secret, ok := cfg.TOTP.GetUserSecret(username)
	if !ok || secret == "" {
		return false
	}
	return h.generatorFrom(cfg.TOTP).VerifyCode(secret, code)
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

func (h *TOTPHandler) generateSecret(totpCfg alaye.TOTP, username string) (secret, uri string, err error) {
	gen := h.generatorFrom(totpCfg)
	secret, err = gen.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	uri = gen.GetProvisioningURI(secret, username)
	return secret, uri, nil
}

func (h *TOTPHandler) generatorFrom(cfg alaye.TOTP) *security.TOTPGenerator {
	return security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Window:    cfg.WindowSize,
		Issuer:    cfg.Issuer,
	})
}
