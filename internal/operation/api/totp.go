package api

import (
	"encoding/json"
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/middleware/auth"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// TOTPHandler registers all TOTP API endpoints under /totp.
func TOTPHandler(s *Shared, r chi.Router) {
	t := NewTOTP(s)

	r.Route("/totp", func(r chi.Router) {
		r.Post("/setup", t.setup)
		r.Get("/{user}/qr.svg", t.qrSVG)
		r.Get("/{user}/qr.png", t.qrPNG)
		r.Post("/{user}/verify", t.verify)
	})
}

// TOTP handles TOTP secret generation, QR provisioning, and code verification.
type TOTP struct {
	shared *Shared
	logger *ll.Logger
}

func NewTOTP(cfg *Shared) *TOTP {
	return &TOTP{
		shared: cfg,
		logger: cfg.Logger.Namespace("api/totp"),
	}
}

// setup handles POST /totp/setup.
//
// Generates a new TOTP secret for the authenticated user and persists it to
// keeper at vault://admin/totp/<user>. The HCL config entry for that user
// should reference the secret as:
//
//	totp { user { username = "alice" secret = "vault://admin/totp/alice" } }
//
// expect.Value.ResolveErr will resolve the vault:// reference at login time.
// If keeper is not available the secret is returned but not persisted — a
// warning is logged so this is never silently lost.
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

	var exists bool
	var secret string
	if t.shared.Keeper != nil {
		secretBytes, err := t.shared.Keeper.Get(expect.Vault().AdminTOTP(user))
		if err == nil && len(secretBytes) > 0 {
			exists = true
		}
	}

	if exists {
		http.Error(w, "TOTP already configured for this user", http.StatusConflict)
		return
	}

	secret, uri, err := t.generateSecret(cfg, user)
	if err != nil {
		t.logger.Fields("user", user, "err", err).Error("failed to generate TOTP secret")
		http.Error(w, "Failed to generate secret", http.StatusInternalServerError)
		return
	}

	// Persist the secret to keeper so HCL config can reference it as
	// vault://admin/totp/<user> via expect.Value resolution.
	storeKey := expect.Vault().AdminTOTP(user)
	if t.shared.Keeper != nil {
		if err := t.shared.Keeper.Set(storeKey, []byte(secret)); err != nil {
			t.logger.Fields("user", user, "err", err).Warn("failed to persist TOTP secret to keeper")
		} else {
			t.logger.Fields("user", user, "key", storeKey).Info("TOTP secret stored in keeper")
		}
	} else {
		t.logger.Fields("user", user).Warn("keeper not available — TOTP secret not persisted; add to HCL config manually")
	}

	qr, qrErr := setup.TOTPProvisioningQR(uri)

	resp := map[string]string{
		"secret":    secret,
		"uri":       uri,
		"store_key": storeKey,
		"message":   "Add to HCL: secret = \"" + storeKey + "\"",
	}
	if qrErr == nil {
		resp["qr_svg"] = qr.SVG
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func (t *TOTP) qrSVG(w http.ResponseWriter, r *http.Request) {
	qr, ok := t.buildQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(qr.SVG)) //nolint:errcheck
}

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

// verify handles POST /totp/{user}/verify.
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
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"valid": true,
			"user":  user,
		})
	} else {
		http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
	}
}

// VerifyCode checks a TOTP code for a user against the current admin config.
//
// Secret resolution order (all handled transparently by expect.Value.ResolveErr):
// Plain base32 literal in HCL:   secret = "JBSWY3DPEHPK3PXP"
// Keeper reference in HCL:       secret = "vault://admin/totp/alice"
// Environment variable in HCL:   secret = "env.ALICE_TOTP_SECRET"
//
// Returns false when TOTP is disabled, the user is not found, or the code is wrong.
func (t *TOTP) VerifyCode(username, code string) bool {
	cfg := t.shared.State().Global.Admin.TOTP
	if !cfg.Enabled.Active() {
		return false
	}
	var ok bool
	var secret string
	if t.shared.Keeper != nil {
		secretBytes, err := t.shared.Keeper.Get(expect.Vault().AdminTOTP(username))
		if err == nil && len(secretBytes) > 0 {
			secret = string(secretBytes)
			ok = true
		}
	}
	if !ok || secret == "" {
		return false
	}
	return t.generatorFrom(cfg).VerifyCode(secret, code)
}

func (t *TOTP) buildQR(w http.ResponseWriter, r *http.Request) (*ui.QRResult, bool) {
	v := expect.NewRaw(chi.URLParam(r, "user"))
	user, err := v.Username()
	if err != nil {
		http.Error(w, "invalid user path parameter", http.StatusBadRequest)
		return nil, false
	}

	cfg := t.shared.State().Global.Admin.TOTP
	var ok bool
	var secret string

	if t.shared.Keeper != nil {
		secretBytes, err := t.shared.Keeper.Get(expect.Vault().AdminTOTP(user))
		if err == nil && len(secretBytes) > 0 {
			secret = string(secretBytes)
			ok = true
		}
	}

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

func (t *TOTP) generateSecret(totpCfg alaye.TOTP, username string) (secret, uri string, err error) {
	gen := t.generatorFrom(totpCfg)
	secret, err = gen.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	uri = gen.GetProvisioningURI(secret, username)
	return secret, uri, nil
}

func (t *TOTP) generatorFrom(cfg alaye.TOTP) *security.TOTPGenerator {
	return security.NewTOTPGenerator(&security.TOTPConfig{
		Digits:    cfg.Digits,
		Period:    cfg.Period,
		Algorithm: cfg.Algorithm,
		Window:    cfg.WindowSize,
		Issuer:    cfg.Issuer,
	})
}
