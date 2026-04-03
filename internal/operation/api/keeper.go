package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/agberohq/keeper"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/zero"
)

// KeeperHandler registers all keeper API endpoints under /keeper.
// POST /keeper/unlock and GET /keeper/status are public — no auth required.
// All other routes must be protected by the caller's auth middleware.
func KeeperHandler(s *Shared, r chi.Router) {
	k := NewKeeper(s)

	r.Route("/keeper", func(r chi.Router) {
		r.Post("/unlock", k.unlock)
		r.Get("/status", k.status)

		r.Group(func(r chi.Router) {
			r.Post("/lock", k.lock)
			r.Get("/secrets", k.list)
			r.Post("/secrets", k.set)
			r.Delete("/secrets/*", k.delete)
			r.Get("/secrets/*", k.get)
		})
	})
}

// setRequest is the JSON body for POST /keeper/secrets.
type setRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	B64   bool   `json:"b64"`
}

// Validate checks the request and normalises the key to its scheme-stripped form.
// It rejects keys that are in the internal or vault-managed namespaces.
func (r *setRequest) Validate() error {
	if r.Key == "" {
		return fmt.Errorf("key is required")
	}
	e := expect.NewRaw(r.Key)
	secret, err := e.SecretRef()
	if err != nil {
		return fmt.Errorf("invalid secret path: must be namespace/key or ss://namespace/key — %w", err)
	}
	if isReserved(secret) {
		return fmt.Errorf("key is in a reserved namespace and cannot be modified via API")
	}
	r.Key = secret.WithoutScheme()

	if r.Value == "" {
		return fmt.Errorf("value is required")
	}
	if r.B64 {
		if _, err := decodeB64Loose(r.Value); err != nil {
			return fmt.Errorf("invalid base64 encoding: %w", err)
		}
	}
	return nil
}

// isReserved returns true for keys that must not be accessible through the
// user-facing secrets API:
//
// IsInternal() — namespace "internal" or "internal/*"
// vault:// scheme — agbero-managed keys (admin users, JWT secret, PPK …)
func isReserved(s *expect.Secret) bool {
	return s.IsInternal() || s.Scheme == expect.SchemeVault
}

// Keeper holds the HTTP handlers for secret management.
type Keeper struct {
	store  *keeper.Keeper
	logger *ll.Logger
	totp   *security.TOTPGenerator
}

// NewKeeper constructs a Keeper handler from shared application state.
func NewKeeper(cfg *Shared) *Keeper {
	return &Keeper{
		store:  cfg.Keeper,
		logger: cfg.Logger.Namespace("api/keeper"),
		totp:   security.NewTOTPGenerator(security.DefaultTOTPConfig()),
	}
}

// unlock handles POST /keeper/unlock.
func (k *Keeper) unlock(w http.ResponseWriter, r *http.Request) {
	if k.store == nil {
		k.errorResponse(w, http.StatusServiceUnavailable, "keeper not configured")
		return
	}
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Passphrase == "" {
		k.errorResponse(w, http.StatusBadRequest, "passphrase required")
		return
	}
	pass := []byte(body.Passphrase)
	err := k.store.Unlock(pass)
	zero.Bytes(pass)
	if err != nil {
		k.errorResponse(w, http.StatusUnauthorized, "invalid passphrase")
		return
	}
	secrets.NewResolver(k.store).Wire()
	k.jsonResponse(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

// lock handles POST /keeper/lock.
func (k *Keeper) lock(w http.ResponseWriter, r *http.Request) {
	if k.store == nil {
		k.errorResponse(w, http.StatusServiceUnavailable, "keeper not configured")
		return
	}
	secrets.NewResolver(k.store).Unwire()
	if err := k.store.Lock(); err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	k.jsonResponse(w, http.StatusOK, map[string]string{"status": "locked"})
}

// status handles GET /keeper/status.
func (k *Keeper) status(w http.ResponseWriter, r *http.Request) {
	enabled := k.store != nil
	locked := true
	if enabled {
		locked = k.store.IsLocked()
	}
	k.jsonResponse(w, http.StatusOK, map[string]any{
		"enabled": enabled,
		"locked":  locked,
	})
}

// list handles GET /keeper/secrets.
//
// User-supplied secrets are stored in the "default" keeper scheme under
// whichever namespace the key path specifies (e.g. "prod/db_pass" goes into
// default:prod). This handler iterates all namespaces in the default scheme
// and collects every key, returning a flat list with their full paths
// ("namespace/key") so the caller can reconstruct the original keys.
func (k *Keeper) list(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}

	namespaces, err := k.store.ListNamespacesInSchemeFull("default")
	if err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	var keys []string
	for _, ns := range namespaces {
		if ns == "__default__" {
			// Skip the auto-created empty namespace.
			continue
		}
		nsKeys, err := k.store.ListNamespacedFull("default", ns)
		if err != nil {
			continue // bucket may be locked; skip silently
		}
		for _, key := range nsKeys {
			keys = append(keys, ns+"/"+key)
		}
	}
	if keys == nil {
		keys = []string{}
	}
	k.jsonResponse(w, http.StatusOK, map[string]any{"keys": keys})
}

// get handles GET /keeper/secrets/{key}.
func (k *Keeper) get(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}
	rawKey := chi.URLParam(r, "*")
	if rawKey == "" {
		k.errorResponse(w, http.StatusBadRequest, "key required")
		return
	}
	e := expect.NewRaw(rawKey)
	secret, err := e.SecretRef()
	if err != nil {
		k.errorResponse(w, http.StatusBadRequest,
			"invalid key: must be namespace/key or ss://namespace/key — "+err.Error())
		return
	}
	if isReserved(secret) {
		k.errorResponse(w, http.StatusForbidden, "key is in a reserved namespace")
		return
	}
	lookupKey := secret.WithoutScheme()
	val, err := k.store.Get(lookupKey)
	if err != nil {
		if errors.Is(err, keeper.ErrKeyNotFound) {
			k.errorResponse(w, http.StatusNotFound, "key not found")
		} else {
			k.errorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	k.jsonResponse(w, http.StatusOK, map[string]string{
		"key":   lookupKey,
		"value": string(val),
	})
}

// set handles POST /keeper/secrets (JSON or multipart).
//
// User secrets go into the "default" keeper scheme. A LevelPasswordOnly bucket
// is created for the namespace on first write — CreateBucket is idempotent
// (returns ErrPolicyImmutable if the bucket already exists, which we ignore).
func (k *Keeper) set(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}

	var key string
	var data []byte

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			k.errorResponse(w, http.StatusBadRequest, "bad multipart: "+err.Error())
			return
		}
		rawKey := r.FormValue("key")
		e := expect.NewRaw(rawKey)
		secret, err := e.SecretRef()
		if err != nil {
			k.errorResponse(w, http.StatusBadRequest,
				"invalid key: must be namespace/key or ss://namespace/key — "+err.Error())
			return
		}
		if isReserved(secret) {
			k.errorResponse(w, http.StatusForbidden, "key is in a reserved namespace")
			return
		}
		key = secret.WithoutScheme()

		file, _, err := r.FormFile("file")
		if err != nil {
			k.errorResponse(w, http.StatusBadRequest, "file required")
			return
		}
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, 4<<20))
		if err != nil {
			k.errorResponse(w, http.StatusInternalServerError, "read failed")
			return
		}
		if len(data) == 0 {
			k.errorResponse(w, http.StatusBadRequest, "file cannot be empty")
			return
		}
	} else {
		var req setRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			k.errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		if err := req.Validate(); err != nil {
			k.errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		key = req.Key
		if req.B64 {
			var err error
			data, err = decodeB64Loose(req.Value)
			if err != nil {
				k.errorResponse(w, http.StatusBadRequest, "invalid base64: "+err.Error())
				return
			}
		} else {
			data = []byte(req.Value)
		}
	}

	// Ensure the namespace bucket exists. CreateBucket is idempotent —
	// ErrPolicyImmutable means it already exists, which is fine.
	if err := k.ensureDefaultBucket(key); err != nil {
		k.errorResponse(w, http.StatusInternalServerError, "failed to prepare bucket: "+err.Error())
		return
	}

	if err := k.store.Set(key, data); err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	k.jsonResponse(w, http.StatusOK, map[string]any{
		"key":   key,
		"bytes": len(data),
		"ref":   "ss://" + key,
	})
}

// delete handles DELETE /keeper/secrets/{key}.
func (k *Keeper) delete(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}
	rawKey := chi.URLParam(r, "*")
	if rawKey == "" {
		k.errorResponse(w, http.StatusBadRequest, "key required")
		return
	}
	e := expect.NewRaw(rawKey)
	secret, err := e.SecretRef()
	if err != nil {
		k.errorResponse(w, http.StatusBadRequest,
			"invalid key: must be namespace/key or ss://namespace/key — "+err.Error())
		return
	}
	if isReserved(secret) {
		k.errorResponse(w, http.StatusForbidden, "key is in a reserved namespace")
		return
	}
	normalizedKey := secret.WithoutScheme()
	if err := k.store.Delete(normalizedKey); err != nil {
		if errors.Is(err, keeper.ErrKeyNotFound) {
			k.errorResponse(w, http.StatusNotFound, "key not found")
		} else {
			k.errorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	k.jsonResponse(w, http.StatusOK, map[string]string{"deleted": normalizedKey})
}

// totpSetup handles POST /keeper/totp/{user}.
func (k *Keeper) totpSetup(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}
	user := chi.URLParam(r, "user")
	if user == "" {
		k.errorResponse(w, http.StatusBadRequest, "user required")
		return
	}
	totpSecret, err := k.totp.GenerateSecret()
	if err != nil {
		k.errorResponse(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}
	storeKey := expect.Vault().AdminTOTP(user)
	if err := k.store.Set(storeKey, []byte(totpSecret)); err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	uri := k.totp.GetProvisioningURI(totpSecret, user)
	qr, err := setup.TOTPProvisioningQR(uri)
	resp := map[string]string{
		"user":      user,
		"store_key": storeKey,
		"ref":       storeKey,
		"uri":       uri,
	}
	if err == nil {
		resp["qr_svg"] = qr.SVG
	}
	k.jsonResponse(w, http.StatusOK, resp)
}

// totpQRSVG handles GET /keeper/totp/{user}/qr.svg.
func (k *Keeper) totpQRSVG(w http.ResponseWriter, r *http.Request) {
	qr, ok := k.buildTOTPQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(qr.SVG)) //nolint:errcheck
}

// totpQRPNG handles GET /keeper/totp/{user}/qr.png.
func (k *Keeper) totpQRPNG(w http.ResponseWriter, r *http.Request) {
	qr, ok := k.buildTOTPQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", `attachment; filename="totp-qr.png"`)
	w.WriteHeader(http.StatusOK)
	w.Write(qr.PNG) //nolint:errcheck
}

func (k *Keeper) guard(w http.ResponseWriter) bool {
	if k.store == nil {
		k.errorResponse(w, http.StatusServiceUnavailable, "keeper not configured")
		return false
	}
	if k.store.IsLocked() {
		k.errorResponse(w, http.StatusLocked, "keeper is locked — POST /keeper/unlock first")
		return false
	}
	return true
}

func (k *Keeper) buildTOTPQR(w http.ResponseWriter, r *http.Request) (*ui.QRResult, bool) {
	if !k.guard(w) {
		return nil, false
	}
	user := chi.URLParam(r, "user")
	if user == "" {
		k.errorResponse(w, http.StatusBadRequest, "user required")
		return nil, false
	}
	storeKey := expect.Vault().AdminTOTP(user)
	secretBytes, err := k.store.Get(storeKey)
	if err != nil {
		if errors.Is(err, keeper.ErrKeyNotFound) {
			k.errorResponse(w, http.StatusNotFound,
				"TOTP not configured for "+user+" — POST /keeper/totp/"+user+" first")
		} else {
			k.errorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return nil, false
	}
	uri := k.totp.GetProvisioningURI(string(secretBytes), user)
	qr, err := setup.TOTPProvisioningQR(uri)
	if err != nil {
		k.errorResponse(w, http.StatusInternalServerError, "QR generation failed: "+err.Error())
		return nil, false
	}
	return qr, true
}

// ensureDefaultBucket creates a LevelPasswordOnly bucket in the "default"
// scheme for the namespace parsed from key ("namespace/key" format).
// It is idempotent: ErrPolicyImmutable (bucket already exists) is silently ignored.
func (k *Keeper) ensureDefaultBucket(key string) error {
	// Extract namespace — first segment before "/"
	ns := key
	if idx := strings.Index(key, "/"); idx > 0 {
		ns = key[:idx]
	}
	if ns == "" || ns == "__default__" {
		return nil // no specific namespace, default bucket already seeded
	}
	err := k.store.CreateBucket("default", ns, keeper.LevelPasswordOnly, "api")
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "immutable") || strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

func (k *Keeper) errorResponse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}

func (k *Keeper) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			k.logger.Error("failed to encode response", "err", err)
		}
	}
}

func decodeB64Loose(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
	}
	return data, err
}
