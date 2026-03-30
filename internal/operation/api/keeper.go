package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/agberohq/agbero/internal/pkg/expect"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

// KeeperHandler registers all keeper API endpoints under the /keeper prefix on the provided chi.Router.
// Unlock is public; all other endpoints should be protected via middleware applied by the caller.
func KeeperHandler(s *Shared, r chi.Router) {
	k := NewKeeper(s)

	r.Route("/keeper", func(r chi.Router) {
		// Public endpoint - no authentication required
		r.Post("/unlock", k.unlock)
		r.Get("/status", k.status)

		// Protected endpoints - caller should apply auth middleware via r.Use() or r.With()
		r.Group(func(r chi.Router) {
			r.Post("/lock", k.lock)
			r.Get("/secrets", k.list)
			r.Post("/secrets", k.set)
			r.Delete("/secrets/{key}", k.delete)
			r.Get("/secrets/{key}", k.get)
		})
	})
}

// setRequest defines the JSON payload structure for storing secrets via the keeper API.
// It supports raw strings, base64-encoded values, and type hints for certificate storage.
type setRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	B64   bool   `json:"b64"`
}

func (r setRequest) Validate() error {
	// Validate key is not empty
	if r.Key == "" {
		return fmt.Errorf("key is required")
	}

	// Check if it's a secret URI (ss://, secret://, etc.)
	e := expect.New(r.Key)

	// If it's a valid secret URI, use that validation
	if e.Type() == expect.TypeSecret {
		secretPath, err := e.Secret()
		if err != nil {
			return fmt.Errorf("invalid secret URI: %w", err)
		}
		// Store the validated secret path back as string
		r.Key = secretPath.Raw
	} else {
		if !regexp.MustCompile(`^[a-zA-Z0-9_.\-/]+$`).MatchString(r.Key) {
			return fmt.Errorf("key contains invalid characters (allowed: a-z, A-Z, 0-9, _, ., -, /)")
		}
		if len(r.Key) < 1 || len(r.Key) > 256 {
			return fmt.Errorf("key length must be between 1 and 256 characters")
		}
	}

	// Validate value is not empty
	if r.Value == "" {
		return fmt.Errorf("value is required")
	}

	// If B64 is true, validate base64 format
	if r.B64 {
		_, err := decodeB64Loose(r.Value)
		if err != nil {
			return fmt.Errorf("invalid base64 encoding: %w", err)
		}
	}

	return nil
}

// Keeper provides HTTP handlers for secret management and TOTP provisioning operations.
// It encapsulates the security store, logger, and TOTP generator for keeper functionality.
type Keeper struct {
	store  *security.Store
	logger *ll.Logger
	totp   *security.TOTPGenerator
}

// NewKeeper initializes a Keeper instance with shared application dependencies.
// It configures the logger namespace and creates a TOTP generator with default settings.
func NewKeeper(cfg *Shared) *Keeper {
	return &Keeper{
		store:  cfg.Store,
		logger: cfg.Logger.Namespace("api"),
		totp:   security.NewTOTPGenerator(security.DefaultTOTPConfig()),
	}
}

// unlock handles POST requests to decrypt and unlock the security store with a passphrase.
// It validates input, attempts decryption, and wires the resolver for ss:// reference resolution.
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

	if err := k.store.Unlock(body.Passphrase); err != nil {
		k.errorResponse(w, http.StatusUnauthorized, "invalid passphrase")
		return
	}

	security.NewResolver(k.store).Wire()
	k.jsonResponse(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

// lock handles POST requests to encrypt and lock the security store, preventing further access.
// It unwires the resolver and delegates to the store's Lock method with error handling.
func (k *Keeper) lock(w http.ResponseWriter, r *http.Request) {
	if k.store == nil {
		k.errorResponse(w, http.StatusServiceUnavailable, "keeper not configured")
		return
	}
	security.NewResolver(k.store).Unwire()
	if err := k.store.Lock(); err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	k.jsonResponse(w, http.StatusOK, map[string]string{"status": "locked"})
}

// list handles GET requests to retrieve all secret keys currently stored in the keeper.
// It validates store availability and lock status before returning the key list as JSON.
func (k *Keeper) list(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}
	keys, err := k.store.List()
	if err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	if keys == nil {
		keys = []string{}
	}
	k.jsonResponse(w, http.StatusOK, map[string]any{"keys": keys})
}

// get handles GET requests to retrieve a specific secret value by its key from the keeper.
// It validates the key parameter, checks store state, and returns the value or appropriate error.
func (k *Keeper) get(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}

	rawKey := chi.URLParam(r, "key")
	var lookupKey string

	e := expect.New(rawKey)
	if e.Type() == expect.TypeSecret {
		secret, err := e.SecretRef()
		if err != nil {
			k.errorResponse(w, http.StatusBadRequest, "invalid key: "+err.Error())
			return
		}
		lookupKey = secret.WithoutScheme()
	} else {
		// Simple key format (backward compatibility)
		lookupKey = rawKey
	}

	ll.Dbg(lookupKey)
	val, err := k.store.Get(lookupKey)
	if err != nil {
		if err == security.ErrKeyNotFound {
			k.errorResponse(w, http.StatusNotFound, "key not found")
		} else {
			k.errorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	k.jsonResponse(w, http.StatusOK, map[string]string{"key": lookupKey, "value": val})
}

// set handles POST requests to store a new secret, supporting JSON body or multipart file upload.
// It validates input, handles base64 decoding if requested, and stores bytes via the security store.
func (k *Keeper) set(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}

	ct := r.Header.Get("Content-Type")
	var key string
	var data []byte

	if strings.HasPrefix(ct, "multipart/") {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			k.errorResponse(w, http.StatusBadRequest, "bad multipart: "+err.Error())
			return
		}
		key = r.FormValue("key")

		// Validate key using expect
		e := expect.New(key)
		validKey, err := e.SecretKey()
		if err != nil {
			k.errorResponse(w, http.StatusBadRequest, "invalid key: "+err.Error())
			return
		}
		key = validKey

		file, _, err := r.FormFile("file")
		if err != nil {
			k.errorResponse(w, http.StatusBadRequest, "file required")
			return
		}
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, 1<<20))
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

		// Validate the request
		if err := req.Validate(); err != nil {
			k.errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}

		key = req.Key
		if req.B64 {
			data, _ = decodeB64Loose(req.Value)
		} else {
			data = []byte(req.Value)
		}
	}

	if err := k.store.SetBytes(key, data); err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	k.jsonResponse(w, http.StatusOK, map[string]any{
		"key":   key,
		"bytes": len(data),
		"ref":   "ss://" + key,
	})
}

// delete handles DELETE requests to remove a secret from the keeper by its key.
// It validates the key parameter, checks store state, and returns confirmation or error.
func (k *Keeper) delete(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}
	key := chi.URLParam(r, "key")
	if key == "" {
		k.errorResponse(w, http.StatusBadRequest, "key required")
		return
	}
	if err := k.store.Delete(key); err != nil {
		if err == security.ErrKeyNotFound {
			k.errorResponse(w, http.StatusNotFound, "key not found")
		} else {
			k.errorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	k.jsonResponse(w, http.StatusOK, map[string]string{"deleted": key})
}

// totpSetup handles POST requests to generate and store a new TOTP secret for a user.
// It returns the provisioning URI and inline SVG QR code for admin UI integration.
func (k *Keeper) totpSetup(w http.ResponseWriter, r *http.Request) {
	if !k.guard(w) {
		return
	}
	user := chi.URLParam(r, "user")
	if user == "" {
		k.errorResponse(w, http.StatusBadRequest, "user required")
		return
	}

	secret, err := k.totp.GenerateSecret()
	if err != nil {
		k.errorResponse(w, http.StatusInternalServerError, "failed to generate secret")
		return
	}

	storeKey := "totp/" + user
	if err := k.store.Set(storeKey, secret); err != nil {
		k.errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	uri := k.totp.GetProvisioningURI(secret, user)
	qr, err := setup.TOTPProvisioningQR(uri)
	if err != nil {
		k.jsonResponse(w, http.StatusOK, map[string]string{
			"user":      user,
			"store_key": storeKey,
			"ref":       "ss://" + storeKey,
			"uri":       uri,
		})
		return
	}

	k.jsonResponse(w, http.StatusOK, map[string]string{
		"user":      user,
		"store_key": storeKey,
		"ref":       "ss://" + storeKey,
		"uri":       uri,
		"qr_svg":    qr.SVG,
	})
}

// totpQRSVG handles GET requests to return a user's TOTP QR code as a standalone SVG image.
// It builds the QR via shared logic and sets the appropriate Content-Type header.
func (k *Keeper) totpQRSVG(w http.ResponseWriter, r *http.Request) {
	svg, ok := k.buildTOTPQR(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(svg.SVG)) //nolint:errcheck
}

// totpQRPNG handles GET requests to return a user's TOTP QR code as a downloadable PNG image.
// It builds the QR via shared logic and sets Content-Disposition for file download.
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

// guard checks if the keeper store is configured and unlocked before allowing handler execution.
// It returns false and sends an appropriate error response if preconditions are not met.
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

// buildTOTPQR generates a QR code for a user's TOTP secret, handling validation and errors.
// It returns the QR result and a boolean indicating success for caller branching logic.
func (k *Keeper) buildTOTPQR(w http.ResponseWriter, r *http.Request) (*ui.QRResult, bool) {
	if !k.guard(w) {
		return nil, false
	}
	user := chi.URLParam(r, "user")
	if user == "" {
		k.errorResponse(w, http.StatusBadRequest, "user required")
		return nil, false
	}

	secret, err := k.store.Get("totp/" + user)
	if err != nil {
		if err == security.ErrKeyNotFound {
			k.errorResponse(w, http.StatusNotFound, "TOTP not configured for "+user+" — POST /keeper/totp/"+user+" first")
		} else {
			k.errorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return nil, false
	}

	uri := k.totp.GetProvisioningURI(secret, user)
	qr, err := setup.TOTPProvisioningQR(uri)
	if err != nil {
		k.errorResponse(w, http.StatusInternalServerError, "QR generation failed: "+err.Error())
		return nil, false
	}
	return qr, true
}

// errorResponse sends a standardized JSON error response with HTTP status and message.
// It ensures consistent error formatting across all keeper API endpoints.
func (k *Keeper) errorResponse(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// jsonResponse encodes and sends a JSON response with the provided status code and data.
// It logs encoding errors internally without exposing them to the client.
func (k *Keeper) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			k.logger.Error("failed to encode response", "err", err)
		}
	}
}

// status handles GET requests to retrieve the current state of the keeper (enabled and locked status).
// It does not expose any secrets and is safe to be polled by the frontend to trigger unlock modals.
func (k *Keeper) status(w http.ResponseWriter, r *http.Request) {
	enabled := k.store != nil
	locked := false
	if enabled {
		locked = k.store.IsLocked()
	}

	k.jsonResponse(w, http.StatusOK, map[string]any{
		"enabled": enabled,
		"locked":  locked,
	})
}

// decodeB64Loose attempts to decode a base64 string using both standard and URL encodings.
// It returns the decoded bytes or the first error encountered if both attempts fail.
func decodeB64Loose(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
	}
	return data, err
}
