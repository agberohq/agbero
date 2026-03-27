package helper

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
)

// Keeper handles CLI commands under `agbero keeper`.
//
// Design rule: this file contains only CLI dispatch and UI rendering.
// All cryptographic operations live in internal/pkg/security.
// All QR generation lives in internal/setup.
// openStore() is the only place that touches the filesystem path or prompts.
type Keeper struct {
	p *Helper
}

// --------------------------------------------------------------------------
// Internal: open + unlock store
// --------------------------------------------------------------------------

// openStore derives the keeper DB path from the config, prompts for a
// passphrase if one is not set in the config, and returns an unlocked *Store.
// The caller must call store.Close().
func (k *Keeper) openStore(configPath string) *security.Store {
	global, err := loadGlobal(configPath)
	if err != nil {
		k.p.Logger.Fatal("failed to load config: ", err)
	}

	dataDir := global.Storage.DataDir
	if dataDir == "" {
		ctx := setup.NewContext(k.p.Logger)
		dataDir = ctx.Paths.DataDir.Path()
	}
	dbPath := filepath.Join(dataDir, woos.DefaultKeeperName)

	store, err := security.NewStore(security.StoreConfig{DBPath: dbPath})
	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "temporarily unavailable") {
			k.p.Logger.Fatal("Keeper database is locked by a running Agbero service. Please use the Admin UI/API to manage secrets, or stop the service first.")
		}
		k.p.Logger.Fatal("failed to open keeper: ", err)
	}

	// Prefer passphrase from config (env., ss://, or literal).
	passphrase := global.Security.Keeper.Passphrase.Resolve(os.Getenv)
	if passphrase == "" {
		if err := huh.NewInput().
			Title("Keeper passphrase").
			EchoMode(huh.EchoModePassword).
			Value(&passphrase).
			Run(); err != nil || passphrase == "" {
			k.p.Logger.Fatal("passphrase required to unlock keeper")
		}
	}

	if err := store.Unlock(passphrase); err != nil {
		k.p.Logger.Fatal("unlock failed — wrong passphrase? ", err)
	}

	return store
}

// --------------------------------------------------------------------------
// Commands
// --------------------------------------------------------------------------

// List prints every key in the keeper.
func (k *Keeper) List(configPath string) {
	store := k.openStore(configPath)
	defer store.Close()

	keys, err := store.List()
	if err != nil {
		k.p.Logger.Fatal("list failed: ", err)
	}

	u := ui.New()
	if len(keys) == 0 {
		u.InfoLine("keeper is empty")
		return
	}
	rows := make([][]string, len(keys))
	for i, key := range keys {
		rows[i] = []string{key}
	}
	u.Table([]string{"Key"}, rows)
}

// Get retrieves and prints a single value from the keeper.
func (k *Keeper) Get(configPath, key string) {
	if key == "" {
		k.p.Logger.Fatal("key is required")
	}
	store := k.openStore(configPath)
	defer store.Close()

	val, err := store.Get(key)
	if err != nil {
		k.p.Logger.Fatal("get failed: ", err)
	}

	u := ui.New()
	u.SecretBox(key, val)
}

// Set stores a value in the keeper.
//
//	agbero keeper set mykey "plaintext"          raw string
//	agbero keeper set mykey "SGVsbG8=" --b64     pre-encoded base64 (decoded before storage)
//	agbero keeper set mykey --file cert.pem       read from file (handles certs/binary)
func (k *Keeper) Set(configPath, key, value string, asB64 bool, fromFile string) {
	if key == "" {
		k.p.Logger.Fatal("key is required")
	}

	store := k.openStore(configPath)
	defer store.Close()

	var data []byte
	switch {
	case fromFile != "":
		var err error
		data, err = os.ReadFile(fromFile)
		if err != nil {
			k.p.Logger.Fatal("failed to read file: ", err)
		}
	case asB64:
		var err error
		data, err = base64.StdEncoding.DecodeString(value)
		if err != nil {
			// Try URL encoding
			data, err = base64.URLEncoding.DecodeString(value)
			if err != nil {
				k.p.Logger.Fatal("invalid base64: ", err)
			}
		}
	default:
		data = []byte(value)
	}

	if err := store.SetBytes(key, data); err != nil {
		k.p.Logger.Fatal("set failed: ", err)
	}

	u := ui.New()
	u.SuccessLine(fmt.Sprintf("stored %q (%d bytes)", key, len(data)))
	u.InfoLine("reference in agbero.hcl as:  ss://" + key)
}

// Delete removes a key after optional confirmation.
func (k *Keeper) Delete(configPath, key string, force bool) {
	if key == "" {
		k.p.Logger.Fatal("key is required")
	}
	if !force {
		var confirm bool
		if err := huh.NewConfirm().
			Title(fmt.Sprintf("Delete %q from the keeper?", key)).
			Description("This cannot be undone.").
			Value(&confirm).Run(); err != nil || !confirm {
			fmt.Println("aborted")
			return
		}
	}

	store := k.openStore(configPath)
	defer store.Close()

	if err := store.Delete(key); err != nil {
		k.p.Logger.Fatal("delete failed: ", err)
	}
	ui.New().SuccessLine(fmt.Sprintf("deleted %q", key))
}

// Rotate changes the master passphrase, re-encrypting all secrets.
func (k *Keeper) Rotate(configPath string) {
	store := k.openStore(configPath)
	defer store.Close()

	var newPass, confirm string
	if err := huh.NewInput().Title("NewStore passphrase").EchoMode(huh.EchoModePassword).Value(&newPass).Run(); err != nil || newPass == "" {
		k.p.Logger.Fatal("passphrase required")
	}
	if err := huh.NewInput().Title("Confirm new passphrase").EchoMode(huh.EchoModePassword).Value(&confirm).Run(); err != nil {
		k.p.Logger.Fatal("confirmation required")
	}
	if newPass != confirm {
		k.p.Logger.Fatal("passphrases do not match")
	}
	if err := store.Rotate(newPass); err != nil {
		k.p.Logger.Fatal("rotation failed: ", err)
	}
	ui.New().SuccessLine("passphrase rotated — update keeper.passphrase in agbero.hcl if stored there")
}

// --------------------------------------------------------------------------
// TOTP commands
// --------------------------------------------------------------------------

// TOTPSetup generates a new TOTP secret, stores it in the keeper, and
// renders the provisioning QR both in the terminal and as an SVG hint.
func (k *Keeper) TOTPSetup(configPath, username string) {
	if username == "" {
		k.p.Logger.Fatal("--user is required")
	}

	store := k.openStore(configPath)
	defer store.Close()

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	secret, err := gen.GenerateSecret()
	if err != nil {
		k.p.Logger.Fatal("failed to generate TOTP secret: ", err)
	}

	storeKey := "totp/" + username
	if err := store.Set(storeKey, secret); err != nil {
		k.p.Logger.Fatal("failed to store TOTP secret: ", err)
	}

	uri := gen.GetProvisioningURI(secret, username)
	k.renderTOTPQR(username, storeKey, uri)
}

// TOTPQR fetches an existing TOTP secret from the keeper and re-prints
// the provisioning QR.  Useful if the user lost their authenticator.
func (k *Keeper) TOTPQR(configPath, username string) {
	if username == "" {
		k.p.Logger.Fatal("--user is required")
	}

	store := k.openStore(configPath)
	defer store.Close()

	storeKey := "totp/" + username
	secret, err := store.Get(storeKey)
	if err != nil {
		k.p.Logger.Fatal("TOTP secret not found — run 'agbero keeper totp setup' first: ", err)
	}

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	uri := gen.GetProvisioningURI(secret, username)
	k.renderTOTPQR(username, storeKey, uri)
}

// renderTOTPQR is the shared presentation layer for both setup and qr commands.
// All QR computation lives in internal/setup — here we only call and display.
func (k *Keeper) renderTOTPQR(username, storeKey, uri string) {
	u := ui.New()
	u.SectionHeader("TOTP — " + username)
	u.KeyValue("Store key", "ss://"+storeKey)
	u.Blank()

	// Generate QR using the setup package
	u.QR(uri)

	u.Blank()
	u.InfoLine("Add to agbero.hcl admin block:")
	u.InfoLine(`  totp {`)
	u.InfoLine(`    enabled = "on"`)
	u.InfoLine(`    user {`)
	u.InfoLine(`      username = "` + username + `"`)
	u.InfoLine(`      secret   = "ss://` + storeKey + `"`)
	u.InfoLine(`    }`)
	u.InfoLine(`  }`)
	u.Blank()
	u.InfoLine("Or open the admin UI → Security → TOTP for a scannable QR.")
}
