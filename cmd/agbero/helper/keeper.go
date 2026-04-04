package helper

import (
	"fmt"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	keeperlib "github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keepcmd"
	"github.com/olekukonko/zero"
)

// Keeper handles all `agbero keeper` CLI commands.
type Keeper struct {
	p *Helper
}

// uiOutput implements keepcmd.Output by delegating to agbero's ui.UI.
type uiOutput struct{ u *ui.UI }

func (o *uiOutput) Table(headers []string, rows [][]string) { o.u.Table(headers, rows) }
func (o *uiOutput) KeyValue(label, value string)            { o.u.KeyValue(label, value) }
func (o *uiOutput) Success(msg string)                      { o.u.SuccessLine(msg) }
func (o *uiOutput) Info(msg string)                         { o.u.InfoLine(msg) }
func (o *uiOutput) Error(msg string)                        { o.u.WarnLine(msg) }

// openStore opens an unlocked keeper using the standard resolution chain:
//  1. cfg.Passphrase in agbero.hcl (any expect.Value — env., vault://, b64. …)
//  2. AGBERO_PASSPHRASE environment variable
//  3. Interactive prompt (run mode only — not valid for service mode)
//
// Uses the same pattern as service.go::preflightCheck.
func (k *Keeper) openStore(configPath string) *keeperlib.Keeper {
	global, err := loadGlobal(configPath)
	if err != nil {
		k.p.Logger.Fatal("failed to load config: ", err)
	}

	dataDir := global.Storage.DataDir
	if dataDir == "" {
		ctx := setup.NewContext(k.p.Logger)
		dataDir = ctx.Paths.DataDir.Path()
	}

	store, openErr := secrets.OpenStore(dataDir, &global.Security.Keeper, k.p.Logger)
	if openErr != nil {
		k.p.Logger.Fatal("failed to open keeper: ", openErr)
	}

	if store.IsLocked() {
		// No passphrase from config or env — prompt interactively.
		u := ui.New()
		result, promptErr := u.PasswordRequired("Keeper passphrase")
		if promptErr != nil {
			store.Close()
			k.p.Logger.Fatal("passphrase required: ", promptErr)
		}
		pass := result.Bytes()
		unlockErr := store.Unlock(pass)
		zero.Bytes(pass)
		result.Zero()
		if unlockErr != nil {
			store.Close()
			k.p.Logger.Fatal("invalid passphrase: ", unlockErr)
		}
	}

	return store
}

// cmds returns a keepcmd.Commands instance wired to openStore.
// List, Get, Set, Delete, Backup, and Status all delegate here so there is
// no duplicate implementation of those operations.
func (k *Keeper) cmds(configPath string) *keepcmd.Commands {
	return &keepcmd.Commands{
		Store: func() (*keeperlib.Keeper, error) {
			return k.openStore(configPath), nil
		},
		Out: &uiOutput{u: ui.New()},
	}
}

func (k *Keeper) List(configPath string) {
	if err := k.cmds(configPath).List(); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Get(configPath, key string) {
	if err := k.cmds(configPath).Get(key); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Set(configPath, key, value string, asB64 bool, fromFile string) {
	opts := keepcmd.SetOptions{Base64: asB64, FromFile: fromFile}
	if err := k.cmds(configPath).Set(key, value, opts); err != nil {
		k.p.Logger.Fatal(err)
	}
	ui.New().InfoLine("reference in agbero.hcl as:  ss://" + key)
}

func (k *Keeper) Delete(configPath, key string, force bool) {
	if key == "" {
		k.p.Logger.Fatal("key is required")
	}
	if !force {
		u := ui.New()
		confirm, err := u.Confirm(fmt.Sprintf("Delete %q from the keeper?", key), "This cannot be undone.")
		if err != nil || !confirm {
			fmt.Println("aborted")
			return
		}
	}
	if err := k.cmds(configPath).Delete(key); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Backup(configPath, dest string) {
	if err := k.cmds(configPath).Backup(keepcmd.BackupOptions{Dest: dest}); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Status(configPath string) {
	if err := k.cmds(configPath).Status(); err != nil {
		k.p.Logger.Fatal(err)
	}
}

// Rotate validates the current passphrase then re-derives under a new one.
// We keep this manual (not delegating to keepcmd.Rotate) because we need to
// verify the current passphrase before accepting a new one.
func (k *Keeper) Rotate(configPath string) {
	store := k.openStore(configPath)
	defer store.Close()

	u := ui.New()

	currentResult, err := u.PasswordRequired("Current passphrase")
	if err != nil {
		k.p.Logger.Fatal("current passphrase required: ", err)
	}
	currentPass := currentResult.Bytes()
	defer currentResult.Zero()

	// Verify the current passphrase.
	if err := store.Unlock(currentPass); err != nil {
		k.p.Logger.Fatal("invalid current passphrase: ", err)
	}
	store.Lock()
	zero.Bytes(currentPass)

	newResult, err := u.PasswordConfirm("New passphrase")
	if err != nil {
		k.p.Logger.Fatal("new passphrase required: ", err)
	}
	newPass := newResult.Bytes()
	defer newResult.Zero()

	if err := store.Rotate(newPass); err != nil {
		k.p.Logger.Fatal("rotation failed: ", err)
	}
	zero.Bytes(newPass)

	ui.New().SuccessLine("passphrase rotated — update keeper.passphrase in agbero.hcl if stored there")
}

// TOTPSetup generates a new TOTP secret for a user and stores it at the
// canonical keeper path: vault://admin/totp/<user>.
//
// The user's HCL entry should then reference it as:
//
//	totp { user { username = "alice"  secret = "vault://admin/totp/alice" } }
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

	// Canonical path — same as setup/home.go and api/totp.go.
	storeKey := expect.Vault().AdminTOTP(username)
	if err := store.Set(storeKey, []byte(secret)); err != nil {
		k.p.Logger.Fatal("failed to store TOTP secret: ", err)
	}

	uri := gen.GetProvisioningURI(secret, username)
	k.renderTOTPQR(username, storeKey, uri)
}

// TOTPQR displays the QR code for a user whose TOTP secret is already stored
// in keeper at vault://admin/totp/<user>.
func (k *Keeper) TOTPQR(configPath, username string) {
	if username == "" {
		k.p.Logger.Fatal("--user is required")
	}

	store := k.openStore(configPath)
	defer store.Close()

	storeKey := expect.Vault().AdminTOTP(username)
	secretBytes, err := store.Get(storeKey)
	if err != nil {
		k.p.Logger.Fatal("TOTP secret not found — run 'agbero keeper totp setup' first: ", err)
	}

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	uri := gen.GetProvisioningURI(string(secretBytes), username)
	k.renderTOTPQR(username, storeKey, uri)
}

func (k *Keeper) renderTOTPQR(username, storeKey, uri string) {
	u := ui.New()
	u.SectionHeader("TOTP — " + username)
	u.KeyValue("Store key", storeKey)
	u.Blank()
	u.QR(uri)
	u.Blank()
	u.InfoLine("Add to agbero.hcl admin block:")
	u.InfoLine(`  totp {`)
	u.InfoLine(`    enabled = "on"`)
	u.InfoLine(`    user {`)
	u.InfoLine(`      username = "` + username + `"`)
	u.InfoLine(`      secret   = "` + storeKey + `"`)
	u.InfoLine(`    }`)
	u.InfoLine(`  }`)
	u.Blank()
	u.InfoLine("Or open the admin UI → Security → TOTP for a scannable QR.")
}
