package helper

import (
	"os"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
)

// Admin handles `agbero admin` CLI commands.
// These operations act on agbero-managed admin state in keeper (users, TOTP).
// They are distinct from `agbero keeper` which manages user-supplied secrets.
type Admin struct {
	p *Helper
}

// TOTPSetup generates a new TOTP secret for a user and stores it at the
// canonical keeper path vault://admin/totp/<user>.
//
// After running this, add to agbero.hcl:
//
//	admin {
//	  totp {
//	    enabled = "on"
//	    user {
//	      username = "alice"
//	      secret   = "vault://admin/totp/alice"
//	    }
//	  }
//	}
func (a *Admin) TOTPSetup(configPath, username string) {
	if username == "" {
		a.p.Logger.Fatal("--user is required")
	}

	k := &Keeper{p: a.p}
	store := k.p.openStore(configPath)
	defer store.Close()

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	secret, err := gen.GenerateSecret()
	if err != nil {
		a.p.Logger.Fatal("failed to generate TOTP secret: ", err)
	}

	storeKey := expect.Vault().AdminTOTP(username) // vault://admin/totp/<user>
	if err := store.Set(storeKey, []byte(secret)); err != nil {
		a.p.Logger.Fatal("failed to store TOTP secret: ", err)
	}

	uri := gen.GetProvisioningURI(secret, username)
	a.renderTOTPQR(username, storeKey, uri)
}

// TOTPQR re-displays the QR code for a user whose TOTP secret is already
// stored in keeper at vault://admin/totp/<user>.
func (a *Admin) TOTPQR(configPath, username string) {
	if username == "" {
		a.p.Logger.Fatal("--user is required")
	}

	k := &Keeper{p: a.p}
	store := k.p.openStore(configPath)
	defer store.Close()

	storeKey := expect.Vault().AdminTOTP(username)
	secretBytes, err := store.Get(storeKey)
	if err != nil {
		a.p.Logger.Fatal("TOTP secret not found — run 'agbero admin totp setup' first: ", err)
	}

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	uri := gen.GetProvisioningURI(string(secretBytes), username)
	a.renderTOTPQR(username, storeKey, uri)
}

// TOTPQRPNGFile generates the QR code for a user and writes the PNG to outFile.
func (a *Admin) TOTPQRPNGFile(configPath, username, outFile string) {
	if username == "" {
		a.p.Logger.Fatal("--user is required")
	}

	k := &Keeper{p: a.p}
	store := k.p.openStore(configPath)
	defer store.Close()

	storeKey := expect.Vault().AdminTOTP(username)
	secretBytes, err := store.Get(storeKey)
	if err != nil {
		a.p.Logger.Fatal("TOTP secret not found — run 'agbero admin totp setup' first: ", err)
	}

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	uri := gen.GetProvisioningURI(string(secretBytes), username)

	qr, qrErr := setup.TOTPProvisioningQR(uri)
	if qrErr != nil {
		a.p.Logger.Fatal("QR generation failed: ", qrErr)
	}

	if err := os.WriteFile(outFile, qr.PNG, 0600); err != nil {
		a.p.Logger.Fatal("failed to write QR PNG: ", err)
	}

	ui.New().SuccessLine("QR code written to " + outFile)
}

func (a *Admin) renderTOTPQR(username, storeKey, uri string) {
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
