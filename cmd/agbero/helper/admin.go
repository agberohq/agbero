package helper

import (
	"os"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	keeperlib "github.com/agberohq/keeper"
)

type Admin struct {
	p *Helper
}

// requireStore returns the injected store or fatals with a clear message.
func (a *Admin) requireStore() *keeperlib.Keeper {
	if a.p.Store == nil {
		a.p.Logger.Fatal("keeper store is not available — run 'agbero init' first or check AGBERO_PASSPHRASE")
	}
	return a.p.Store
}

func (a *Admin) TOTPSetup(_ string, username string) {
	if username == "" {
		a.p.Logger.Fatal("--user is required")
	}
	store := a.requireStore()

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	secret, err := gen.GenerateSecret()
	if err != nil {
		a.p.Logger.Fatal("failed to generate TOTP secret: ", err)
	}

	storeKey := expect.Vault().AdminTOTP(username)
	if err := store.Set(storeKey, []byte(secret)); err != nil {
		a.p.Logger.Fatal("failed to store TOTP secret: ", err)
	}

	uri := gen.GetProvisioningURI(secret, username)
	a.renderTOTPQR(username, storeKey, uri)
}

func (a *Admin) TOTPQR(_ string, username string) {
	if username == "" {
		a.p.Logger.Fatal("--user is required")
	}
	store := a.requireStore()

	storeKey := expect.Vault().AdminTOTP(username)
	secretBytes, err := store.Get(storeKey)
	if err != nil {
		a.p.Logger.Fatal("TOTP secret not found — run 'agbero admin totp setup' first: ", err)
	}

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	uri := gen.GetProvisioningURI(string(secretBytes), username)
	a.renderTOTPQR(username, storeKey, uri)
}

func (a *Admin) TOTPQRPNGFile(_ string, username, outFile string) {
	if username == "" {
		a.p.Logger.Fatal("--user is required")
	}
	store := a.requireStore()

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

	u2 := ui.New()
	u2.SuccessLine("QR code written to " + outFile)
	u2.Blank()
}

func (a *Admin) renderTOTPQR(username, storeKey, uri string) {
	u := ui.New()
	u.SectionHeader("TOTP — " + username)
	u.PrintKeyValue("Store key", storeKey)
	u.QR(uri)
	u.Blank()
	u.PrintInfoLine("Add to agbero.hcl admin block:")
	u.PrintInfoLine(`  totp {`)
	u.PrintInfoLine(`    enabled = "on"`)
	u.PrintInfoLine(`    user {`)
	u.PrintInfoLine(`      username = "` + username + `"`)
	u.PrintInfoLine(`      secret   = "` + storeKey + `"`)
	u.PrintInfoLine(`    }`)
	u.PrintInfoLine(`  }`)
	u.PrintInfoLine("Or open the admin UI → Security → TOTP for a scannable QR.")
}
