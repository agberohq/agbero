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
		a.p.UI().Abort("keeper store is not available — run 'agbero init' first or check AGBERO_KEEPER_PASSPHRASE / keeper.passphrase_file")
	}
	return a.p.Store
}

func (a *Admin) TOTPSetup(_ string, username string) {
	if username == "" {
		a.p.UI().Abort("--user is required")
	}
	store := a.requireStore()

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	secret, err := gen.GenerateSecret()
	if err != nil {
		a.p.UI().Abort("failed to generate TOTP secret: ", err)
	}

	storeKey := expect.Vault().AdminTOTP(username)
	if err := store.Set(storeKey, []byte(secret)); err != nil {
		a.p.UI().Abort("failed to store TOTP secret: ", err)
	}

	uri := gen.GetProvisioningURI(secret, username)
	a.renderTOTPQR(username, storeKey, uri, secret)
}

func (a *Admin) TOTPQR(_ string, username string) {
	if username == "" {
		a.p.UI().Abort("--user is required")
	}
	store := a.requireStore()

	storeKey := expect.Vault().AdminTOTP(username)
	secretBytes, err := store.Get(storeKey)
	if err != nil {
		a.p.UI().Abort("TOTP secret not found — run 'agbero admin totp setup' first: ", err)
	}

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	uri := gen.GetProvisioningURI(string(secretBytes), username)
	a.renderTOTPQR(username, storeKey, uri, string(secretBytes))
}

func (a *Admin) TOTPQRPNGFile(_ string, username, outFile string) {
	if username == "" {
		a.p.UI().Abort("--user is required")
	}
	store := a.requireStore()

	storeKey := expect.Vault().AdminTOTP(username)
	secretBytes, err := store.Get(storeKey)
	if err != nil {
		a.p.UI().Abort("TOTP secret not found — run 'agbero admin totp setup' first: ", err)
	}

	gen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	uri := gen.GetProvisioningURI(string(secretBytes), username)

	qr, qrErr := setup.TOTPProvisioningQR(uri)
	if qrErr != nil {
		a.p.UI().Abort("QR generation failed: ", qrErr)
	}

	if err := os.WriteFile(outFile, qr.PNG, 0600); err != nil {
		a.p.UI().Abort("failed to write QR PNG: ", err)
	}

	u := ui.New()
	u.Render(func() {
		u.SuccessLine("QR code written to " + outFile)
	})
}

func (a *Admin) renderTOTPQR(username, storeKey, uri, secret string) {
	u := ui.New()
	u.Render(func() {
		u.SectionHeader("TOTP — " + username)
		u.KeyValue("Store key", storeKey)
		u.QR(uri)
		u.Blank()
		u.InfoLine("TOTP secret: " + secret)
		u.InfoLine("Provisioning URI: " + uri)
		u.WarnLine("The secret is shown once. If the QR cannot be scanned, enter the secret manually.")
		u.Blank()
		u.InfoLine("Add to agbero.hcl admin block:")
		u.InfoLine(`  totp {`)
		u.InfoLine(`    enabled = "on"`)
		u.InfoLine(`    user {`)
		u.InfoLine(`      username = "` + username + `"`)
		u.InfoLine(`      secret   = "` + storeKey + `"`)
		u.InfoLine(`    }`)
		u.InfoLine(`  }`)
		u.InfoLine("Or open the admin UI → Security → TOTP for a scannable QR.")
	})
}
