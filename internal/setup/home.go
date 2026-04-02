package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/keeper"
	"golang.org/x/crypto/bcrypt"
)

const (
	name = "setup"
)

type Home struct {
	ctx *Context
	u   *ui.UI
}

type session struct {
	Step              string    `json:"step"`
	AdminUsername     string    `json:"admin_username,omitempty"`
	AdminPasswordHash []byte    `json:"admin_password_hash,omitempty"`
	KeeperUnlocked    bool      `json:"keeper_unlocked"`
	TOTPEnabled       bool      `json:"totp_enabled"`
	TOTPSecret        string    `json:"totp_secret,omitempty"`
	LEEmail           string    `json:"le_email,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func NewHome(ctx *Context) *Home {
	return &Home{
		ctx: ctx,
		u:   ui.New(),
	}
}

func (h *Home) Run() error {
	if err := h.checkExistingConfig(); err != nil {
		return err
	}

	store, sess, err := h.initializeKeeper()
	if err != nil {
		return err
	}
	defer store.Close()

	if err := h.runSetupSteps(store, sess); err != nil {
		return err
	}

	if err := h.writeConfigFiles(store, sess); err != nil {
		return err
	}

	h.displaySuccess(sess)
	return nil
}

func (h *Home) checkExistingConfig() error {
	if _, err := os.Stat(h.ctx.Paths.ConfigFile); err == nil {
		h.u.ErrorHint(
			"Configuration already exists",
			fmt.Sprintf("Remove %s to re-run setup", h.ctx.Paths.ConfigFile),
		)
		return fmt.Errorf("configuration already exists at %s", h.ctx.Paths.ConfigFile)
	}
	return nil
}

func (h *Home) initializeKeeper() (*keeper.Keeper, *session, error) {
	h.u.SectionHeader("Keeper Setup")
	h.u.InfoLine("Agbero requires an encrypted secret store. Let's set it up.")

	if err := os.MkdirAll(h.ctx.Paths.DataDir.Path(), woos.DirPerm); err != nil {
		return nil, nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	store, err := secrets.OpenStore(h.ctx.Paths.DataDir.Path(), nil, h.ctx.Logger)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open/create keeper: %w", err)
	}

	// Set keeper on context for other components
	h.ctx.SetKeeper(store)

	// Create TLS store from keeper and set on context
	tlsStore, err := tlsstore.NewKeeper(store)
	if err != nil {
		store.Close()
		return nil, nil, fmt.Errorf("failed to create TLS store: %w", err)
	}
	h.ctx.SetTLSStore(tlsStore)

	// Try to load existing session
	sess := &session{Step: woos.SetupStepInit, UpdatedAt: time.Now()}
	initData, err := store.Get(expect.Vault().Temp(name))
	if err == nil && len(initData) > 0 {
		if err := json.Unmarshal(initData, &sess); err != nil {
			h.u.WarnLine("Failed to parse saved setup state, starting fresh")
		}
	}

	// If already unlocked, return
	if !store.IsLocked() && sess.KeeperUnlocked {
		return store, sess, nil
	}

	// Need to unlock (new store or locked existing)
	passphraseResult, err := h.u.PasswordConfirmWithHint(
		"Keeper Master Passphrase",
		"This passphrase encrypts ALL secrets. Choose a strong, memorable passphrase.\n"+
			"⚠️  Losing this means losing access to ALL encrypted secrets!",
	)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	passphrase := passphraseResult.Bytes()
	defer passphraseResult.Zero()

	if err := store.Unlock(passphrase); err != nil {
		store.Close()
		return nil, nil, fmt.Errorf("failed to unlock keeper: %w", err)
	}

	sess.KeeperUnlocked = true
	sess.UpdatedAt = time.Now()

	stateBytes, _ := json.Marshal(sess)
	_ = store.Set(expect.Vault().Temp(name), stateBytes)

	h.u.Step("ok", "Keeper initialized and unlocked")
	return store, sess, nil
}

func (h *Home) runSetupSteps(store *keeper.Keeper, sess *session) error {
	steps := []struct {
		name string
		fn   func(*keeper.Keeper, *session) error
	}{
		{woos.SetupStepAdmin, h.setupAdmin},
		{woos.SetupStepKeeperSecrets, h.setupKeeperSecrets},
		{woos.SetupStepTOTP, h.setupTOTP},
		{woos.SetupStepLetsEncrypt, h.setupLetsEncrypt},
	}

	for _, step := range steps {
		if sess.Step == step.name {
			continue
		}
		if err := step.fn(store, sess); err != nil {
			return err
		}
		sess.Step = step.name
		sess.UpdatedAt = time.Now()
		stateBytes, _ := json.Marshal(sess)
		_ = store.Set(expect.Vault().Temp(name), stateBytes)
	}

	sess.Step = woos.SetupStepDone
	stateBytes, _ := json.Marshal(sess)
	_ = store.Set(expect.Vault().Temp(name), stateBytes)

	return nil
}

func (h *Home) setupAdmin(store *keeper.Keeper, sess *session) error {
	if sess.AdminUsername != "" {
		h.u.Step("ok", fmt.Sprintf("Admin user %s already configured", sess.AdminUsername))
		return nil
	}

	h.u.SectionHeader("Admin Account Setup")
	h.u.InfoLine("Create the initial administrator account for your Agbero instance")
	h.u.Blank()

	username, err := h.u.Input(ui.InputConfig{
		Title:       "Username",
		Description: "Choose a username for admin access",
		Placeholder: "admin",
		Width:       60,
	})
	if err != nil {
		return err
	}
	if username == "" {
		username = "admin"
	}

	passwordResult, err := h.u.PasswordConfirmWithHint(
		"Password",
		fmt.Sprintf("Choose a strong password (minimum %d characters)", woos.MinPasswordLength),
	)
	if err != nil {
		return err
	}
	password := passwordResult.String()
	defer passwordResult.Zero()

	if len(password) < woos.MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", woos.MinPasswordLength)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	adminUser := alaye.AdminUser{
		Username:     username,
		PasswordHash: string(hash),
		TOTPEnabled:  false,
		Role:         "superadmin",
		CreatedAt:    time.Now(),
	}

	adminUserJSON, err := json.Marshal(adminUser)
	if err != nil {
		return fmt.Errorf("failed to marshal admin user: %w", err)
	}

	if err := store.Set(expect.Vault().AdminUser(username), adminUserJSON); err != nil {
		return fmt.Errorf("failed to store admin user: %w", err)
	}

	sess.AdminUsername = username
	sess.AdminPasswordHash = hash
	h.u.Step("ok", fmt.Sprintf("Created admin user: %s", username))
	return nil
}

func (h *Home) setupKeeperSecrets(store *keeper.Keeper, sess *session) error {
	h.u.Step("ok", "Generating system secrets")

	p := security.NewPassword()

	adminSecret, err := p.Generate(woos.JWTSecretLength)
	if err != nil {
		return fmt.Errorf("failed to generate admin secret: %w", err)
	}
	if err := store.Set(expect.Vault().AdminJWT(sess.AdminUsername), []byte(adminSecret)); err != nil {
		return fmt.Errorf("failed to store JWT secret: %w", err)
	}
	h.u.Step("ok", "Stored JWT signing secret")

	_, ppkPEM, err := security.GeneratePPK()
	if err != nil {
		return fmt.Errorf("failed to generate internal auth key: %w", err)
	}
	if err := store.Set(expect.Vault().Key("internal"), ppkPEM); err != nil {
		return fmt.Errorf("failed to store PPK: %w", err)
	}
	h.u.Step("ok", "Stored internal auth key")

	clusterSecret, err := p.Generate(woos.ClusterSecretLen)
	if err != nil {
		return fmt.Errorf("failed to generate cluster secret: %w", err)
	}
	if err := store.Set(expect.Vault().Key("cluster"), []byte(clusterSecret)); err != nil {
		return fmt.Errorf("failed to store cluster secret: %w", err)
	}
	h.u.Step("ok", "Stored cluster gossip secret")

	h.u.WarnLine("⚠️  Keep your master passphrase safe – it is the only way to unlock Keeper")
	return nil
}

func (h *Home) setupTOTP(store *keeper.Keeper, sess *session) error {
	if !h.ctx.Interactive {
		return nil
	}

	if sess.TOTPEnabled {
		h.u.Step("ok", "TOTP already configured")
		return nil
	}

	h.u.Blank()
	enableTOTP, err := h.u.Confirm("Enable TOTP two-factor authentication for admin?",
		"Requires an authenticator app (Google Authenticator, Authy, etc.)")
	if err != nil {
		return err
	}

	if !enableTOTP {
		return nil
	}

	totpGen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	totpSecret, err := totpGen.GenerateSecret()
	if err != nil {
		return fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	if err := store.Set(expect.Vault().AdminTOTP(sess.AdminUsername), []byte(totpSecret)); err != nil {
		return fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	adminUserJSON, err := store.Get(expect.Vault().AdminTOTP(sess.AdminUsername))
	if err == nil {
		var adminUser alaye.AdminUser
		if err := json.Unmarshal(adminUserJSON, &adminUser); err == nil {
			adminUser.TOTPEnabled = true
			if updatedJSON, err := json.Marshal(adminUser); err == nil {
				store.Set(expect.Vault().AdminTOTP(sess.AdminUsername), updatedJSON)
			}
		}
	}

	uri := totpGen.GetProvisioningURI(totpSecret, sess.AdminUsername)
	h.u.SectionHeader("Two-Factor Authentication")
	h.u.InfoLine("Scan this QR code with Google Authenticator, Authy, or another TOTP app")
	h.u.QR(uri)
	h.u.Blank()

	sess.TOTPEnabled = true
	sess.TOTPSecret = totpSecret
	h.u.Step("ok", "TOTP enabled")
	return nil
}

func (h *Home) setupLetsEncrypt(store *keeper.Keeper, sess *session) error {
	if !h.ctx.Interactive {
		return nil
	}

	if sess.LEEmail != "" {
		h.u.Step("ok", fmt.Sprintf("Let's Encrypt email: %s", sess.LEEmail))
		return nil
	}

	ca := NewCA(h.ctx)
	if err := ca.PromptAndInstall(); err != nil {
		h.u.WarnLine("CA installation skipped: " + err.Error())
	}
	h.u.Blank()

	leEmail, err := h.u.Input(ui.InputConfig{
		Title:       "Let's Encrypt Email",
		Description: "Email for automatic public certificates (optional, leave blank to skip)",
		Placeholder: "admin@example.com",
		Width:       60,
	})
	if err != nil {
		return err
	}

	sess.LEEmail = leEmail
	if leEmail != "" {
		h.u.Step("ok", fmt.Sprintf("Let's Encrypt email: %s", leEmail))
	}
	return nil
}

func (h *Home) writeConfigFiles(store *keeper.Keeper, sess *session) error {
	leEnabled := woos.Off
	if sess.LEEmail != "" {
		leEnabled = woos.On
	}

	totpEnabled := woos.Off
	if sess.TOTPEnabled {
		totpEnabled = woos.On
	}

	replacements := []struct{ key, value string }{
		{"{HOST_DIR}", filepath.ToSlash(h.ctx.Paths.HostsDir.Path())},
		{"{CERTS_DIR}", filepath.ToSlash(h.ctx.Paths.CertsDir.Path())},
		{"{DATA_DIR}", filepath.ToSlash(h.ctx.Paths.DataDir.Path())},
		{"{LOGS_DIR}", filepath.ToSlash(h.ctx.Paths.LogsDir.Path())},
		{"{WORK_DIR}", filepath.ToSlash(h.ctx.Paths.WorkDir.Path())},
		{"{ADMIN_USERNAME}", sess.AdminUsername},
		{"{ADMIN_SECRET}", expect.Vault().AdminJWT(sess.AdminUsername)},
		{"{INTERNAL_AUTH_KEY}", expect.Vault().Key("internal")},
		{"{LE_ENABLED}", leEnabled},
		{"{LE_EMAIL}", sess.LEEmail},
		{"{KEEPER_ENABLED}", woos.On},
		{"{TOTP_ENABLED}", totpEnabled},
		{"{TOTP_ADMIN_SECRECT}", expect.Vault().AdminTOTP(sess.AdminUsername)},
	}

	content := ConfigTmpl
	for _, r := range replacements {
		content = strings.ReplaceAll(content, r.key, r.value)
	}

	if err := os.WriteFile(h.ctx.Paths.ConfigFile, []byte(content), woos.FilePermSecured); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	h.u.Step("ok", "Written configuration to "+h.ctx.Paths.ConfigFile)

	adminFile := filepath.Join(h.ctx.Paths.HostsDir.Path(), "admin.hcl")
	if err := os.WriteFile(adminFile, TplAdminHcl, woos.FilePerm); err != nil {
		return err
	}
	webFile := filepath.Join(h.ctx.Paths.HostsDir.Path(), "web.hcl")
	if err := os.WriteFile(webFile, TplWebHcl, woos.FilePerm); err != nil {
		return err
	}
	h.u.Step("ok", "Created example host configurations")

	return nil
}

func (h *Home) displaySuccess(sess *session) {
	bin := filepath.Base(os.Args[0])
	nextSteps := []ui.ListItem{
		{Text: "sudo " + bin + " service start"},
		{Text: "sudo " + bin + " service status"},
		{Text: fmt.Sprintf("Login with username: %s and your password", sess.AdminUsername)},
		{Text: "http://admin.localhost:9090 — admin UI", URL: "http://admin.localhost:9090"},
		{Text: "http://localhost — web UI", URL: "http://localhost"},
	}

	if sess.TOTPEnabled {
		nextSteps = append([]ui.ListItem{
			{Text: "TOTP is enabled — you'll need your authenticator app to log in"},
		}, nextSteps...)
	}

	h.u.Blank()
	h.u.InitSuccess(
		h.ctx.Paths.ConfigFile,
		sess.AdminUsername,
		"",
		nextSteps,
	)
}
