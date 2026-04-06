package setup

import (
	"encoding/json"
	"errors"
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
)

const name = "setup"

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
	return &Home{ctx: ctx, u: ui.New()}
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

	// Open with nil cfg returns a locked store — caller unlocks.
	store, err := secrets.Open(secrets.Config{
		DataDir: h.ctx.Paths.DataDir,
		Setting: &alaye.Keeper{
			Enabled: alaye.Active,
		},
		Logger:      h.ctx.Logger,
		Interactive: true,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to open/create keeper: %w", err)
	}

	h.ctx.SetKeeper(store)
	tlsStore, err := tlsstore.NewKeeper(store)
	if err != nil {
		store.Close()
		return nil, nil, fmt.Errorf("failed to create TLS store: %w", err)
	}
	h.ctx.SetTLSStore(tlsStore)

	// Try to load existing session state (will return ErrStoreLocked on first run — OK).
	sess := &session{Step: woos.SetupStepInit, UpdatedAt: time.Now()}
	if initData, err := store.Get(expect.Vault().Temp(name)); err == nil && len(initData) > 0 {
		if err := json.Unmarshal(initData, &sess); err != nil {
			h.u.WarnLine("Failed to parse saved setup state, starting fresh")
		}
	}

	if !store.IsLocked() && sess.KeeperUnlocked {
		return store, sess, nil
	}

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

	// After Unlock only default:__default__ is seeded. Every vault:// key
	// needs a policy registered. Create all required vault buckets here, once,
	// immediately after unlock while the store is hot.
	//
	// Bucket mapping (parseKeyExtended splits on first "/" after scheme):
	//   vault://admin/*  → bucket vault:admin  (users, totp, jwt)
	//   vault://key/*    → bucket vault:key    (internal PPK, cluster secret)
	//   vault://temp/*   → bucket vault:temp   (setup session state)
	for _, ns := range expect.VaultBuckets {
		if err := store.CreateBucket("vault", ns, keeper.LevelPasswordOnly, "setup"); err != nil {
			// ErrPolicyImmutable means the bucket already exists — fine on re-runs.
			if !isImmutablePolicyError(err) {
				store.Close()
				return nil, nil, fmt.Errorf("failed to create vault:%s bucket: %w", ns, err)
			}
		}
	}

	sess.KeeperUnlocked = true
	sess.UpdatedAt = time.Now()

	stateBytes, err := json.Marshal(sess)
	if err != nil {
		store.Close()
		return nil, nil, fmt.Errorf("failed to marshal session: %w", err)
	}
	if err := store.Set(expect.Vault().Temp(name), stateBytes); err != nil {
		store.Close()
		return nil, nil, fmt.Errorf("failed to save session state: %w", err)
	}

	h.u.Blank()
	h.u.Step("ok", "Keeper initialised and unlocked")
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
		stateBytes, err := json.Marshal(sess)
		if err != nil {
			return fmt.Errorf("marshal session: %w", err)
		}
		if err := store.Set(expect.Vault().Temp(name), stateBytes); err != nil {
			return fmt.Errorf("save session after step %s: %w", step.name, err)
		}
	}

	sess.Step = woos.SetupStepDone
	stateBytes, _ := json.Marshal(sess)
	_ = store.Set(expect.Vault().Temp(name), stateBytes) // best-effort; non-fatal at completion
	return nil
}

func (h *Home) setupAdmin(store *keeper.Keeper, sess *session) error {
	if sess.AdminUsername != "" {
		h.u.Step("ok", fmt.Sprintf("Admin user %s already configured", sess.AdminUsername))
		return nil
	}

	reg, err := h.u.RegistrationForm("Admin Account Setup", "Create the initial administrator account for your Agbero instance")
	if err != nil {
		return err
	}

	adminUser := alaye.AdminUser{
		Username:     reg.Username,
		PasswordHash: string(reg.PasswordHash),
		TOTPEnabled:  false,
		Role:         "superadmin",
		CreatedAt:    time.Now(),
	}
	adminUserJSON, err := json.Marshal(adminUser)
	if err != nil {
		return fmt.Errorf("failed to marshal admin user: %w", err)
	}
	if err := store.Set(expect.Vault().AdminUser(reg.Username), adminUserJSON); err != nil {
		return fmt.Errorf("failed to store admin user: %w", err)
	}

	sess.AdminUsername = reg.Username
	sess.AdminPasswordHash = reg.PasswordHash
	h.u.Step("ok", fmt.Sprintf("Created admin user: %s", reg.Username))
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
	enableTOTP, err := h.u.Confirm(
		"Enable TOTP two-factor authentication for admin?",
		"Requires an authenticator app (Google Authenticator, Authy, etc.)",
	)
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

	// Store the TOTP base32 secret at the canonical TOTP path.
	if err := store.Set(expect.Vault().AdminTOTP(sess.AdminUsername), []byte(totpSecret)); err != nil {
		return fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	// Update the AdminUser record's TOTPEnabled flag.
	// The AdminUser record lives at AdminUser(username) — NOT at AdminTOTP(username).
	userKey := expect.Vault().AdminUser(sess.AdminUsername)
	if userJSON, err := store.Get(userKey); err == nil {
		var adminUser alaye.AdminUser
		if json.Unmarshal(userJSON, &adminUser) == nil {
			adminUser.TOTPEnabled = true
			if updatedJSON, err := json.Marshal(adminUser); err == nil {
				if err := store.Set(userKey, updatedJSON); err != nil {
					h.u.WarnLine("Failed to update TOTPEnabled flag on admin user record: " + err.Error())
				}
			}
		}
	}

	uri := totpGen.GetProvisioningURI(totpSecret, sess.AdminUsername)
	h.u.SectionHeader("Two-Factor Authentication")
	h.u.InfoLine("Scan this QR code with Google Authenticator, Authy, or another TOTP app")
	h.u.Blank()
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
		{"{INTERNAL_AUTH_KEY}", expect.Vault().Key("internal")},
		{"{LE_ENABLED}", leEnabled},
		{"{LE_EMAIL}", sess.LEEmail},
		{"{KEEPER_ENABLED}", woos.On},
		{"{TOTP_ENABLED}", totpEnabled},
	}

	content := ConfigTmpl
	for _, r := range replacements {
		content = strings.ReplaceAll(content, r.key, r.value)
	}

	if err := os.WriteFile(h.ctx.Paths.ConfigFile, []byte(content), expect.FilePermSecured); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	h.u.Step("ok", "Written configuration to "+h.ctx.Paths.ConfigFile)

	err := h.ctx.Paths.HostsDir.Make(true)
	if err != nil {
		return fmt.Errorf("failed to initialize host directory: %w", err)
	}

	err = h.ctx.Paths.HostsDir.Put("admin.hcl", TplAdminHcl, expect.FilePerm)
	if err != nil {
		return fmt.Errorf("failed to write admin host config: %w", err)
	}

	err = h.ctx.Paths.HostsDir.Put("web.hcl", TplWebHcl, expect.FilePerm)
	if err != nil {
		return fmt.Errorf("failed to write web host config: %w", err)
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
	h.u.InitSuccess(h.ctx.Paths.ConfigFile, sess.AdminUsername, "", nextSteps)
}

// isImmutablePolicyError returns true when err indicates a bucket policy
// already exists — which is safe to ignore on re-runs.
func isImmutablePolicyError(err error) bool {
	return errors.Is(err, keeper.ErrPolicyImmutable)
}
