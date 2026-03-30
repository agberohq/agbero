package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"golang.org/x/crypto/bcrypt"
)

type Home struct {
	ctx *Context
	u   *ui.UI
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

	leEmail, err := h.promptLEEmail()
	if err != nil {
		return err
	}

	h.u.SectionHeader("Initializing configuration")

	if err := h.createDirectories(); err != nil {
		return err
	}

	secrets, err := h.generateSecrets()
	if err != nil {
		return err
	}

	keeperConfig, totpConfig, adminSecretRef, err := h.configureSecurity(secrets.adminSecret)
	if err != nil {
		return err
	}

	if err := h.writeConfigFiles(secrets, leEmail, keeperConfig, totpConfig, adminSecretRef); err != nil {
		return err
	}

	h.displaySuccess(secrets.adminPassword, keeperConfig.mode)

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

func (h *Home) promptLEEmail() (string, error) {
	if !h.ctx.Interactive {
		return "", nil
	}

	ca := NewCA(h.ctx)
	if err := ca.PromptAndInstall(); err != nil {
		h.u.WarnLine("CA installation skipped: " + err.Error())
	}
	h.u.Blank()

	var leEmail string
	err := huh.NewInput().
		Title("Let's Encrypt Email").
		Description("Email for automatic public certificates (optional, leave blank to skip)").
		Placeholder("admin@example.com").
		Value(&leEmail).
		WithWidth(60).
		Run()

	return leEmail, err
}

func (h *Home) createDirectories() error {
	dirs := []woos.Folder{
		h.ctx.Paths.HostsDir,
		h.ctx.Paths.CertsDir,
		h.ctx.Paths.DataDir,
		h.ctx.Paths.LogsDir,
		h.ctx.Paths.WorkDir,
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.Path(), woos.DirPerm); err != nil {
			h.u.ErrorHint("Failed to create directory", d.Path())
			return fmt.Errorf("failed to create directory %s: %w", d.Path(), err)
		}
		h.u.Step("ok", "Created "+d.Path())
	}
	return nil
}

type setupSecrets struct {
	adminSecret       string
	adminPassword     string
	adminPasswordHash []byte
	internalAuthKey   string
}

func (h *Home) generateSecrets() (*setupSecrets, error) {
	h.u.Step("ok", "Generating cryptographic secrets")

	p := security.NewPassword()

	adminSecret, err := p.Generate(128)
	if err != nil {
		return nil, fmt.Errorf("failed to generate admin secret: %w", err)
	}

	internalAuthKeyPath := filepath.Join(h.ctx.Paths.DataDir.Path(), woos.InternalAuthKeyName)
	if err := security.NewPPK(internalAuthKeyPath); err != nil {
		return nil, fmt.Errorf("failed to generate internal auth key: %w", err)
	}
	h.u.Step("ok", "Generated internal auth key")

	adminPassword, err := p.Generate(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate admin password: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash admin password: %w", err)
	}

	return &setupSecrets{
		adminSecret:       adminSecret,
		adminPassword:     adminPassword,
		adminPasswordHash: hash,
		internalAuthKey:   internalAuthKeyPath,
	}, nil
}

type keeperConfig struct {
	mode            string // "standard", "shamir", or "disabled"
	enabled         string // woos.On or woos.Off
	shamirThreshold int
	shamirTotal     int
}

type totpConfig struct {
	enabled bool
	secret  string
}

func (h *Home) configureSecurity(adminSecret string) (*keeperConfig, *totpConfig, string, error) {
	if !h.ctx.Interactive {
		return &keeperConfig{
			mode:    "disabled",
			enabled: woos.Off,
		}, &totpConfig{enabled: false, secret: ""}, adminSecret, nil
	}

	h.u.Blank()
	enableKeeper, err := h.promptEnableKeeper()
	if err != nil {
		return nil, nil, "", err
	}

	if !enableKeeper {
		h.u.InfoLine("Secrets will be stored in plain text in the configuration file")
		return &keeperConfig{
			mode:    "disabled",
			enabled: woos.Off,
		}, &totpConfig{enabled: false, secret: ""}, adminSecret, nil
	}

	h.u.SectionHeader("Configuring Keeper")

	keeperMode, err := h.promptKeeperMode()
	if err != nil {
		return nil, nil, "", err
	}

	dbPath := filepath.Join(h.ctx.Paths.DataDir.Path(), woos.DefaultKeeperName)

	// Remove existing store if present (fresh install)
	if _, err := os.Stat(dbPath); err == nil {
		os.Remove(dbPath)
	}

	var store *security.Store
	var kc *keeperConfig

	switch keeperMode {
	case "shamir":
		kc, store, err = h.setupShamirKeeper(dbPath, adminSecret)
	case "standard":
		kc, store, err = h.setupStandardKeeper(dbPath, adminSecret)
	default:
		return nil, nil, "", fmt.Errorf("unknown keeper mode: %s", keeperMode)
	}

	if err != nil {
		return nil, nil, "", err
	}
	defer store.Close()

	// Now ask about TOTP (only if Keeper is enabled since TOTP secrets are stored there)
	enableTOTP, err := h.promptEnableTOTP()
	if err != nil {
		return nil, nil, "", err
	}

	tc := &totpConfig{enabled: false, secret: ""}

	if enableTOTP {
		totpSecret, err := h.setupTOTP(store)
		if err != nil {
			return nil, nil, "", err
		}
		tc.enabled = true
		tc.secret = "ss://totp/admin"

		uri := security.NewTOTPGenerator(security.DefaultTOTPConfig()).GetProvisioningURI(totpSecret, "admin")
		h.u.SectionHeader("Two-Factor Authentication")
		h.u.InfoLine("Scan this QR code with Google Authenticator, Authy, or another TOTP app")
		h.u.QR(uri)
		h.u.Blank()
	}

	// Store admin JWT secret in Keeper
	if err := store.Set("admin/jwt_secret", adminSecret); err != nil {
		return nil, nil, "", fmt.Errorf("failed to store admin secret in keeper: %w", err)
	}
	h.u.Step("ok", "Stored admin JWT secret in Keeper")

	return kc, tc, "ss://admin/jwt_secret", nil
}

func (h *Home) promptEnableKeeper() (bool, error) {
	var enable bool
	err := huh.NewConfirm().
		Title("Enable encrypted secret store (Keeper)?").
		Description("Keeper encrypts secrets like API keys, passwords, and certificates at rest").
		WithButtonAlignment(lipgloss.Left).
		Value(&enable).
		Run()
	return enable, err
}

func (h *Home) promptEnableTOTP() (bool, error) {
	h.u.Blank()
	var enable bool
	err := huh.NewConfirm().
		Title("Enable TOTP two-factor authentication for admin?").
		Description("Requires an authenticator app (Google Authenticator, Authy, etc.)").
		WithButtonAlignment(lipgloss.Left).
		Value(&enable).
		Run()
	return enable, err
}

func (h *Home) promptKeeperMode() (string, error) {
	var mode string
	options := []huh.Option[string]{
		{Key: "Standard (single passphrase)", Value: "standard"},
		{Key: "Shamir (multiple administrators)", Value: "shamir"},
	}
	err := huh.NewSelect[string]().
		Title("Keeper security mode").
		Description("Select how the master key is protected").
		Options(options...).
		Value(&mode).
		WithWidth(60).
		Run()
	return mode, err
}

func (h *Home) setupStandardKeeper(dbPath, adminSecret string) (*keeperConfig, *security.Store, error) {
	passphrase, err := h.promptPassphrase("Keeper passphrase", "This passphrase will be used to unlock the secret store")
	if err != nil {
		return nil, nil, err
	}
	h.u.Step("ok", "Keeper passphrase recorded")

	store, err := security.NewStore(security.StoreConfig{
		DBPath:           dbPath,
		AutoLockInterval: 0,
		EnableAudit:      true,
		EnableShamir:     false,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret store: %w", err)
	}

	if err := store.Unlock(passphrase); err != nil {
		store.Close()
		return nil, nil, fmt.Errorf("failed to unlock store: %w", err)
	}
	h.u.Step("ok", "Initialized and unlocked Keeper")

	h.u.WarnLine("Keep your passphrase safe – it is the only way to unlock the Keeper")

	return &keeperConfig{
		mode:    "standard",
		enabled: woos.On,
	}, store, nil
}

func (h *Home) setupShamirKeeper(dbPath, adminSecret string) (*keeperConfig, *security.Store, error) {
	h.u.InfoLine("Shamir mode: split trust across multiple administrators")

	totalAdmins, threshold, err := h.promptShamirParams()
	if err != nil {
		return nil, nil, err
	}

	adminPassphrases := make([]string, totalAdmins)
	for i := 0; i < totalAdmins; i++ {
		passphrase, err := h.promptPassphrase(
			fmt.Sprintf("Admin %d passphrase", i+1),
			"This passphrase will be required to unlock the Keeper",
		)
		if err != nil {
			return nil, nil, err
		}
		adminPassphrases[i] = passphrase
		h.u.Step("ok", fmt.Sprintf("Admin %d passphrase recorded", i+1))
	}

	store, err := security.NewStore(security.StoreConfig{
		DBPath:           dbPath,
		AutoLockInterval: 0,
		EnableAudit:      true,
		EnableShamir:     true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret store: %w", err)
	}

	encryptedShares, err := store.InitializeShamir(threshold, totalAdmins, adminPassphrases)
	if err != nil {
		store.Close()
		return nil, nil, fmt.Errorf("failed to initialise store: %w", err)
	}

	for i, share := range encryptedShares {
		sharePath := filepath.Join(h.ctx.Paths.CertsDir.Path(), fmt.Sprintf("keeper_share_%d.bin", i+1))
		if err := os.WriteFile(sharePath, share, 0600); err != nil {
			store.Close()
			return nil, nil, fmt.Errorf("failed to write share %d: %w", i+1, err)
		}
	}
	h.u.Step("ok", fmt.Sprintf("Saved %d Keeper share(s) to %s", len(encryptedShares), h.ctx.Paths.CertsDir.Path()))

	h.u.WarnLine("Store share files AND passphrases in separate secure locations")

	return &keeperConfig{
		mode:            "shamir",
		enabled:         woos.On,
		shamirThreshold: threshold,
		shamirTotal:     totalAdmins,
	}, store, nil
}

func (h *Home) setupTOTP(store *security.Store) (string, error) {
	totpGen := security.NewTOTPGenerator(security.DefaultTOTPConfig())
	totpSecret, err := totpGen.GenerateSecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	if err := store.Set("totp/admin", totpSecret); err != nil {
		return "", fmt.Errorf("failed to store TOTP secret: %w", err)
	}
	h.u.Step("ok", "Stored TOTP secret in Keeper")
	return totpSecret, nil
}

func (h *Home) promptShamirParams() (total, threshold int, err error) {
	var totalStr string
	err = huh.NewInput().
		Title("Number of Keeper administrators").
		Description("How many people will have access to unlock the secret store").
		Value(&totalStr).
		WithWidth(60).
		Run()
	if err != nil {
		return 0, 0, err
	}
	total, err = strconv.Atoi(totalStr)
	if err != nil || total < 2 {
		return 0, 0, fmt.Errorf("invalid number of admins – must be at least 2")
	}

	var threshStr string
	err = huh.NewInput().
		Title("Recovery threshold").
		Description(fmt.Sprintf("How many of the %d admins are needed to unlock the store", total)).
		Value(&threshStr).
		WithWidth(60).
		Run()
	if err != nil {
		return 0, 0, err
	}
	threshold, err = strconv.Atoi(threshStr)
	if err != nil || threshold < 2 || threshold > total {
		return 0, 0, fmt.Errorf("invalid threshold (must be between 2 and %d)", total)
	}

	return total, threshold, nil
}

func (h *Home) promptPassphrase(title, description string) (string, error) {
	var passphrase string
	err := huh.NewInput().
		Title(title).
		Description(description).
		EchoMode(huh.EchoModePassword).
		Value(&passphrase).
		WithWidth(60).
		Run()
	if err != nil {
		return "", err
	}
	if passphrase == "" {
		return "", fmt.Errorf("passphrase required")
	}
	return passphrase, nil
}

func (h *Home) writeConfigFiles(secrets *setupSecrets, leEmail string, kc *keeperConfig, tc *totpConfig, adminSecretRef string) error {
	leEnabled := woos.Off
	if leEmail != "" {
		leEnabled = woos.On
	}

	totpEnabled := woos.Off
	totpSecret := ""
	if tc.enabled {
		totpEnabled = woos.On
		totpSecret = tc.secret
	}

	keeperEnabled := woos.Off
	if kc != nil && kc.enabled != "" {
		keeperEnabled = kc.enabled
	}

	content := ConfigTmpl
	content = strings.ReplaceAll(content, "{HOST_DIR}", filepath.ToSlash(h.ctx.Paths.HostsDir.Path()))
	content = strings.ReplaceAll(content, "{CERTS_DIR}", filepath.ToSlash(h.ctx.Paths.CertsDir.Path()))
	content = strings.ReplaceAll(content, "{DATA_DIR}", filepath.ToSlash(h.ctx.Paths.DataDir.Path()))
	content = strings.ReplaceAll(content, "{LOGS_DIR}", filepath.ToSlash(h.ctx.Paths.LogsDir.Path()))
	content = strings.ReplaceAll(content, "{WORK_DIR}", filepath.ToSlash(h.ctx.Paths.WorkDir.Path()))
	content = strings.ReplaceAll(content, "{ADMIN_PASSWORD}", string(secrets.adminPasswordHash))
	content = strings.ReplaceAll(content, "{ADMIN_SECRET}", adminSecretRef)
	content = strings.ReplaceAll(content, "{INTERNAL_AUTH_KEY}", filepath.ToSlash(secrets.internalAuthKey))
	content = strings.ReplaceAll(content, "{LE_ENABLED}", leEnabled)
	content = strings.ReplaceAll(content, "{LE_EMAIL}", leEmail)
	content = strings.ReplaceAll(content, "{KEEPER_ENABLED}", keeperEnabled)
	content = strings.ReplaceAll(content, "{TOTP_ENABLED}", totpEnabled)
	content = strings.ReplaceAll(content, "{TOTP_ADMIN_SECRECT}", totpSecret)

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

func (h *Home) displaySuccess(adminPassword string, keeperMode string) {
	bin := filepath.Base(os.Args[0])
	nextSteps := []ui.ListItem{
		{Text: "sudo " + bin + " service start"},
		{Text: "sudo " + bin + " service status"},
		{Text: "http://admin.localhost:9090 — admin UI", URL: "http://admin.localhost:9090"},
		{Text: "http://localhost — web UI", URL: "http://localhost"},
	}

	if keeperMode == "shamir" {
		nextSteps = append([]ui.ListItem{
			{Text: fmt.Sprintf("Keeper shares: %s/keeper_share_*.bin", h.ctx.Paths.CertsDir.Path()), URL: "file://" + filepath.ToSlash(h.ctx.Paths.CertsDir.Path())},
			{Text: "Store share files and passphrases in separate secure locations"},
		}, nextSteps...)
	}

	h.u.Blank()
	h.u.InitSuccess(
		h.ctx.Paths.ConfigFile,
		"admin",
		adminPassword,
		nextSteps,
	)
}
