package installer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/charmbracelet/huh"
	"golang.org/x/crypto/bcrypt"
)

type Home struct {
	ctx *Context
}

func NewHome(ctx *Context) *Home {
	return &Home{ctx: ctx}
}

func (h *Home) Run() error {
	if _, err := os.Stat(h.ctx.Paths.ConfigFile); err == nil {
		return fmt.Errorf("configuration already exists at %s", h.ctx.Paths.ConfigFile)
	}

	var environment = h.ctx.Env
	var leEmail = ""

	if h.ctx.Interactive {
		fmt.Println(BannerTmpl)

		err := huh.NewSelect[string]().
			Title("How are you planning to use Agbero?").
			Options(
				huh.NewOption("Local Development (Serve local projects / proxy local ports)", "local"),
				huh.NewOption("Production Server (Deploying on a VPS / Cloud server)", "prod"),
			).
			Value(&environment).
			Run()

		if err != nil {
			return err
		}

		h.ctx.Env = environment

		if environment == "local" {
			ca := NewCA(h.ctx)
			if err := ca.PromptAndInstall(); err != nil {
				h.ctx.Logger.Warn("CA prompt interrupted", "err", err)
			}
		} else {
			_ = huh.NewInput().
				Title("Let's Encrypt Email").
				Description("Enter your email for automatic public certificates (Optional but recommended):").
				Placeholder("admin@example.com").
				Value(&leEmail).
				Run()
		}
	}

	h.ctx.Logger.Info("Initializing configuration...")

	dirs := []woos.Folder{
		h.ctx.Paths.HostsDir,
		h.ctx.Paths.CertsDir,
		h.ctx.Paths.DataDir,
		h.ctx.Paths.LogsDir,
		h.ctx.Paths.WorkDir,
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d.Path(), woos.DirPerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", d.Path(), err)
		}
	}

	adminSecret, _ := h.generateSecureKey(128)
	internalAuthKeyPath := filepath.Join(h.ctx.Paths.CertsDir.Path(), "internal_auth.key")
	if err := security.GenerateNewKeyFile(internalAuthKeyPath); err != nil {
		return fmt.Errorf("failed to generate internal auth key: %w", err)
	}

	adminPassword, err := h.generateRandomPassword(16)
	if err != nil {
		return fmt.Errorf("failed to generate admin password: %w", err)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)

	devMode := "true"
	leEnabled := "false"

	if environment == "prod" {
		devMode = "false"
		if leEmail != "" {
			leEnabled = "true"
		}
	}

	content := ConfigTmpl
	content = strings.ReplaceAll(content, "{DEV_MODE}", devMode)
	content = strings.ReplaceAll(content, "{HOST_DIR}", h.ctx.Paths.HostsDir.Path())
	content = strings.ReplaceAll(content, "{CERTS_DIR}", h.ctx.Paths.CertsDir.Path())
	content = strings.ReplaceAll(content, "{DATA_DIR}", h.ctx.Paths.DataDir.Path())
	content = strings.ReplaceAll(content, "{LOGS_DIR}", h.ctx.Paths.LogsDir.Path())
	content = strings.ReplaceAll(content, "{WORK_DIR}", h.ctx.Paths.WorkDir.Path())
	content = strings.ReplaceAll(content, "{ADMIN_PASSWORD}", string(hash))
	content = strings.ReplaceAll(content, "{ADMIN_SECRET}", adminSecret)
	content = strings.ReplaceAll(content, "{INTERNAL_AUTH_KEY}", internalAuthKeyPath)
	content = strings.ReplaceAll(content, "{LE_ENABLED}", leEnabled)
	content = strings.ReplaceAll(content, "{LE_EMAIL}", leEmail)

	if err := os.WriteFile(h.ctx.Paths.ConfigFile, []byte(content), woos.FilePermSecured); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	adminFile := filepath.Join(h.ctx.Paths.HostsDir.Path(), "admin.hcl")
	if err := os.WriteFile(adminFile, TplAdminHcl, woos.FilePerm); err != nil {
		return err
	}

	webFile := filepath.Join(h.ctx.Paths.HostsDir.Path(), "web.hcl")
	if err := os.WriteFile(webFile, TplWebHcl, woos.FilePerm); err != nil {
		return err
	}

	fmt.Println("\n===============================================================")
	fmt.Println("CONFIGURATION INITIALIZED")
	fmt.Println("===============================================================")
	fmt.Printf("Environment:    %s\n", strings.ToUpper(environment))
	fmt.Printf("Config File:    %s\n", h.ctx.Paths.ConfigFile)
	fmt.Printf("Admin User:     admin\n")
	fmt.Printf("Admin Password: %s\n", adminPassword)
	fmt.Println("===============================================================")
	fmt.Println("Note: This password is now hashed in your config file.")
	fmt.Println("")

	return nil
}

func (h *Home) generateSecureKey(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (h *Home) generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[num.Int64()]
	}
	return string(b), nil
}
