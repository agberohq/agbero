package installer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

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
		fmt.Printf("%s - %s\n", woos.Name, woos.Description)
		fmt.Printf("Version: %s\n", woos.Version) // You might want to get this from build info
		fmt.Printf("Date: %s\n", time.Now().Format("2006-01-02T15:04:05Z"))
		fmt.Println()

		fmt.Println("Environment Selection:")
		fmt.Println("  [local]  Local Development")
		fmt.Println("           • Serve local projects")
		fmt.Println("           • Proxy local ports")
		fmt.Println("           • Development domains with HTTPS")
		fmt.Println()
		fmt.Println("  [prod]   Production Server")
		fmt.Println("           • Deploy on VPS/Cloud servers")
		fmt.Println("           • Let's Encrypt SSL certificates")
		fmt.Println("           • High availability setup")
		fmt.Println()

		err := huh.NewSelect[string]().
			Title("How are you planning to use Agbero?").
			Options(
				huh.NewOption("Local Development", "local"),
				huh.NewOption("Production Server", "prod"),
			).
			Value(&environment).
			Run()

		if err != nil {
			return err
		}

		h.ctx.Env = environment
		fmt.Println()

		if environment == "local" {
			fmt.Println("Setting up local development environment...")
			fmt.Println()

			ca := NewCA(h.ctx)
			if err := ca.PromptAndInstall(); err != nil {
				h.ctx.Logger.Warn("CA prompt interrupted", "err", err)
			}
		} else {
			fmt.Println("Setting up production environment...")
			fmt.Println()

			err := huh.NewInput().
				Title("Let's Encrypt Email").
				Description("Enter your email for automatic public certificates (Optional but recommended):").
				Placeholder("admin@example.com").
				Value(&leEmail).
				Run()

			if err != nil {
				return err
			}
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

	adminSecret, err := h.generateSecureKey(128)
	if err != nil {
		return fmt.Errorf("failed to generate admin secret: %w", err)
	}

	internalAuthKeyPath := filepath.Join(h.ctx.Paths.CertsDir.Path(), "internal_auth.key")
	if err := security.GenerateNewKeyFile(internalAuthKeyPath); err != nil {
		return fmt.Errorf("failed to generate internal auth key: %w", err)
	}

	adminPassword, err := h.generateRandomPassword(16)
	if err != nil {
		return fmt.Errorf("failed to generate admin password: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

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

	// Professional summary with ASCII only
	fmt.Println("\n===============================================================")
	fmt.Println("CONFIGURATION INITIALIZED")
	fmt.Println("===============================================================")
	fmt.Printf("Environment:    %s\n", strings.ToUpper(environment))
	fmt.Printf("Config File:    %s\n", h.ctx.Paths.ConfigFile)
	fmt.Printf("Admin User:     admin\n")
	fmt.Printf("Admin Password: %s\n", adminPassword)
	fmt.Println("===============================================================")
	fmt.Println("Note: Save this password - it will not be shown again.")
	fmt.Println("")
	fmt.Println("Next steps:")
	fmt.Printf("  • Start Agbero:   sudo %s start\n", filepath.Base(os.Args[0]))
	fmt.Printf("  • Check status:   sudo %s status\n", filepath.Base(os.Args[0]))
	fmt.Printf("  • View logs:      sudo %s logs\n", filepath.Base(os.Args[0]))
	fmt.Printf("  • Admin UI:       http://admin.localhost:9090\n")
	fmt.Printf("  • Web UI:         http://localhost\n")
	fmt.Println("")
	fmt.Println("For more information, visit https://agbero.io/docs")
	fmt.Println()

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
