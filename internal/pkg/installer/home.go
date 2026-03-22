package installer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/bcrypt"
)

// Lipgloss styles
var (
	redStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true)
)

type Home struct {
	ctx *Context
}

func NewHome(ctx *Context) *Home {
	return &Home{ctx: ctx}
}

// Run initializes the configuration directory structure and scaffold files.
// Always prompts to install the local CA and optionally collects a Let's Encrypt email.
func (h *Home) Run() error {
	if _, err := os.Stat(h.ctx.Paths.ConfigFile); err == nil {
		return fmt.Errorf("configuration already exists at %s", h.ctx.Paths.ConfigFile)
	}

	var leEmail = ""

	if h.ctx.Interactive {
		h.ctx.Logger.Println(BannerTmpl)
		h.ctx.Logger.Printf("%s - %s\n", woos.Name, woos.Description)
		h.ctx.Logger.Printf("Version: %s\n", woos.Version)
		h.ctx.Logger.Printf("Date: %s\n", time.Now().Format("2006-01-02T15:04:05Z"))
		h.ctx.Logger.Println()

		ca := NewCA(h.ctx)
		if err := ca.PromptAndInstall(); err != nil {
			h.ctx.Logger.Warn("CA prompt interrupted", "err", err)
		}

		h.ctx.Logger.Println()

		err := huh.NewInput().
			Title("Let's Encrypt Email (optional)").
			Description("Enter your email for automatic public certificates. Leave blank to skip:").
			Placeholder("admin@example.com").
			Value(&leEmail).
			Run()

		if err != nil {
			return err
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

	leEnabled := "false"
	if leEmail != "" {
		leEnabled = "true"
	}

	content := ConfigTmpl
	content = strings.ReplaceAll(content, "{HOST_DIR}", filepath.ToSlash(h.ctx.Paths.HostsDir.Path()))
	content = strings.ReplaceAll(content, "{CERTS_DIR}", filepath.ToSlash(h.ctx.Paths.CertsDir.Path()))
	content = strings.ReplaceAll(content, "{DATA_DIR}", filepath.ToSlash(h.ctx.Paths.DataDir.Path()))
	content = strings.ReplaceAll(content, "{LOGS_DIR}", filepath.ToSlash(h.ctx.Paths.LogsDir.Path()))
	content = strings.ReplaceAll(content, "{WORK_DIR}", filepath.ToSlash(h.ctx.Paths.WorkDir.Path()))
	content = strings.ReplaceAll(content, "{ADMIN_PASSWORD}", string(hash))
	content = strings.ReplaceAll(content, "{ADMIN_SECRET}", adminSecret)
	content = strings.ReplaceAll(content, "{INTERNAL_AUTH_KEY}", filepath.ToSlash(internalAuthKeyPath))
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

	// Highlight password in red using Lipgloss
	highlightedPassword := redStyle.Render(adminPassword)

	h.ctx.Logger.Println("\n===============================================================")
	h.ctx.Logger.Println("CONFIGURATION INITIALIZED")
	h.ctx.Logger.Println("===============================================================")
	h.ctx.Logger.Printf("Config File:    %s\n", h.ctx.Paths.ConfigFile)
	h.ctx.Logger.Printf("Admin User:     admin\n")
	h.ctx.Logger.Printf("Admin Password: %s\n", highlightedPassword)
	h.ctx.Logger.Println("===============================================================")
	h.ctx.Logger.Println("Note: Save this password - it will not be shown again.")
	h.ctx.Logger.Println("")
	h.ctx.Logger.Println("Next steps:")
	h.ctx.Logger.Printf("  • Start Agbero:   sudo %s start\n", filepath.Base(os.Args[0]))
	h.ctx.Logger.Printf("  • Check status:   sudo %s status\n", filepath.Base(os.Args[0]))
	h.ctx.Logger.Printf("  • View logs:      sudo %s logs\n", filepath.Base(os.Args[0]))
	h.ctx.Logger.Printf("  • Admin UI:       http://admin.localhost:9090\n")
	h.ctx.Logger.Printf("  • Web UI:         http://localhost\n")
	h.ctx.Logger.Println()

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
	if length < 5 {
		return "", fmt.Errorf("password length must be at least 5")
	}

	const (
		lower   = "abcdefghijklmnopqrstuvwxyz"
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits  = "0123456789"
		symbols = "!@#$%^&*"
	)
	all := lower + upper + digits + symbols

	// Ensure at least one of each character class
	var result []byte
	result = append(result, lower[randByte(len(lower))])
	result = append(result, upper[randByte(len(upper))])
	result = append(result, digits[randByte(len(digits))])
	result = append(result, symbols[randByte(len(symbols))])

	// Fill remaining with random from all charset
	remaining := length - len(result)
	buf := make([]byte, remaining)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for _, b := range buf {
		result = append(result, all[int(b)%len(all)])
	}

	// Shuffle to avoid predictable positions (Fisher-Yates)
	for i := len(result) - 1; i > 0; i-- {
		jBuf := make([]byte, 1)
		if _, err := rand.Read(jBuf); err != nil {
			return "", err
		}
		j := int(jBuf[0]) % (i + 1)
		result[i], result[j] = result[j], result[i]
	}

	return string(result), nil
}

// Helper using crypto/rand directly for uniform distribution
func randByte(max int) int {
	// Rejection sampling for unbiased distribution
	for {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			// Fallback - should not happen with crypto/rand
			return 0
		}
		if int(b[0]) < 256-(256%max) { // Reject values that would create bias
			return int(b[0]) % max
		}
	}
}
