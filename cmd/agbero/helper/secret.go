package helper

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agberohq/agbero/internal/pkg/installer"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"golang.org/x/crypto/bcrypt"
)

type Secret struct {
	p *Helper
}

func (s *Secret) Cluster() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		s.p.Logger.Fatal("random generation failed: ", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	u := ui.New()
	u.SecretBox("Cluster key", "b64."+encoded)
	u.InfoLine(`add to agbero.hcl:  gossip { secret_key = "b64.` + encoded + `" }`)
}

func (s *Secret) KeyInit(configPath string) {
	global, err := loadGlobal(configPath)
	var targetPath string
	if err == nil && global.Security.InternalAuthKey != "" {
		targetPath = global.Security.InternalAuthKey
	} else {
		ctx := installer.NewContext(s.p.Logger)
		targetPath = filepath.Join(ctx.Paths.CertsDir.Path(), "internal_auth.key")
	}

	if _, err := os.Stat(targetPath); err == nil {
		s.p.Logger.Warn("key file already exists: ", targetPath)
		return
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		s.p.Logger.Fatal("failed to create directory: ", err)
	}
	if err := security.GenerateNewKeyFile(targetPath); err != nil {
		s.p.Logger.Fatal("failed to generate key: ", err)
	}

	u := ui.New()
	u.SecretBox("Internal auth key", targetPath)
	u.InfoLine(`add to agbero.hcl:  security { enabled = true  internal_auth_key = "` + targetPath + `" }`)
}

func (s *Secret) Token(configPath, svcName string, ttl time.Duration) {
	if svcName == "" {
		s.p.Logger.Fatal("--service name is required")
	}

	global, err := loadGlobal(configPath)
	if err != nil {
		s.p.Logger.Fatal("failed to load config: ", err)
	}

	keyPath := global.Security.InternalAuthKey
	if keyPath == "" {
		ctx := installer.NewContext(s.p.Logger)
		defaultPath := filepath.Join(ctx.Paths.CertsDir.Path(), "internal_auth.key")
		if _, err := os.Stat(defaultPath); err == nil {
			keyPath = defaultPath
		}
	}
	if keyPath == "" {
		s.p.Logger.Fatal("security.internal_auth_key is not set and default key file not found")
	}

	tm, err := security.LoadKeys(keyPath)
	if err != nil {
		s.p.Logger.Fatal("failed to load private key: ", err)
	}

	if ttl == 0 {
		ttl = 365 * 24 * time.Hour
	}

	token, err := tm.Mint(svcName, ttl)
	if err != nil {
		s.p.Logger.Fatal("failed to mint token: ", err)
	}

	u := ui.New()
	u.SecretBox(
		"API token — "+svcName,
		token,
	)
	u.KeyValueBlock("", []ui.KV{
		{Label: "Service", Value: svcName},
		{Label: "Expires", Value: time.Now().Add(ttl).Format(time.RFC3339) + "  (" + ttl.String() + ")"},
	})
}

func (s *Secret) Hash(password string) {
	if password == "" {
		fmt.Print("Enter password: ")
		fmt.Scanln(&password)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.p.Logger.Fatal(err)
	}

	u := ui.New()
	u.SecretBox("Bcrypt hash", string(hash))
}

func (s *Secret) Password(length int) {
	if length <= 0 {
		length = 32
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		s.p.Logger.Fatal("random generation failed: ", err)
	}
	password := base64.URLEncoding.EncodeToString(b)[:length]

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.p.Logger.Fatal("failed to hash password: ", err)
	}

	u := ui.New()
	u.SecretBox("Generated password", password)
	u.SecretBox("Bcrypt hash", string(hash))
}
