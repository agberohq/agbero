package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
)

// Secret handles CLI commands under `agbero secret`.
// Cryptographic primitives (hashing, generation) all delegate to
// pkg/security so there is no duplicate crypto code here.
type Secret struct {
	p *Helper
}

// Cluster generates a random 32-byte AES-256 gossip key and prints it
// in b64. format ready to paste into agbero.hcl.
func (s *Secret) Cluster() {
	pw := security.NewPassword()
	key, err := pw.Generate(32)
	if err != nil {
		s.p.Logger.Fatal("random generation failed: ", err)
	}

	u := ui.New()
	u.SecretBox("Cluster key", "b64."+key)
	u.InfoLine(`add to agbero.hcl:  gossip { secret_key = "b64.` + key + `" }`)
}

// KeyInit generates the ed25519 key used for internal service-to-service JWT auth.
func (s *Secret) KeyInit(configPath string) {
	global, err := loadGlobal(configPath)
	var targetPath string
	if err == nil && global.Security.InternalAuthKey != "" {
		targetPath = global.Security.InternalAuthKey
	} else {
		ctx := setup.NewContext(s.p.Logger)
		targetPath = filepath.Join(ctx.Paths.DataDir.Path(), woos.InternalAuthKeyName)
	}

	if _, err := os.Stat(targetPath); err == nil {
		s.p.Logger.Warn("key file already exists: ", targetPath)
		return
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		s.p.Logger.Fatal("failed to create directory: ", err)
	}
	if err := security.NewPPK(targetPath); err != nil {
		s.p.Logger.Fatal("failed to generate key: ", err)
	}

	u := ui.New()
	u.SecretBox("Internal auth key", targetPath)
	u.InfoLine(`add to agbero.hcl:  security { enabled = true  internal_auth_key = "` + targetPath + `" }`)
}

// Token mints a signed JWT for a named service using the internal auth key.
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
		ctx := setup.NewContext(s.p.Logger)
		defaultPath := filepath.Join(ctx.Paths.DataDir.Path(), woos.InternalAuthKeyName)
		if _, err := os.Stat(defaultPath); err == nil {
			keyPath = defaultPath
		}
	}
	if keyPath == "" {
		s.p.Logger.Fatal("security.internal_auth_key is not set and default key file not found")
	}

	tm, err := security.PPKLoad(keyPath)
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

	verified, err := tm.Verify(token)
	if err != nil {
		s.p.Logger.Fatal("failed to verify minted token: ", err)
	}

	expires := time.Now().Add(ttl)
	u := ui.New()
	u.SecretBox("API token — "+svcName, token)
	u.KeyValueBlock("", []ui.KV{
		{Label: "Service", Value: svcName},
		{Label: "JTI", Value: verified.JTI},
		{Label: "Expires", Value: expires.Format(time.RFC3339) + "  (" + ttl.String() + ")"},
	})
	u.InfoLine("Keep the JTI — you will need it to revoke this token via POST /api/v1/auto/revoke")
}

// Hash bcrypt-hashes a password and prints the hash.
// If password is empty the user is prompted interactively.
func (s *Secret) Hash(password string) {
	if password == "" {
		fmt.Print("Enter password: ")
		fmt.Scanln(&password)
	}

	pw := security.NewPassword()
	hash, err := pw.Hash(password)
	if err != nil {
		s.p.Logger.Fatal(err)
	}

	u := ui.New()
	u.SecretBox("Bcrypt hash", hash)
}

// Password generates a random password and prints both the plaintext and
// its bcrypt hash, ready to paste into a users = [...] block.
func (s *Secret) Password(length int) {
	if length <= 0 {
		length = 32
	}

	pw := security.NewPassword()
	password, hash, err := pw.Make(length)
	if err != nil {
		s.p.Logger.Fatal("failed to generate password: ", err)
	}

	u := ui.New()
	u.SecretBox("Generated password", password)
	u.SecretBox("Bcrypt hash", hash)
}
