package helper

import (
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	keeperlib "github.com/agberohq/keeper"
)

type Secret struct {
	p *Helper
}

// requireStore returns the injected keeper or fatals. Mirrors the pattern
// used by the Keeper helper — all methods that need auth call this first.
func (s *Secret) requireStore() *keeperlib.Keeper {
	if s.p.Store == nil {
		s.p.Logger.Fatal("keeper is not available — run 'agbero init' first or check AGBERO_PASSPHRASE")
	}
	return s.p.Store
}

// Cluster generates a random AES-256 gossip secret key and prints it with
// the agbero.hcl snippet needed to activate it.
// No keeper access required — this is a standalone random value.
func (s *Secret) Cluster() {
	pw := security.NewPassword()
	key, err := pw.Generate(32)
	if err != nil {
		s.p.Logger.Fatal("random generation failed: ", err)
	}

	u := ui.New()
	u.Render(func() {
		u.SecretBox("Cluster key", "b64."+key)
		u.InfoLine(`add to agbero.hcl:  gossip { secret_key = "b64.` + key + `" }`)
	})
}

// KeyInit generates a new Ed25519 internal auth key and stores it in the keeper
// at vault://key/internal. Used to rotate the key after initial setup.
// The key never touches the filesystem.
func (s *Secret) KeyInit(_ string) {
	store := s.requireStore()

	existing, err := store.Get(expect.Vault().Key("internal"))
	if err == nil && len(existing) > 0 {
		s.p.Logger.Warn("internal auth key already exists in keeper — delete it first: agbero keeper delete vault://key/internal")
		return
	}

	_, pemBytes, err := security.GeneratePPK()
	if err != nil {
		s.p.Logger.Fatal("failed to generate internal auth key: ", err)
	}

	if err := store.EnsureBucket(expect.Vault().Key("internal")); err != nil {
		s.p.Logger.Fatal("failed to ensure vault key bucket in keeper: ", err)
	}

	if err := store.Set(expect.Vault().Key("internal"), pemBytes); err != nil {
		s.p.Logger.Fatal("failed to store internal auth key in keeper: ", err)
	}

	u := ui.New()
	u.Render(func() {
		u.SuccessLine("internal auth key stored in keeper at vault://key/internal")
		u.InfoLine("managed by keeper — no file path needed in agbero.hcl")
	})
}

// Token mints a signed JWT for an external service using the internal auth key
// from the keeper (vault://key/internal). Prints the token and the JTI needed
// to revoke it later via POST /api/v1/auto/revoke.
func (s *Secret) Token(_ string, svcName string, ttl time.Duration) {
	if svcName == "" {
		s.p.Logger.Fatal("--service name is required")
	}

	store := s.requireStore()

	pemBytes, err := store.Get(expect.Vault().Key("internal"))
	if err != nil || len(pemBytes) == 0 {
		s.p.Logger.Fatal("internal auth key not found in keeper — run 'agbero secret key init' first")
	}

	tm, err := security.LoadPPKFromPEM(pemBytes)
	if err != nil {
		s.p.Logger.Fatal("failed to load internal auth key: ", err)
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
	u.Render(func() {
		u.SecretBox("API token — "+svcName, token)
		u.KeyValueBlock("", []ui.KV{
			{Label: "Service", Value: svcName},
			{Label: "JTI", Value: verified.JTI},
			{Label: "Expires", Value: expires.Format(time.RFC3339) + "  (" + ttl.String() + ")"},
		})
		u.InfoLine("Keep the JTI — you will need it to revoke this token via POST /api/v1/auto/revoke")
	})
}

// Hash bcrypt-hashes a password and prints the result.
func (s *Secret) Hash(password string) {
	if password == "" {
		u := ui.New()
		result, err := u.PasswordConfirm("Password to hash")
		if err != nil {
			s.p.Logger.Fatal("password required: ", err)
		}
		password = string(result.Bytes())
		defer result.Zero()
	}

	pw := security.NewPassword()
	hash, err := pw.Hash(password)
	if err != nil {
		s.p.Logger.Fatal(err)
	}

	u := ui.New()
	u.Render(func() {
		u.SecretBox("Bcrypt hash", hash)
	})
}

// Password generates a random password, hashes it, and prints both.
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
	u.Render(func() {
		u.SecretBox("Generated password", password)
		u.SecretBox("Bcrypt hash", hash)
	})
}
