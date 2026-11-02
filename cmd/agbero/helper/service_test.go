package helper

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
)

const testKeeperPassphrase = "service-preflight-test-passphrase-32!!"

func writePreflightConfig(t *testing.T, dir string) string {
	t.Helper()
	configPath := filepath.Join(dir, "agbero.hcl")
	config := `version = 1

storage {
  hosts_dir = "` + filepath.ToSlash(filepath.Join(dir, "hosts.d")) + `"
  certs_dir = "` + filepath.ToSlash(filepath.Join(dir, "certs.d")) + `"
  data_dir  = "` + filepath.ToSlash(filepath.Join(dir, "data.d")) + `"
  work_dir  = "` + filepath.ToSlash(filepath.Join(dir, "work.d")) + `"
}

security {
  keeper {
    enabled    = "on"
    passphrase = "` + testKeeperPassphrase + `"
  }
}
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func createPreflightKeeper(t *testing.T, dir string, withInternal, withJWT bool) {
	t.Helper()
	store, err := secrets.Open(secrets.Config{
		DataDir: expect.NewFolder(filepath.Join(dir, "data.d")),
		Setting: &alaye.Keeper{
			Enabled:    expect.Active,
			Passphrase: expect.Value(testKeeperPassphrase),
		},
		Logger:      ll.New("preflight-test").Disable(),
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("open keeper: %v", err)
	}
	defer store.Close()

	for _, ns := range expect.VaultBuckets {
		if err := store.CreateBucket("vault", ns, keeper.LevelPasswordOnly, "preflight-test"); err != nil {
			t.Fatalf("create vault:%s bucket: %v", ns, err)
		}
	}

	if withInternal {
		if err := store.Set(expect.Vault().Key("internal"), []byte("ppk")); err != nil {
			t.Fatalf("set internal key: %v", err)
		}
	}
	if withJWT {
		if err := store.Set(expect.Vault().AdminJWT("admin"), []byte("jwt-secret")); err != nil {
			t.Fatalf("set admin JWT: %v", err)
		}
	}
}

func TestServicePreflightAcceptsCanonicalKeeperKeys(t *testing.T) {
	dir := t.TempDir()
	configPath := writePreflightConfig(t, dir)
	createPreflightKeeper(t, dir, true, true)

	svc := &Service{p: &Helper{Logger: ll.New("preflight-test").Disable()}}
	if err := svc.preflightCheck(configPath); err != nil {
		t.Fatalf("preflightCheck: %v", err)
	}
}

func TestServicePreflightReportsMissingInternalKey(t *testing.T) {
	dir := t.TempDir()
	configPath := writePreflightConfig(t, dir)
	createPreflightKeeper(t, dir, false, true)

	svc := &Service{p: &Helper{Logger: ll.New("preflight-test").Disable()}}
	err := svc.preflightCheck(configPath)
	if err == nil || !strings.Contains(err.Error(), "vault:key/internal") {
		t.Fatalf("error = %v, want missing internal key", err)
	}
}

func TestServicePreflightReportsMissingJWT(t *testing.T) {
	dir := t.TempDir()
	configPath := writePreflightConfig(t, dir)
	createPreflightKeeper(t, dir, true, false)

	svc := &Service{p: &Helper{Logger: ll.New("preflight-test").Disable()}}
	err := svc.preflightCheck(configPath)
	if err == nil || !strings.Contains(err.Error(), "vault:admin/jwt") {
		t.Fatalf("error = %v, want missing admin JWT", err)
	}
}

func writePreflightConfigWithPassphraseFile(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	passFile := filepath.Join(dir, "keeper.passphrase")
	if err := os.WriteFile(passFile, []byte(testKeeperPassphrase), mode); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "agbero.hcl")
	config := `version = 1

storage {
  hosts_dir = "` + filepath.ToSlash(filepath.Join(dir, "hosts.d")) + `"
  certs_dir = "` + filepath.ToSlash(filepath.Join(dir, "certs.d")) + `"
  data_dir  = "` + filepath.ToSlash(filepath.Join(dir, "data.d")) + `"
  work_dir  = "` + filepath.ToSlash(filepath.Join(dir, "work.d")) + `"
}

security {
  keeper {
    enabled         = "on"
    passphrase_file = "` + filepath.ToSlash(passFile) + `"
  }
}
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestServicePreflightAcceptsPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	configPath := writePreflightConfigWithPassphraseFile(t, dir, 0600)
	createPreflightKeeper(t, dir, true, true)

	svc := &Service{p: &Helper{Logger: ll.New("preflight-test").Disable()}}
	if err := svc.preflightCheck(configPath); err != nil {
		t.Fatalf("preflightCheck: %v", err)
	}
}

func TestServicePreflightRejectsInsecurePassphraseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dir := t.TempDir()
	configPath := writePreflightConfigWithPassphraseFile(t, dir, 0644)
	createPreflightKeeper(t, dir, true, true)

	svc := &Service{p: &Helper{Logger: ll.New("preflight-test").Disable()}}
	err := svc.preflightCheck(configPath)
	if err == nil || !strings.Contains(err.Error(), "accessible by other users") {
		t.Fatalf("error = %v, want insecure mode rejection", err)
	}
}
