package secrets

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

func TestReadPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keeper.passphrase")
	if err := os.WriteFile(path, []byte("  secret value  \r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := readPassphraseFile(path)
	if err != nil {
		t.Fatalf("readPassphraseFile: %v", err)
	}
	if got != "  secret value  " {
		t.Fatalf("got %q, want %q", got, "  secret value  ")
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPassphraseFile(path); err == nil {
			t.Fatal("expected world-readable file to be rejected")
		}
	}
}

func TestReadPassphraseFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	if _, err := readPassphraseFile(link); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
}

func TestReadPassphraseFileRejectsEmptyAndNUL(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassphraseFile(empty); err == nil {
		t.Fatal("expected empty file to be rejected")
	}

	nul := filepath.Join(dir, "nul")
	if err := os.WriteFile(nul, []byte("sec\x00ret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassphraseFile(nul); err == nil {
		t.Fatal("expected NUL byte to be rejected")
	}
}

func TestResolvePassphrasePrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keeper.passphrase")
	if err := os.WriteFile(path, []byte("file-pass"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AGBERO_KEEPER_PASSPHRASE", "canonical-env")
	t.Setenv("AGBERO_PASSPHRASE", "legacy-env")

	// Config value wins over the file and both env names.
	cfg := &alaye.Keeper{Passphrase: expect.Value("config-pass"), PassphraseFile: path}
	if got := resolvePassphrase(cfg); got != "config-pass" {
		t.Fatalf("config precedence: got %q", got)
	}

	// File wins over the env names.
	cfg = &alaye.Keeper{PassphraseFile: path}
	if got := resolvePassphrase(cfg); got != "file-pass" {
		t.Fatalf("file precedence: got %q", got)
	}

	// Canonical env wins over the deprecated alias when no file is set.
	cfg = &alaye.Keeper{}
	if got := resolvePassphrase(cfg); got != "canonical-env" {
		t.Fatalf("canonical env precedence: got %q", got)
	}
}

func TestReadPassphraseFileTooLarge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxPassphraseFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassphraseFile(path); err == nil {
		t.Fatal("expected oversized file to be rejected")
	}
}

func TestSystemdCredentialWinsOverEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keeper_passphrase"), []byte("credential-pass\n"), 0400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("AGBERO_KEEPER_PASSPHRASE", "env-pass")
	if got := resolvePassphrase(&alaye.Keeper{}); got != "credential-pass" {
		t.Fatalf("systemd credential precedence: got %q", got)
	}
}

func TestAllowLockedMissingPassphraseSource(t *testing.T) {
	dataDir := expect.NewFolder(filepath.Join(t.TempDir(), "data"))
	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     &alaye.Keeper{PassphraseFile: filepath.Join(t.TempDir(), "missing")},
		Logger:      ll.New("test").Disable(),
		AllowLocked: true,
	})
	if err != nil {
		t.Fatalf("AllowLocked should return a locked store: %v", err)
	}
	defer store.Close()
	if !store.IsLocked() {
		t.Fatal("store should be locked")
	}
}
