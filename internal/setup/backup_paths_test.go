package setup

import (
	"path/filepath"
	"testing"
)

func TestKeeperPassphrasePathsExcludesDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agbero.hcl")

	paths := keeperPassphrasePaths(configPath, "")
	want := filepath.Join(dir, "keeper.passphrase")
	if !paths[want] {
		t.Fatalf("default passphrase path %q not excluded: %#v", want, paths)
	}
}

func TestKeeperPassphrasePathsExcludesConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agbero.hcl")
	custom := filepath.Join(dir, "secrets", "keeper.pass")

	paths := keeperPassphrasePaths(configPath, custom)
	if !paths[custom] {
		t.Fatalf("configured passphrase path %q not excluded: %#v", custom, paths)
	}
	if !paths[filepath.Join(dir, "keeper.passphrase")] {
		t.Fatal("default passphrase path should also be excluded")
	}
}

func TestKeeperPassphrasePathsEmptyConfig(t *testing.T) {
	paths := keeperPassphrasePaths("", "")
	if len(paths) != 1 {
		t.Fatalf("expected exactly the default path, got %#v", paths)
	}
}
