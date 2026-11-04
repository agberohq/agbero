package woos

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultPathsWebDirIsNotConfigDir(t *testing.T) {
	t.Setenv("AGBERO_HOME", "")
	paths := DefaultPaths()

	if paths.WebDir.Path() == paths.BaseDir.Path() {
		t.Fatalf("web dir must not be the config dir: %q", paths.WebDir.Path())
	}
	if runtime.GOOS != "windows" {
		if want := filepath.Join("/var/www", "agbero"); paths.WebDir.Path() != want {
			t.Fatalf("web dir = %q, want %q", paths.WebDir.Path(), want)
		}
	}
}

func TestDefaultPathsCustomHomeUsesWebSubdir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGBERO_HOME", home)
	paths := DefaultPaths()

	if want := filepath.Join(home, "www"); paths.WebDir.Path() != want {
		t.Fatalf("web dir = %q, want %q", paths.WebDir.Path(), want)
	}
}

func TestGetUserDefaultsWebDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGBERO_HOME", home)
	paths, err := GetUserDefaults()
	if err != nil {
		t.Fatal(err)
	}

	if want := filepath.Join(home, "www"); paths.WebDir.Path() != want {
		t.Fatalf("web dir = %q, want %q", paths.WebDir.Path(), want)
	}
}
