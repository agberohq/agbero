package helper

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
)

func TestWriteAndRemovePIDFile(t *testing.T) {
	dir := t.TempDir()
	path, err := writePIDFile(dir)
	if err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}
	if path != filepath.Join(dir, def.DefaultPIDName) {
		t.Fatalf("path = %q", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("pid file = %q, want %d", string(data), os.Getpid())
	}

	removePIDFile(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pid file was not removed")
	}
}

func TestRemovePIDFileLeavesAnotherProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, def.DefaultPIDName)
	if err := os.WriteFile(path, []byte("999999"), def.ConfigFilePerm); err != nil {
		t.Fatal(err)
	}

	removePIDFile(path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale pid file for another process was removed: %v", err)
	}
}

func TestWritePIDFileEmptyDataDir(t *testing.T) {
	path, err := writePIDFile("")
	if err != nil {
		t.Fatalf("writePIDFile empty: %v", err)
	}
	if path != "" {
		t.Fatalf("path = %q, want empty", path)
	}
}
