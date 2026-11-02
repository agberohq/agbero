package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olekukonko/ll"
	"github.com/yeka/zip"
)

func TestBackupExcludesKeeperPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	hostsDir := filepath.Join(dir, "hosts.d")
	dataDir := filepath.Join(dir, "data.d")
	certsDir := filepath.Join(dir, "certs.d")
	workDir := filepath.Join(dir, "work.d")
	for _, d := range []string{hostsDir, dataDir, certsDir, workDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	configPath := filepath.Join(dir, "agbero.hcl")
	config := `version = 1
storage {
  hosts_dir = "` + filepath.ToSlash(hostsDir) + `"
  certs_dir = "` + filepath.ToSlash(certsDir) + `"
  data_dir  = "` + filepath.ToSlash(dataDir) + `"
  work_dir  = "` + filepath.ToSlash(workDir) + `"
}
security {
  keeper {
    enabled         = "on"
    passphrase_file = "` + filepath.ToSlash(filepath.Join(dir, "keeper.passphrase")) + `"
  }
}
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keeper.passphrase"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "keeper.db"), []byte("encrypted"), 0600); err != nil {
		t.Fatal(err)
	}
	host := `domains = ["test.local"]
route "/" {
  web { root = "/tmp" }
}
`
	if err := os.WriteFile(filepath.Join(hostsDir, "test.local.hcl"), []byte(host), 0600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "backup.zip")
	sys := NewSystem(SystemConfig{Logger: ll.New("backup-test").Disable()})
	if err := sys.Backup(configPath, out, "backup-password"); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	r, err := zip.OpenReader(out)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.Contains(f.Name, "keeper.passphrase") {
			t.Fatalf("backup contains the keeper passphrase file: %s", f.Name)
		}
	}
}
