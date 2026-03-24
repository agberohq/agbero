package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/olekukonko/ll"
)

func TestSystemBackupAndRestore(t *testing.T) {
	tmpDir := t.TempDir()

	hostsDir := filepath.Join(tmpDir, "hosts.d")
	certsDir := filepath.Join(tmpDir, "certs.d")
	dataDir := filepath.Join(tmpDir, "data.d")
	workDir := filepath.Join(tmpDir, "work.d")

	for _, d := range []string{hostsDir, certsDir, dataDir, workDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("failed to create mock directory %s: %v", d, err)
		}
	}

	configPath := filepath.Join(tmpDir, "agbero.hcl")
	configContent := fmt.Sprintf(`
version = 1
storage {
  hosts_dir = "%s"
  certs_dir = "%s"
  data_dir  = "%s"
  work_dir  = "%s"
}
`, filepath.ToSlash(hostsDir), filepath.ToSlash(certsDir), filepath.ToSlash(dataDir), filepath.ToSlash(workDir))

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write mock config: %v", err)
	}

	hostFilePath := filepath.Join(hostsDir, "test.hcl")
	hostContent := `
domains = ["test.local"]
route "/" {
  web { root = "." }
}
`
	if err := os.WriteFile(hostFilePath, []byte(hostContent), 0644); err != nil {
		t.Fatalf("failed to write mock host file: %v", err)
	}

	certFilePath := filepath.Join(certsDir, "test.pem")
	certContent := "-----BEGIN CERTIFICATE-----\nMOCKCERTIFICATE\n-----END CERTIFICATE-----"
	if err := os.WriteFile(certFilePath, []byte(certContent), 0644); err != nil {
		t.Fatalf("failed to write mock cert file: %v", err)
	}

	logger := ll.New("test", ll.WithFatalExits(false)).Disable()
	h := New(logger, nil, &Config{})
	sys := h.System()

	t.Run("Encrypted Backup and Restore", func(t *testing.T) {
		backupZip := filepath.Join(tmpDir, "backup_enc.zip")
		password := "super_secure_password_123"

		sys.Backup(configPath, backupZip, password)

		if _, err := os.Stat(backupZip); os.IsNotExist(err) {
			t.Fatalf("encrypted backup zip was not created at %s", backupZip)
		}

		if err := os.Remove(hostFilePath); err != nil {
			t.Fatalf("failed to simulate data loss: %v", err)
		}
		if err := os.Remove(certFilePath); err != nil {
			t.Fatalf("failed to simulate data loss: %v", err)
		}

		if _, err := os.Stat(hostFilePath); !os.IsNotExist(err) {
			t.Fatalf("host file should be deleted to simulate loss")
		}

		sys.Restore(backupZip, password, true, true)

		restoredHost, err := os.ReadFile(hostFilePath)
		if err != nil {
			t.Fatalf("failed to read restored host file: %v", err)
		}
		if string(restoredHost) != hostContent {
			t.Errorf("restored host content mismatch.\nExpected: %s\nGot: %s", hostContent, string(restoredHost))
		}

		restoredCert, err := os.ReadFile(certFilePath)
		if err != nil {
			t.Fatalf("failed to read restored cert file: %v", err)
		}
		if string(restoredCert) != certContent {
			t.Errorf("restored cert content mismatch")
		}
	})

	t.Run("Unencrypted Backup and Restore Overwrite", func(t *testing.T) {
		backupZip := filepath.Join(tmpDir, "backup_plain.zip")
		password := ""

		sys.Backup(configPath, backupZip, password)

		if _, err := os.Stat(backupZip); os.IsNotExist(err) {
			t.Fatalf("unencrypted backup zip was not created at %s", backupZip)
		}

		tamperedContent := "this file has been illegally modified"
		if err := os.WriteFile(hostFilePath, []byte(tamperedContent), 0644); err != nil {
			t.Fatalf("failed to tamper file: %v", err)
		}

		sys.Restore(backupZip, password, true, true)

		restoredHost, err := os.ReadFile(hostFilePath)
		if err != nil {
			t.Fatalf("failed to read restored host file: %v", err)
		}
		if string(restoredHost) != hostContent {
			t.Errorf("restore failed to overwrite tampered file.\nExpected: %s\nGot: %s", hostContent, string(restoredHost))
		}
	})
}
