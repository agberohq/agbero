package tlsstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
)

func newTestDisk(t *testing.T) *Disk {
	t.Helper()
	dir := t.TempDir()
	d, err := NewDisk(DiskConfig{
		CertDir: expect.Folder(dir),
	})
	if err != nil {
		t.Fatalf("NewDisk: %v", err)
	}
	return d
}

// TestDisk_Save_RejectsTraversal verifies that Disk.Save returns an error for
// domain values that contain path traversal sequences, without writing anything
// to disk.
func TestDisk_Save_RejectsTraversal(t *testing.T) {
	d := newTestDisk(t)

	traversalDomains := []string{
		"../../etc/passwd",
		"../secret",
		"../../../../../../etc/ld",
		"foo/bar",
		"foo\\bar",
		"etc/cron.d",
	}

	certPEM := []byte("FAKE CERT")
	keyPEM := []byte("FAKE KEY")

	for _, domain := range traversalDomains {
		err := d.Save(IssuerLocal, domain, certPEM, keyPEM)
		if err == nil {
			t.Errorf("Save(%q): expected error, got nil — traversal not blocked", domain)
			continue
		}
		if !strings.Contains(err.Error(), "illegal path") {
			t.Errorf("Save(%q): got error %q but expected 'illegal path' message", domain, err)
		}
	}
}

// TestDisk_Save_AllowsLegitDomains ensures the traversal guard does not
// block legitimate hostname strings.
func TestDisk_Save_AllowsLegitDomains(t *testing.T) {
	d := newTestDisk(t)

	legit := []string{
		"localhost",
		"admin.localhost",
		"example.com",
		"foo.bar.local",
	}

	certPEM := []byte("FAKE CERT")
	keyPEM := []byte("FAKE KEY")

	for _, domain := range legit {
		if err := d.Save(IssuerLocal, domain, certPEM, keyPEM); err != nil {
			t.Errorf("Save(%q): unexpected error: %v", domain, err)
		}
	}
}

// TestDisk_Save_RejectsTraversal_NoEscape confirms nothing is written outside
// the configured cert directory when traversal domains are submitted.
func TestDisk_Save_RejectsTraversal_NoEscape(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDisk(DiskConfig{CertDir: expect.Folder(dir)})
	if err != nil {
		t.Fatalf("NewDisk: %v", err)
	}

	parent := filepath.Dir(dir)
	countBefore := countFiles(t, parent)

	_ = d.Save(IssuerLocal, "../../etc/ld", []byte("cert"), []byte("key"))
	_ = d.Save(IssuerLocal, "../secret.local", []byte("cert"), []byte("key"))

	countAfter := countFiles(t, parent)
	if countAfter != countBefore {
		t.Errorf("file count in parent changed from %d to %d — possible escape", countBefore, countAfter)
	}
}

// TestDisk_SafeName_StripsSeparators verifies the belt-and-suspenders safeName
// hardening independently of the Save guard.
func TestDisk_SafeName_StripsSeparators(t *testing.T) {
	d := &Disk{}

	cases := []struct {
		input string
		desc  string
	}{
		{"../../etc/ld", "unix traversal"},
		{"foo/bar", "forward slash"},
		{"foo\\bar", "backslash"},
		{"*.example.com", "wildcard"},
	}

	for _, c := range cases {
		got := d.safeName(c.input)
		if strings.Contains(got, "/") || strings.Contains(got, "\\") || strings.Contains(got, "..") {
			t.Errorf("safeName(%q) [%s] = %q still contains dangerous chars", c.input, c.desc, got)
		}
		if got == "." || got == ".." {
			t.Errorf("safeName(%q) [%s] = %q is a dot reference", c.input, c.desc, got)
		}
	}
}

// TestKeeperStore_Save_RejectsTraversal confirms the guard fires before any
// keeper interaction (keeper is nil; the check must run first).
func TestKeeperStore_Save_RejectsTraversal(t *testing.T) {
	s := &KeeperStore{keeper: nil}

	traversalDomains := []string{
		"../../etc/passwd",
		"../secret",
		"foo/bar",
		"foo\\bar",
	}

	for _, domain := range traversalDomains {
		err := s.Save(IssuerLocal, domain, []byte("cert"), []byte("key"))
		if err == nil {
			t.Errorf("KeeperStore.Save(%q): expected error, got nil", domain)
			continue
		}
		if !strings.Contains(err.Error(), "illegal path") {
			t.Errorf("KeeperStore.Save(%q): error %q missing 'illegal path'", domain, err)
		}
	}
}

// Helpers

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	count := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		count++
		return nil
	})
	return count
}
