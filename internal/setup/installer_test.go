package setup

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoInstaller(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("installer not found: %v", err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar not available")
	}
	return path
}

func makeInstallerAssets(t *testing.T) (dir, archiveName string) {
	t.Helper()
	dir = t.TempDir()
	stage := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stage, 0755); err != nil {
		t.Fatal(err)
	}

	// The check/install paths only require an executable that reports a
	// version; a shell script is enough and keeps the test platform-neutral.
	fake := filepath.Join(stage, "agbero")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'Version: 0.0.0'\n"), 0755); err != nil {
		t.Fatal(err)
	}

	archiveName = fmt.Sprintf("agbero-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	archive := filepath.Join(dir, archiveName)
	out, err := exec.Command("tar", "-czf", archive, "-C", stage, "agbero").CombinedOutput()
	if err != nil {
		t.Fatalf("tar: %v: %s", err, out)
	}

	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	checksums := fmt.Sprintf("%x  %s\n", sum, archiveName)
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(checksums), 0644); err != nil {
		t.Fatal(err)
	}
	return dir, archiveName
}

func TestInstallerCheckFromFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is POSIX-only")
	}
	script := repoInstaller(t)
	dir, _ := makeInstallerAssets(t)

	cmd := exec.Command("bash", script,
		"--from-file", dir,
		"--version", "v0.0.0",
		"--check",
		"--no-color",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installer --check failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Verified") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestInstallerRejectsChecksumMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is POSIX-only")
	}
	script := repoInstaller(t)
	dir, name := makeInstallerAssets(t)
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  "+name+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", script,
		"--from-file", dir,
		"--version", "v0.0.0",
		"--check",
		"--no-color",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("installer accepted a bad checksum:\n%s", out)
	}
	if !strings.Contains(string(out), "checksum mismatch") {
		t.Fatalf("unexpected error:\n%s", out)
	}
}

func TestInstallerRejectsSymlinkArchive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is POSIX-only")
	}
	script := repoInstaller(t)

	dir := t.TempDir()
	stage := filepath.Join(dir, "stage")
	if err := os.MkdirAll(stage, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(stage, "agbero")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	name := fmt.Sprintf("agbero-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	archive := filepath.Join(dir, name)
	if out, err := exec.Command("tar", "-czf", archive, "-C", stage, "agbero").CombinedOutput(); err != nil {
		t.Fatalf("tar: %v: %s", err, out)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	checksums := fmt.Sprintf("%x  %s\n", sum, name)
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(checksums), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", script,
		"--from-file", dir,
		"--version", "v0.0.0",
		"--check",
		"--no-color",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("installer accepted a symlink archive:\n%s", out)
	}
	if !strings.Contains(string(out), "symlink") {
		t.Fatalf("unexpected error:\n%s", out)
	}
}

func TestInstallerNormalizesVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is POSIX-only")
	}
	script := repoInstaller(t)

	cmd := exec.Command("bash", script,
		"--version", "0.0.0",
		"--dry-run",
		"--no-color",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installer --dry-run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "v0.0.0") {
		t.Fatalf("version was not normalized:\n%s", out)
	}
}

func TestInstallerInstallAndUninstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install.sh is POSIX-only")
	}
	script := repoInstaller(t)
	dir, _ := makeInstallerAssets(t)
	binDir := t.TempDir()
	target := filepath.Join(binDir, "agbero")

	cmd := exec.Command("bash", script,
		"--from-file", dir,
		"--version", "v0.0.0",
		"--dir", binDir,
		"--no-color",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("installer install failed: %v\n%s", err, out)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("installed binary missing: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Fatalf("installed binary is not executable: %v", info.Mode())
	}

	cmd = exec.Command("bash", script, "--uninstall", "--dir", binDir, "--yes", "--no-color")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("installer uninstall failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("uninstall did not remove the binary")
	}
}
