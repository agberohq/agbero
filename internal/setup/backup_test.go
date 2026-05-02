package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/olekukonko/ll"
	"github.com/yeka/zip"
)

// newTestSystem returns a System with fatal exits disabled.
func newTestSystem(t *testing.T) *System {
	t.Helper()
	logger := ll.New("test", ll.WithFatalExits(false)).Disable()
	return NewSystem(SystemConfig{Logger: logger})
}

// writeTestZip creates a valid backup archive at path.
// When password is non-empty entries are AES-256 encrypted.
// When skipSig is true the signature entry is omitted (used to test sig-missing rejection).
func writeTestZip(t *testing.T, path, password string, files map[string]string, skipSig bool) BackupManifest {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("writeTestZip create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	ts := time.Now()
	manifest := BackupManifest{
		Version:   1,
		Timestamp: ts,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	idx := 0
	for orig, content := range files {
		archivePath := fmt.Sprintf("files/%d", idx)
		idx++

		h := sha256.Sum256([]byte(content))
		manifest.Files = append(manifest.Files, BackupEntry{
			OriginalPath: orig,
			ArchivePath:  archivePath,
			SHA256:       hex.EncodeToString(h[:]),
			Size:         int64(len(content)),
			Mode:         def.ConfigFilePerm,
		})

		var (
			w    io.Writer
			werr error
		)
		if password != "" {
			w, werr = zw.Encrypt(archivePath, password, zip.AES256Encryption)
		} else {
			w, werr = zw.Create(archivePath)
		}
		if werr != nil {
			t.Fatalf("writeTestZip entry create: %v", werr)
		}
		if _, err := fmt.Fprint(w, content); err != nil {
			t.Fatalf("writeTestZip entry write: %v", err)
		}
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("writeTestZip marshal: %v", err)
	}

	var (
		mw    io.Writer
		mwerr error
	)
	if password != "" {
		mw, mwerr = zw.Encrypt("agbero.manifest.json", password, zip.AES256Encryption)
	} else {
		mw, mwerr = zw.Create("agbero.manifest.json")
	}
	if mwerr != nil {
		t.Fatalf("writeTestZip manifest entry: %v", mwerr)
	}
	if _, err := mw.Write(manifestBytes); err != nil {
		t.Fatalf("writeTestZip manifest write: %v", err)
	}

	if !skipSig {
		sig := computeManifestHMAC(manifestBytes, password, ts)
		var (
			sw    io.Writer
			swerr error
		)
		if password != "" {
			sw, swerr = zw.Encrypt("agbero.manifest.sig", password, zip.AES256Encryption)
		} else {
			sw, swerr = zw.Create("agbero.manifest.sig")
		}
		if swerr != nil {
			t.Fatalf("writeTestZip sig entry: %v", swerr)
		}
		if _, err := fmt.Fprint(sw, sig); err != nil {
			t.Fatalf("writeTestZip sig write: %v", err)
		}
	}

	return manifest
}

// sha256Hex returns the hex-encoded SHA-256 digest of b.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// isSafeRestorePath

func TestIsSafeRestorePath_allow(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "hosts.d", "example.hcl")
	if err := isSafeRestorePath(target, []string{filepath.Join(root, "hosts.d")}); err != nil {
		t.Errorf("expected allowed path to pass: %v", err)
	}
}

func TestIsSafeRestorePath_escape(t *testing.T) {
	root := t.TempDir()
	probe := filepath.Join(t.TempDir(), "agbero_zipslip_probe")
	if err := isSafeRestorePath(probe, []string{filepath.Join(root, "hosts.d")}); err == nil {
		t.Error("path outside allowed roots must be rejected")
	}
}

func TestIsSafeRestorePath_dotdot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "hosts.d", "..", "..", "etc", "cron.d", "pwned")
	if err := isSafeRestorePath(target, []string{filepath.Join(root, "hosts.d")}); err == nil {
		t.Error("dot-dot traversal must be rejected")
	}
}

func TestIsSafeRestorePath_multipleRoots(t *testing.T) {
	root1 := t.TempDir()
	root2 := t.TempDir()
	target := filepath.Join(root2, "certs.d", "cert.pem")
	if err := isSafeRestorePath(target, []string{root1, root2}); err != nil {
		t.Errorf("path under second root should be allowed: %v", err)
	}
}

// computeManifestHMAC

func TestComputeManifestHMAC_deterministic(t *testing.T) {
	data := []byte(`{"version":1}`)
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if a, b := computeManifestHMAC(data, "secret", ts), computeManifestHMAC(data, "secret", ts); a != b {
		t.Error("HMAC must be deterministic for identical inputs")
	}
}

func TestComputeManifestHMAC_differentPasswords(t *testing.T) {
	data := []byte(`{"version":1}`)
	ts := time.Now()
	if computeManifestHMAC(data, "a", ts) == computeManifestHMAC(data, "b", ts) {
		t.Error("different passwords must produce different HMACs")
	}
}

// TestComputeManifestHMAC_noPasswordIsMachineBound verifies that the passwordless
// HMAC is stable across calls on the same machine (hostname-derived key).
// The old test asserted different timestamps produce different HMACs, but that
// was testing the vulnerability: the attacker-controlled timestamp was the key.
// The new key is hostname-derived, so the same machine always produces the same
// HMAC for the same manifest bytes regardless of timestamp.
func TestComputeManifestHMAC_noPasswordIsMachineBound(t *testing.T) {
	data := []byte(`{"version":1}`)
	ts1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ts2 := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	// Same manifest bytes, same machine — must produce the same HMAC regardless of ts.
	if computeManifestHMAC(data, "", ts1) != computeManifestHMAC(data, "", ts2) {
		t.Error("passwordless HMAC must be machine-bound and stable across timestamps")
	}
	// Different manifest bytes — must produce different HMACs.
	data2 := []byte(`{"version":2}`)
	if computeManifestHMAC(data, "", ts1) == computeManifestHMAC(data2, "", ts1) {
		t.Error("different manifest bytes must produce different HMACs")
	}
}

// buildAllowedRoots

func TestBuildAllowedRoots_deduplicates(t *testing.T) {
	root := t.TempDir()
	entries := []BackupEntry{
		{OriginalPath: filepath.Join(root, "hosts.d", "a.hcl")},
		{OriginalPath: filepath.Join(root, "hosts.d", "b.hcl")},
		{OriginalPath: filepath.Join(root, "certs.d", "cert.pem")},
	}
	roots := buildAllowedRoots(entries)
	if len(roots) != 2 {
		t.Errorf("expected 2 unique roots, got %d", len(roots))
	}
}

// Restore — missing signature (SEC-08a)

func TestRestore_MissingSig(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)
	target := filepath.Join(hostsDir, "x.hcl")

	zipPath := filepath.Join(tmpDir, "nosig.zip")
	writeTestZip(t, zipPath, "", map[string]string{target: "content"}, true /* skipSig */)

	err := newTestSystem(t).Restore(zipPath, "", "", true, true)
	if err == nil {
		t.Fatal("missing sig must return an error")
	}
	if !strings.Contains(err.Error(), "agbero.manifest.sig not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Restore — ZipSlip (SEC-01)

func TestRestore_ZipSlip_archivePath(t *testing.T) {
	tmpDir := t.TempDir()

	ts := time.Now()
	legit := filepath.Join(tmpDir, "hosts.d", "x.hcl")
	h := sha256.Sum256([]byte("content"))
	manifest := BackupManifest{
		Version:   1,
		Timestamp: ts,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Files: []BackupEntry{{
			OriginalPath: legit,
			ArchivePath:  "../../../etc/evil",
			SHA256:       hex.EncodeToString(h[:]),
			Size:         7,
			Mode:         def.ConfigFilePerm,
		}},
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	zipPath := filepath.Join(tmpDir, "evil.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	mw, _ := zw.Create("agbero.manifest.json")
	mw.Write(manifestBytes)
	sw, _ := zw.Create("agbero.manifest.sig")
	fmt.Fprint(sw, computeManifestHMAC(manifestBytes, "", ts))
	zw.Close()
	f.Close()

	err := newTestSystem(t).Restore(zipPath, "", "", true, true)
	if err == nil {
		t.Error("ZipSlip via archive path must return an error")
		return
	}
	if !strings.Contains(err.Error(), "suspicious archive path") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRestore_ZipSlip_originalPath(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)

	legitFile := filepath.Join(hostsDir, "real.hcl")
	_ = os.WriteFile(legitFile, []byte("real"), def.ConfigFilePerm)

	siblingDir := t.TempDir()
	probe := filepath.Join(siblingDir, "agbero_zipslip_probe_test")
	_ = os.Remove(probe)

	ts := time.Now()
	h := sha256.Sum256([]byte("pwned"))

	// Sign only the legit manifest — adding the evil entry tampers the bytes.
	legitManifest := BackupManifest{
		Version: 1, Timestamp: ts, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Files: []BackupEntry{{
			OriginalPath: legitFile, ArchivePath: "files/0",
			SHA256: sha256Hex([]byte("real")), Size: 4, Mode: def.ConfigFilePerm,
		}},
	}
	legitBytes, _ := json.MarshalIndent(legitManifest, "", "  ")
	sig := computeManifestHMAC(legitBytes, "", ts)

	// Tamper by adding the evil entry after signing.
	tamperedManifest := legitManifest
	tamperedManifest.Files = append(tamperedManifest.Files, BackupEntry{
		OriginalPath: probe, ArchivePath: "files/1",
		SHA256: hex.EncodeToString(h[:]), Size: 5, Mode: def.ConfigFilePerm,
	})
	tamperedBytes, _ := json.MarshalIndent(tamperedManifest, "", "  ")

	zipPath := filepath.Join(tmpDir, "evil.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	ew0, _ := zw.Create("files/0")
	fmt.Fprint(ew0, "real")
	ew1, _ := zw.Create("files/1")
	fmt.Fprint(ew1, "pwned")
	mw, _ := zw.Create("agbero.manifest.json")
	mw.Write(tamperedBytes)
	sw, _ := zw.Create("agbero.manifest.sig")
	fmt.Fprint(sw, sig) // sig computed before tampering — mismatch
	zw.Close()
	f.Close()

	t.Cleanup(func() { os.Remove(probe) })

	err := newTestSystem(t).Restore(zipPath, "", "", true, true)
	if err == nil {
		t.Error("tampered manifest must return an error")
		return
	}
	isHMAC := strings.Contains(err.Error(), "signature verification failed")
	isPath := strings.Contains(err.Error(), "path containment violation")
	if !isHMAC && !isPath {
		t.Errorf("unexpected error (expected HMAC or path violation): %v", err)
	}
	if _, statErr := os.Stat(probe); statErr == nil {
		t.Error("probe file must not exist after rejection")
	}
}

// Restore — manifest HMAC

func TestRestore_TamperedSignature(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)
	target := filepath.Join(hostsDir, "x.hcl")

	ts := time.Now()
	h := sha256.Sum256([]byte("real content"))
	manifest := BackupManifest{
		Version: 1, Timestamp: ts, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Files: []BackupEntry{{
			OriginalPath: target, ArchivePath: "files/0",
			SHA256: hex.EncodeToString(h[:]), Size: 12, Mode: def.ConfigFilePerm,
		}},
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	zipPath := filepath.Join(tmpDir, "tampered.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	ew, _ := zw.Create("files/0")
	fmt.Fprint(ew, "real content")
	mw, _ := zw.Create("agbero.manifest.json")
	mw.Write(manifestBytes)
	sw, _ := zw.Create("agbero.manifest.sig")
	fmt.Fprint(sw, "deadbeefdeadbeef")
	zw.Close()
	f.Close()

	err := newTestSystem(t).Restore(zipPath, "", "", true, true)
	if err == nil {
		t.Error("tampered signature must return an error")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Error("target file must not exist after signature rejection")
	}
}

// Restore — encrypted round-trip

func TestRestore_EncryptedRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)

	target := filepath.Join(hostsDir, "test.hcl")
	content := `domains = ["test.local"]`
	_ = os.WriteFile(target, []byte(content), def.ConfigFilePerm)

	zipPath := filepath.Join(tmpDir, "backup_enc.zip")
	writeTestZip(t, zipPath, "super_secure_password_123", map[string]string{target: content}, false)
	_ = os.Remove(target)

	if err := newTestSystem(t).Restore(zipPath, "", "super_secure_password_123", true, true); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("restored file not found: %v", err)
	}
	if string(got) != content {
		t.Errorf("content mismatch: got %q", string(got))
	}
}

func TestRestore_WrongPassword(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)
	target := filepath.Join(hostsDir, "test.hcl")

	zipPath := filepath.Join(tmpDir, "backup_enc.zip")
	writeTestZip(t, zipPath, "correct", map[string]string{target: "hello"}, false)

	err := newTestSystem(t).Restore(zipPath, "", "wrong", true, true)
	if err == nil {
		t.Error("wrong password must return an error")
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Error("file must not be written with wrong password")
	}
}

// Restore — hash mismatch (corrupt archive)

func TestRestore_HashMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)
	target := filepath.Join(hostsDir, "test.hcl")

	ts := time.Now()
	manifest := BackupManifest{
		Version: 1, Timestamp: ts, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Files: []BackupEntry{{
			OriginalPath: target, ArchivePath: "files/0",
			SHA256: strings.Repeat("0", 64), Size: 7, Mode: def.ConfigFilePerm,
		}},
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	zipPath := filepath.Join(tmpDir, "corrupt.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	ew, _ := zw.Create("files/0")
	fmt.Fprint(ew, "content")
	mw, _ := zw.Create("agbero.manifest.json")
	mw.Write(manifestBytes)
	sw, _ := zw.Create("agbero.manifest.sig")
	fmt.Fprint(sw, computeManifestHMAC(manifestBytes, "", ts))
	zw.Close()
	f.Close()

	err := newTestSystem(t).Restore(zipPath, "", "", true, true)
	if err == nil {
		t.Error("hash mismatch must return an error")
	}
	if !strings.Contains(err.Error(), "CORRUPTION") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Error("corrupt file must not be written")
	}
}

// Restore — overwrite tampered file

func TestRestore_OverwriteTamperedFile(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)
	target := filepath.Join(hostsDir, "test.hcl")
	original := "original content"

	zipPath := filepath.Join(tmpDir, "backup.zip")
	writeTestZip(t, zipPath, "", map[string]string{target: original}, false)
	_ = os.WriteFile(target, []byte("tampered"), def.ConfigFilePerm)

	if err := newTestSystem(t).Restore(zipPath, "", "", true, true); err != nil {
		t.Fatalf("restore failed: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("file not found after restore: %v", err)
	}
	if string(got) != original {
		t.Errorf("tampered file not overwritten: got %q", string(got))
	}
}
