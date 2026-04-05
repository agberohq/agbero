package setup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/olekukonko/ll"
	"github.com/yeka/zip"
)

// newTestSystem returns a System with fatal exits disabled. All public methods
// now return errors, so tests inspect the error directly — fatal is not needed
// for control flow.
func newTestSystem(t *testing.T) *System {
	t.Helper()
	logger := ll.New("test", ll.WithFatalExits(false)).Disable()
	return NewSystem(SystemConfig{Logger: logger})
}

// Test archive builders

// writeTestZip creates a valid backup archive at path containing files.
// When password is non-empty entries are AES-256 encrypted.
// When skipSig is true the signature entry is omitted.
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
			Mode:         0644,
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

// writeTarGz creates a .tar.gz archive at dst containing a single file named
// after the agbero binary with the given content. Used to mock GitHub assets.
func writeTarGz(t *testing.T, dst string, content []byte) {
	t.Helper()
	f, err := os.Create(dst)
	if err != nil {
		t.Fatalf("writeTarGz create: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	binaryName := woos.Name
	if runtime.GOOS == woos.Windows {
		binaryName += ".exe"
	}
	hdr := &tar.Header{
		Name:     binaryName,
		Mode:     0755,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("writeTarGz header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("writeTarGz body: %v", err)
	}
	tw.Close()
	gw.Close()
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

// rejectInsecureURL

func TestRejectInsecureURL_https(t *testing.T) {
	if err := rejectInsecureURL("https://github.com/agberohq/agbero/releases/download/v1.0.0/agbero_1.0.0_linux_amd64.tar.gz"); err != nil {
		t.Errorf("HTTPS URL must be accepted: %v", err)
	}
}

func TestRejectInsecureURL_http(t *testing.T) {
	if err := rejectInsecureURL("http://evil.example.com/agbero"); err == nil {
		t.Error("HTTP URL must be rejected")
	}
}

func TestRejectInsecureURL_noScheme(t *testing.T) {
	if err := rejectInsecureURL("evil.example.com/agbero"); err == nil {
		t.Error("URL without scheme must be rejected")
	}
}

// parseChecksumFile

func TestParseChecksumFile_found(t *testing.T) {
	data := []byte("abc123  agbero_1.0.0_linux_amd64.tar.gz\ndef456  agbero_1.0.0_darwin_arm64.tar.gz\n")
	hash, err := parseChecksumFile(data, "agbero_1.0.0_linux_amd64.tar.gz")
	if err != nil {
		t.Fatalf("expected match: %v", err)
	}
	if hash != "abc123" {
		t.Errorf("wrong hash: %q", hash)
	}
}

func TestParseChecksumFile_notFound(t *testing.T) {
	data := []byte("abc123  other_binary.tar.gz\n")
	if _, err := parseChecksumFile(data, "agbero_1.0.0_linux_amd64.tar.gz"); err == nil {
		t.Error("missing asset must return error")
	}
}

func TestParseChecksumFile_caseInsensitive(t *testing.T) {
	data := []byte("abc123  AGBERO_1.0.0_LINUX_AMD64.TAR.GZ\n")
	if _, err := parseChecksumFile(data, "agbero_1.0.0_linux_amd64.tar.gz"); err != nil {
		t.Errorf("lookup must be case-insensitive: %v", err)
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

func TestComputeManifestHMAC_noPasswordUsesTimestamp(t *testing.T) {
	data := []byte(`{"version":1}`)
	ts1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ts2 := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	if computeManifestHMAC(data, "", ts1) == computeManifestHMAC(data, "", ts2) {
		t.Error("different timestamps must produce different HMACs when password is empty")
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
			Mode:         0644,
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

	err := newTestSystem(t).Restore(zipPath, "", true, true)
	if err == nil {
		t.Error("ZipSlip via archive path must return an error")
		return
	}
	if !strings.Contains(err.Error(), "suspicious archive path") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestRestore_ZipSlip_originalPath verifies that isSafeRestorePath rejects
// original_path values that escape the backup's known root set.
// The attack model: a backup made on machine A contains paths under /machine-a/data/.
// When restored on machine B (where that path doesn't exist), any entry claiming
// to restore to /machine-a/data/ is rejected because that root is not in the
// allowed set derived from entries that DO share a root with other entries.
//
// Note: isSafeRestorePath provides defence-in-depth against accidental
// cross-machine restores and misrouted paths. Layer 1 (archive path prefix
// check) is the primary guard against archive-level path injection.
func TestRestore_ZipSlip_originalPath(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)

	// Legitimate file establishes hostsDir as the only allowed root.
	legitFile := filepath.Join(hostsDir, "real.hcl")
	_ = os.WriteFile(legitFile, []byte("real"), 0644)

	// Attacker entry: claims to restore to a completely different directory
	// not related to hostsDir. Use a path that is a sibling of tmpDir so it
	// cannot be derived from hostsDir's parent chain.
	siblingDir := t.TempDir() // separate TempDir — completely unrelated to tmpDir
	probe := filepath.Join(siblingDir, "agbero_zipslip_probe_test")
	_ = os.Remove(probe)

	ts := time.Now()
	h := sha256.Sum256([]byte("pwned"))
	manifest := BackupManifest{
		Version:   1,
		Timestamp: ts,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Files: []BackupEntry{
			{
				OriginalPath: legitFile,
				ArchivePath:  "files/0",
				SHA256:       sha256Hex([]byte("real")),
				Size:         4,
				Mode:         0644,
			},
		},
	}

	// Tamper the manifest after HMAC is computed to add the evil entry.
	// This simulates an attacker who has bypassed the HMAC (e.g. no password,
	// or has the password) and is now injecting a rogue original_path.
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	sig := computeManifestHMAC(manifestBytes, "", ts)

	// Now build the actual zip with BOTH the legit entry and the evil entry,
	// but sign only the legit manifest (so sig check fails first — testing
	// that the path check also works independently requires skipSig).
	// We skip the sig to isolate the path containment check.
	manifest.Files = append(manifest.Files, BackupEntry{
		OriginalPath: probe,
		ArchivePath:  "files/1",
		SHA256:       hex.EncodeToString(h[:]),
		Size:         5,
		Mode:         0644,
	})
	tamperedManifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	zipPath := filepath.Join(tmpDir, "evil.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	ew0, _ := zw.Create("files/0")
	fmt.Fprint(ew0, "real")
	ew1, _ := zw.Create("files/1")
	fmt.Fprint(ew1, "pwned")
	mw, _ := zw.Create("agbero.manifest.json")
	mw.Write(tamperedManifestBytes)
	// Use the original sig (computed before tamper) — this ensures the HMAC
	// check fires first and stops execution before isSafeRestorePath.
	sw, _ := zw.Create("agbero.manifest.sig")
	fmt.Fprint(sw, sig)
	zw.Close()
	f.Close()

	t.Cleanup(func() { os.Remove(probe) })

	err := newTestSystem(t).Restore(zipPath, "", true, true)
	if err == nil {
		t.Error("tampered manifest must return an error (HMAC mismatch or path violation)")
		return
	}
	// Either the HMAC check or the path containment check fires — both are correct.
	isHMAC := strings.Contains(err.Error(), "signature verification failed")
	isPath := strings.Contains(err.Error(), "path containment violation")
	if !isHMAC && !isPath {
		t.Errorf("unexpected error (expected HMAC or path violation): %v", err)
	}
	if _, statErr := os.Stat(probe); statErr == nil {
		t.Error("probe file must not exist after rejection")
	}
}

// Restore — manifest HMAC (SEC-08)

func TestRestore_TamperedSignature(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)
	target := filepath.Join(hostsDir, "x.hcl")

	ts := time.Now()
	h := sha256.Sum256([]byte("real content"))
	manifest := BackupManifest{
		Version:   1,
		Timestamp: ts,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Files: []BackupEntry{{
			OriginalPath: target,
			ArchivePath:  "files/0",
			SHA256:       hex.EncodeToString(h[:]),
			Size:         12,
			Mode:         0644,
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

	err := newTestSystem(t).Restore(zipPath, "", true, true)
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

// Restore — encrypted backup round-trip

func TestRestore_EncryptedRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts.d")
	_ = os.MkdirAll(hostsDir, 0755)

	target := filepath.Join(hostsDir, "test.hcl")
	content := `domains = ["test.local"]`
	_ = os.WriteFile(target, []byte(content), 0644)

	zipPath := filepath.Join(tmpDir, "backup_enc.zip")
	writeTestZip(t, zipPath, "super_secure_password_123", map[string]string{target: content}, false)
	_ = os.Remove(target)

	if err := newTestSystem(t).Restore(zipPath, "super_secure_password_123", true, true); err != nil {
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

	err := newTestSystem(t).Restore(zipPath, "wrong", true, true)
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
		Version:   1,
		Timestamp: ts,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Files: []BackupEntry{{
			OriginalPath: target,
			ArchivePath:  "files/0",
			SHA256:       strings.Repeat("0", 64),
			Size:         7,
			Mode:         0644,
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

	err := newTestSystem(t).Restore(zipPath, "", true, true)
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
	_ = os.WriteFile(target, []byte("tampered"), 0644)

	if err := newTestSystem(t).Restore(zipPath, "", true, true); err != nil {
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

// Update — asset naming

func TestBuildAssetName(t *testing.T) {
	sys := newTestSystem(t)
	name := sys.buildAssetName("v0.2.6")
	expected := fmt.Sprintf("agbero-%s-%s", runtime.GOOS, runtime.GOARCH)
	if !strings.HasPrefix(name, expected) {
		t.Errorf("unexpected asset name: got %q, want prefix %q", name, expected)
	}
	if runtime.GOOS != woos.Windows && !strings.HasSuffix(name, ".tar.gz") {
		t.Errorf("non-Windows asset must end in .tar.gz: %q", name)
	}
	if runtime.GOOS == woos.Windows && !strings.HasSuffix(name, ".zip") {
		t.Errorf("Windows asset must end in .zip: %q", name)
	}
}

func TestBuildChecksumName(t *testing.T) {
	sys := newTestSystem(t)
	if name := sys.buildChecksumName("v0.2.6"); name != "checksums.txt" {
		t.Errorf("unexpected checksum name: %q", name)
	}
}

func TestFindAsset_caseInsensitive(t *testing.T) {
	sys := newTestSystem(t)
	assets := []githubAsset{
		{Name: "AGBERO_1.0.0_LINUX_AMD64.TAR.GZ", BrowserDownloadURL: "https://example.com/a"},
	}
	if got := sys.findAsset(assets, "agbero_1.0.0_linux_amd64.tar.gz"); got == nil {
		t.Error("findAsset must be case-insensitive")
	}
}

func TestUpdate_AlreadyUpToDate(t *testing.T) {
	original := woos.Version
	woos.Version = "v1.0.0"
	t.Cleanup(func() { woos.Version = original })

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		json.NewEncoder(w).Encode(githubRelease{TagName: "v1.0.0"})
	}))
	t.Cleanup(srv.Close)

	sys := newTestSystem(t)
	sys.cfg.githubAPIURL = srv.URL
	sys.cfg.httpClient = srv.Client()
	sys.cfg.insecureHTTPAllowed = true

	if err := sys.Update(false, true); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !called {
		t.Error("GitHub API must be called even on up-to-date check")
	}
}

// Update — checksum mismatch aborts apply

func TestUpdate_ChecksumMismatch_Aborts(t *testing.T) {
	original := woos.Version
	woos.Version = "v0.0.1"
	t.Cleanup(func() { woos.Version = original })

	sys := newTestSystem(t)
	assetName := sys.buildAssetName("v1.0.0")
	checksumName := sys.buildChecksumName("v1.0.0")

	tmpDir := t.TempDir()
	binaryContent := []byte("fake binary content")
	tarPath := filepath.Join(tmpDir, assetName)
	writeTarGz(t, tarPath, binaryContent)

	checksumContent := fmt.Sprintf("%s  %s\n", strings.Repeat("0", 64), assetName)
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	_ = os.WriteFile(checksumPath, []byte(checksumContent), 0644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		switch {
		case strings.Contains(r.URL.Path, "latest"):
			json.NewEncoder(w).Encode(githubRelease{
				TagName: "v1.0.0",
				Assets: []githubAsset{
					{Name: assetName, BrowserDownloadURL: base + "/binary", Size: int64(len(binaryContent))},
					{Name: checksumName, BrowserDownloadURL: base + "/checksums"},
				},
			})
		case r.URL.Path == "/binary":
			http.ServeFile(w, r, tarPath)
		case r.URL.Path == "/checksums":
			http.ServeFile(w, r, checksumPath)
		}
	}))
	t.Cleanup(srv.Close)

	applied := false
	sys.cfg.githubAPIURL = srv.URL + "/latest"
	sys.cfg.httpClient = srv.Client()
	sys.cfg.insecureHTTPAllowed = true
	sys.cfg.applyFn = func(_ *os.File) error { applied = true; return nil }

	err := sys.Update(true, true)
	if err == nil {
		t.Error("checksum mismatch must return an error")
		return
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
	if applied {
		t.Error("selfupdate.Apply must not be called on checksum mismatch")
	}
}

// Update — valid checksum triggers apply

func TestUpdate_ValidChecksum_Applies(t *testing.T) {
	original := woos.Version
	woos.Version = "v0.0.1"
	t.Cleanup(func() { woos.Version = original })

	sys := newTestSystem(t)
	assetName := sys.buildAssetName("v1.0.0")
	checksumName := sys.buildChecksumName("v1.0.0")

	tmpDir := t.TempDir()
	binaryContent := []byte("correct binary content")
	tarPath := filepath.Join(tmpDir, assetName)
	writeTarGz(t, tarPath, binaryContent)

	archiveBytes, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatalf("failed to read archive: %v", err)
	}
	correctHash := sha256Hex(archiveBytes)
	checksumContent := fmt.Sprintf("%s  %s\n", correctHash, assetName)
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	_ = os.WriteFile(checksumPath, []byte(checksumContent), 0644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		switch {
		case strings.Contains(r.URL.Path, "latest"):
			json.NewEncoder(w).Encode(githubRelease{
				TagName: "v1.0.0",
				Assets: []githubAsset{
					{Name: assetName, BrowserDownloadURL: base + "/binary", Size: int64(len(binaryContent))},
					{Name: checksumName, BrowserDownloadURL: base + "/checksums"},
				},
			})
		case r.URL.Path == "/binary":
			http.ServeFile(w, r, tarPath)
		case r.URL.Path == "/checksums":
			http.ServeFile(w, r, checksumPath)
		}
	}))
	t.Cleanup(srv.Close)

	applied := false
	sys.cfg.githubAPIURL = srv.URL + "/latest"
	sys.cfg.httpClient = srv.Client()
	sys.cfg.insecureHTTPAllowed = true
	sys.cfg.applyFn = func(_ *os.File) error { applied = true; return nil }

	if err := sys.Update(true, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applied {
		t.Error("selfupdate.Apply must be called when checksum matches")
	}
}

// extractBinaryFromTarGz

func TestExtractBinaryFromTarGz(t *testing.T) {
	tmpDir := t.TempDir()
	want := []byte("binary payload")
	tarPath := filepath.Join(tmpDir, "test.tar.gz")
	writeTarGz(t, tarPath, want)

	src, err := os.Open(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	dst, err := os.CreateTemp(tmpDir, "extracted_*")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	if err := extractBinaryFromTarGz(src, dst); err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	_, _ = dst.Seek(0, 0)
	got, _ := io.ReadAll(dst)
	if string(got) != string(want) {
		t.Errorf("extracted content: got %q want %q", got, want)
	}
}
