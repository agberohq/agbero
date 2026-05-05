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

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/woos"
)

// writeTarGz creates a .tar.gz archive at dst containing the agbero binary
// with the given content. Used to mock GitHub release assets in update tests.
func writeTarGz(t *testing.T, dst string, content []byte) {
	t.Helper()
	f, err := os.Create(dst)
	if err != nil {
		t.Fatalf("writeTarGz create: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	binaryName := def.Name
	if runtime.GOOS == def.Windows {
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

// sha256HexBytes returns the hex SHA-256 of b.
func sha256HexBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// rejectInsecureURL

func TestRejectInsecureURL_https(t *testing.T) {
	if err := rejectInsecureURL("https://github.com/agberohq/agbero/releases/download/v1.0.0/agbero.tar.gz"); err != nil {
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

// Update — asset naming

func TestBuildAssetName(t *testing.T) {
	sys := newTestSystem(t)
	name := sys.buildAssetName("v0.2.6")
	expected := fmt.Sprintf("agbero-%s-%s", runtime.GOOS, runtime.GOARCH)
	if !strings.HasPrefix(name, expected) {
		t.Errorf("unexpected asset name: got %q, want prefix %q", name, expected)
	}
	if runtime.GOOS != def.Windows && !strings.HasSuffix(name, ".tar.gz") {
		t.Errorf("non-Windows asset must end in .tar.gz: %q", name)
	}
	if runtime.GOOS == def.Windows && !strings.HasSuffix(name, ".zip") {
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
	_ = os.WriteFile(checksumPath, []byte(checksumContent), def.ConfigFilePerm)

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
	correctHash := sha256HexBytes(archiveBytes)
	checksumContent := fmt.Sprintf("%s  %s\n", correctHash, assetName)
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	_ = os.WriteFile(checksumPath, []byte(checksumContent), def.ConfigFilePerm)

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
