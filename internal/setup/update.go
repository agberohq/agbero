package setup

import (
	"archive/tar"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/pkg/version"
	"github.com/klauspost/compress/gzip"
	"github.com/minio/selfupdate"
	"github.com/yeka/zip"
)

// Update fetches the latest release from GitHub, verifies the SHA-256 checksum
// from the release's checksums.txt, and applies the binary replacement
// atomically. force skips the version comparison. autoYes skips the
// confirmation prompt. SHA-256 verification is never skipped regardless of flags.
func (s *System) Update(force, autoYes bool) error {
	u := ui.New()
	u.SectionHeader("System Update")

	release, err := s.fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to fetch release info: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")

	if !force && !version.ShouldUpdate(woos.Version, latestVersion) {
		u.SuccessLine(fmt.Sprintf("already up to date (%s)", woos.Version))
		return nil
	}

	assetName := s.buildAssetName(release.TagName)
	checksumName := s.buildChecksumName(release.TagName)

	binaryAsset := s.findAsset(release.Assets, assetName)
	if binaryAsset == nil {
		return fmt.Errorf("no asset found for %s/%s (looked for %q)",
			runtime.GOOS, runtime.GOARCH, assetName)
	}

	checksumAsset := s.findAsset(release.Assets, checksumName)
	if checksumAsset == nil {
		return fmt.Errorf("no checksums file found (looked for %q)", checksumName)
	}

	if !s.cfg.insecureHTTPAllowed {
		if err := rejectInsecureURL(binaryAsset.BrowserDownloadURL); err != nil {
			return err
		}
		if err := rejectInsecureURL(checksumAsset.BrowserDownloadURL); err != nil {
			return err
		}
	}

	u.KeyValueBlock("", []ui.KV{
		{Label: "Current", Value: woos.Version},
		{Label: "Latest", Value: release.TagName},
		{Label: "Asset", Value: assetName},
		{Label: "Size", Value: fmt.Sprintf("%d bytes", binaryAsset.Size)},
	})

	if !autoYes {
		ok, err := u.Confirm(fmt.Sprintf("Download and apply %s from GitHub?", release.TagName))
		if err != nil || !ok {
			return fmt.Errorf("update aborted by user")
		}
	}

	u.Step("run", "downloading binary")
	tmpArchive, err := s.downloadArchive(binaryAsset.BrowserDownloadURL, assetName, def.UpdateDownloadTimeout)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer os.Remove(tmpArchive)

	u.Step("run", "downloading checksums")
	checksumBody, err := s.downloadBytes(checksumAsset.BrowserDownloadURL, def.UpdateFetchTimeout)
	if err != nil {
		return fmt.Errorf("checksum download failed: %w", err)
	}

	expectedHash, err := parseChecksumFile(checksumBody, assetName)
	if err != nil {
		return err
	}

	u.Step("run", "verifying checksum")
	actualHash, err := hashFile(tmpArchive)
	if err != nil {
		return fmt.Errorf("failed to hash downloaded archive: %w", err)
	}

	if !hmac.Equal([]byte(expectedHash), []byte(actualHash)) {
		return fmt.Errorf("checksum mismatch — update aborted")
	}

	u.Step("run", "applying update")
	f, err := s.extractBinary(tmpArchive, assetName)
	if err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if s.cfg.applyFn != nil {
		if err := s.cfg.applyFn(f); err != nil {
			return fmt.Errorf("failed to apply binary: %w", err)
		}
	} else {
		if err := selfupdate.Apply(f, selfupdate.Options{}); err != nil {
			return fmt.Errorf("failed to apply binary: %w", err)
		}
	}

	u.SuccessLine("Update applied. Run 'sudo agbero service restart' to activate.")
	return nil
}

// fetchLatestRelease queries the GitHub Releases API for the most recent release.
func (s *System) fetchLatestRelease() (*githubRelease, error) {
	apiURL := def.GitHubReleaseAPIURL
	if s.cfg.githubAPIURL != "" {
		apiURL = s.cfg.githubAPIURL
	}
	client := &http.Client{Timeout: def.UpdateFetchTimeout}
	if s.cfg.httpClient != nil {
		client = s.cfg.httpClient
	}
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode release: %w", err)
	}
	return &release, nil
}

// buildAssetName returns the expected binary asset filename for the current platform.
func (s *System) buildAssetName(_ string) string {
	if runtime.GOOS == def.Windows {
		return fmt.Sprintf("agbero-%s-%s.zip", runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("agbero-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

// buildChecksumName returns the checksums filename produced by the release workflow.
func (s *System) buildChecksumName(_ string) string {
	return "checksums.txt"
}

// findAsset searches assets for one whose Name matches target (case-insensitive).
func (s *System) findAsset(assets []githubAsset, name string) *githubAsset {
	for i := range assets {
		if strings.EqualFold(assets[i].Name, name) {
			return &assets[i]
		}
	}
	return nil
}

// downloadArchive downloads rawURL to a temp file without extracting it.
// The archive hash is verified against checksums.txt before any extraction.
// The caller must remove the returned file when done.
func (s *System) downloadArchive(rawURL, assetName string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	if s.cfg.httpClient != nil {
		client = s.cfg.httpClient
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	ext := ".tar.gz"
	if strings.HasSuffix(strings.ToLower(assetName), ".zip") {
		ext = ".zip"
	}
	tmp, err := os.CreateTemp("", "agbero_archive_*"+ext)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func (s *System) extractBinary(archivePath, assetName string) (*os.File, error) {
	tmp, err := os.CreateTemp("", "agbero_binary_*")
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(strings.ToLower(assetName), ".tar.gz") {
		src, err := os.Open(archivePath)
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, err
		}
		defer src.Close()
		if err := extractBinaryFromTarGz(src, tmp); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("extraction failed: %w", err)
		}
	} else if strings.HasSuffix(strings.ToLower(assetName), ".zip") {
		if err := extractBinaryFromZip(archivePath, tmp); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("extraction failed: %w", err)
		}
	} else {
		src, err := os.Open(archivePath)
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, err
		}
		if _, err := io.Copy(tmp, src); err != nil {
			src.Close()
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, err
		}
		src.Close()
	}

	if _, err := tmp.Seek(0, 0); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	return tmp, nil
}

func (s *System) downloadBytes(rawURL string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	if s.cfg.httpClient != nil {
		client = s.cfg.httpClient
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func extractBinaryFromTarGz(r io.Reader, dst *os.File) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()

	binaryName := def.Name
	if runtime.GOOS == def.Windows {
		binaryName = def.Name + ".exe"
	}

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(hdr.Name) == binaryName {
			_, err = io.Copy(dst, tr)
			return err
		}
	}
	return fmt.Errorf("binary %q not found in archive", binaryName)
}

func extractBinaryFromZip(archivePath string, dst *os.File) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()

	binaryName := def.Name
	if runtime.GOOS == def.Windows {
		binaryName = def.Name + ".exe"
	}

	for _, f := range zr.File {
		if filepath.Base(f.Name) == binaryName {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			_, err = io.Copy(dst, rc)
			rc.Close()
			return err
		}
	}
	return fmt.Errorf("binary %q not found in zip archive", binaryName)
}

// rejectInsecureURL returns an error when rawURL does not use HTTPS.
func rejectInsecureURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if !strings.EqualFold(u.Scheme, def.Https) {
		return fmt.Errorf("refusing insecure URL %q — only HTTPS is accepted for updates", rawURL)
	}
	return nil
}

// parseChecksumFile finds the SHA-256 hash for assetName in a GoReleaser
// checksums.txt (format: "<hash>  <filename>" per line).
func parseChecksumFile(data []byte, assetName string) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		if strings.EqualFold(parts[1], assetName) || strings.EqualFold(filepath.Base(parts[1]), assetName) {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("no checksum found for %q in checksums file", assetName)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
