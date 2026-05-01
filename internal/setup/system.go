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

	"charm.land/huh/v2"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/pkg/version"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/gzip"
	"github.com/minio/selfupdate"
	"github.com/olekukonko/ll"
	"github.com/yeka/zip"
)

// BackupManifest describes the contents of a backup archive.
// Version 1 archives store per-file SHA-256 hashes and an HMAC-SHA256 signature
// over the entire manifest so Restore can detect tampering.
type BackupManifest struct {
	Version   int           `json:"version"`
	Timestamp time.Time     `json:"timestamp"`
	OS        string        `json:"os"`
	Arch      string        `json:"arch"`
	Files     []BackupEntry `json:"files"`
}

// BackupEntry holds metadata for one file inside a backup archive.
type BackupEntry struct {
	OriginalPath string      `json:"original_path"`
	ArchivePath  string      `json:"archive_path"`
	SHA256       string      `json:"sha256"`
	Size         int64       `json:"size"`
	Mode         os.FileMode `json:"mode"`
}

// githubRelease is the subset of the GitHub Releases API response we consume.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// githubAsset represents one downloadable artifact attached to a release.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// SystemConfig carries all dependencies for the System operator.
// Only Logger is required for production callers. The unexported fields are
// test hooks that override network behaviour without real HTTP calls.
type SystemConfig struct {
	Logger *ll.Logger

	// githubAPIURL overrides woos.GitHubReleaseAPIURL in tests.
	githubAPIURL string

	// httpClient overrides the default HTTP client in tests.
	httpClient *http.Client

	// insecureHTTPAllowed disables the HTTPS-only guard so tests using
	// httptest.NewServer (plain HTTP) do not trip the security check.
	insecureHTTPAllowed bool

	// applyFn replaces selfupdate.Apply in tests so no binary is replaced on
	// disk. Receives the open *os.File of the verified binary.
	applyFn func(f *os.File) error
}

// System implements backup, restore, and self-update operations.
// Backup, Restore, and Update each return an error so callers can decide
// whether to fatal or propagate. The CLI wrapper calls Fatal; tests inspect
// the returned error directly.
type System struct {
	cfg SystemConfig
}

// NewSystem constructs a System operator with the provided configuration.
func NewSystem(cfg SystemConfig) *System {
	return &System{cfg: cfg}
}

// Backup archives the configuration, certificates, and associated data files
// referenced by configPath into outPath. When password is non-empty the
// archive entries are AES-256 encrypted and an HMAC-SHA256 signature is stored
// inside the archive so Restore can detect manifest tampering.
func (s *System) Backup(configPath, outPath, password string) error {
	global, err := loadGlobalConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load global config: %w", err)
	}

	if outPath == "" {
		outPath = fmt.Sprintf("agbero_backup_%s.zip", time.Now().Format("20060102_150405"))
	}
	outAbs, _ := filepath.Abs(outPath)

	u := ui.New()
	u.SectionHeader("Backup")
	u.BackupStart(password != "")

	addedFiles := make(map[string]bool)
	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return
		}
		info, err := os.Stat(abs)
		if err != nil {
			return
		}
		if info.IsDir() {
			_ = filepath.Walk(abs, func(wp string, wi os.FileInfo, we error) error {
				if we == nil && !wi.IsDir() {
					addedFiles[wp] = true
				}
				return nil
			})
		} else {
			addedFiles[abs] = true
		}
	}

	u.Step("run", "scanning configuration for associated files")

	addPath(configPath)
	addPath(global.Storage.HostsDir.Path())
	addPath(global.Storage.CertsDir.Path())
	addPath(global.Storage.DataDir.Path())
	addPath(global.Storage.WorkDir.Path())
	addPath(global.ErrorPages.Default)

	for _, p := range global.ErrorPages.Pages {
		addPath(p)
	}

	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(s.cfg.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		u.WarnLine(fmt.Sprintf("failed to load some hosts: %v", err))
	}
	for _, h := range hosts {
		addPath(h.TLS.Local.CertFile)
		addPath(h.TLS.Local.KeyFile)
		addPath(h.TLS.CustomCA.Root)
		for _, ca := range h.TLS.ClientCAs {
			addPath(ca)
		}
		addPath(h.ErrorPages.Default)
		for _, p := range h.ErrorPages.Pages {
			addPath(p)
		}
		for _, r := range h.Routes {
			addPath(r.ErrorPages.Default)
			for _, p := range r.ErrorPages.Pages {
				addPath(p)
			}
			if r.Wasm.Enabled.Active() {
				addPath(r.Wasm.Module)
			}
		}
	}

	u.Step("run", fmt.Sprintf("found %d files — creating archive", len(addedFiles)))

	outFile, err := os.Create(outAbs)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	manifest := BackupManifest{
		Version:   1,
		Timestamp: time.Now(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	fileIndex := 0
	for absPath := range addedFiles {
		if absPath == outAbs {
			continue
		}
		info, err := os.Stat(absPath)
		if err != nil {
			u.Step("warn", fmt.Sprintf("stat failed: %s", filepath.Base(absPath)))
			continue
		}
		file, err := os.Open(absPath)
		if err != nil {
			if strings.Contains(absPath, def.DefaultKeeperName) {
				u.Step("fail", fmt.Sprintf("%s is locked. You MUST stop the Agbero service before taking a system backup.", def.DefaultKeeperName))
				return fmt.Errorf("failed to backup %s: file is locked", def.DefaultKeeperName)
			}
			u.Step("warn", fmt.Sprintf("open failed: %s", filepath.Base(absPath)))
			continue
		}

		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			file.Close()
			u.Step("warn", fmt.Sprintf("hash failed: %s", filepath.Base(absPath)))
			continue
		}
		hashString := hex.EncodeToString(hasher.Sum(nil))

		archivePath := fmt.Sprintf("files/%d", fileIndex)
		fileIndex++

		var writer io.Writer
		if password != "" {
			writer, err = zipWriter.Encrypt(archivePath, password, zip.AES256Encryption)
		} else {
			writer, err = zipWriter.Create(archivePath)
		}
		if err != nil {
			file.Close()
			u.Step("warn", fmt.Sprintf("archive entry failed: %s", filepath.Base(absPath)))
			continue
		}

		_, _ = file.Seek(0, 0)
		if _, err = io.Copy(writer, file); err != nil {
			u.Step("warn", fmt.Sprintf("write failed: %s", filepath.Base(absPath)))
		}
		file.Close()

		u.Step("ok", fmt.Sprintf("%-48s  %s",
			truncatePath(absPath, 48),
			humanize.Bytes(uint64(info.Size())),
		))

		manifest.Files = append(manifest.Files, BackupEntry{
			OriginalPath: absPath,
			ArchivePath:  archivePath,
			SHA256:       hashString,
			Size:         info.Size(),
			Mode:         info.Mode(),
		})
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize manifest: %w", err)
	}

	var mWriter io.Writer
	if password != "" {
		mWriter, err = zipWriter.Encrypt("agbero.manifest.json", password, zip.AES256Encryption)
	} else {
		mWriter, err = zipWriter.Create("agbero.manifest.json")
	}
	if err != nil {
		return fmt.Errorf("failed to create manifest entry: %w", err)
	}
	if _, err := mWriter.Write(manifestBytes); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	sig := computeManifestHMAC(manifestBytes, password, manifest.Timestamp)
	var sigWriter io.Writer
	if password != "" {
		sigWriter, err = zipWriter.Encrypt("agbero.manifest.sig", password, zip.AES256Encryption)
	} else {
		sigWriter, err = zipWriter.Create("agbero.manifest.sig")
	}
	if err != nil {
		return fmt.Errorf("failed to create signature entry: %w", err)
	}
	if _, err := sigWriter.Write([]byte(sig)); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	u.BackupDone(outAbs, len(manifest.Files))
	return nil
}

// Restore extracts and verifies files from a backup archive created by Backup.
// autoYes skips the unconditional top-level prompt. force skips per-conflict
// overwrite prompts. Both flags are independent of each other.
func (s *System) Restore(inPath, password string, force, autoYes bool) error {
	if inPath == "" {
		return fmt.Errorf("input file path (-i) is required")
	}

	inAbs, _ := filepath.Abs(inPath)
	zr, err := zip.OpenReader(inAbs)
	if err != nil {
		return fmt.Errorf("failed to open backup zip: %w", err)
	}
	defer zr.Close()

	manifest, err := s.readAndVerifyManifest(zr, password)
	if err != nil {
		return err
	}

	u := ui.New()
	u.SectionHeader("Restore")

	if manifest.OS != runtime.GOOS {
		u.WarnLine(fmt.Sprintf("backup created on %s/%s, currently running %s/%s",
			manifest.OS, manifest.Arch, runtime.GOOS, runtime.GOARCH))
	}

	u.KeyValueBlock("", []ui.KV{
		{Label: "Archive", Value: inAbs},
		{Label: "Created", Value: manifest.Timestamp.Format("2006-01-02 15:04:05")},
		{Label: "Platform", Value: fmt.Sprintf("%s/%s", manifest.OS, manifest.Arch)},
		{Label: "Files", Value: fmt.Sprintf("%d", len(manifest.Files))},
	})

	allowedRoots := buildAllowedRoots(manifest.Files)

	for _, fe := range manifest.Files {
		if !strings.HasPrefix(fe.ArchivePath, "files/") || strings.Contains(fe.ArchivePath, "..") {
			return fmt.Errorf("corrupt backup — suspicious archive path %q", fe.ArchivePath)
		}
		if err := isSafeRestorePath(fe.OriginalPath, allowedRoots); err != nil {
			return fmt.Errorf("path containment violation — %w", err)
		}
	}

	if !autoYes {
		var confirm bool
		_ = huh.NewConfirm().
			Title("Restore Backup").
			Description(fmt.Sprintf("Restore %d files from %s to their original paths?",
				len(manifest.Files), inAbs)).
			Value(&confirm).Run()
		if !confirm {
			return fmt.Errorf("restore aborted by user")
		}
	}

	if !force {
		var conflicts []string
		for _, f := range manifest.Files {
			if _, err := os.Stat(f.OriginalPath); err == nil {
				conflicts = append(conflicts, f.OriginalPath)
			}
		}
		if len(conflicts) > 0 {
			u.WarnLine(fmt.Sprintf("%d existing files will be overwritten", len(conflicts)))
			var confirm bool
			err := huh.NewConfirm().
				Title("Files Exist").
				Description("Continue with restore and overwrite these files?").
				Value(&confirm).Run()
			if err != nil || !confirm {
				return fmt.Errorf("restore aborted by user")
			}
		}
	}

	archiveMap := make(map[string]*zip.File)
	for _, f := range zr.File {
		archiveMap[f.Name] = f
	}

	u.Step("run", "restoring files")

	restored := 0
	for _, fe := range manifest.Files {
		zf, ok := archiveMap[fe.ArchivePath]
		if !ok {
			return fmt.Errorf("corrupt backup — missing zip entry %s", fe.ArchivePath)
		}
		if zf.IsEncrypted() {
			zf.SetPassword(password)
		}

		src, err := zf.Open()
		if err != nil {
			return fmt.Errorf("failed to extract %s: %w", fe.ArchivePath, err)
		}

		destDir := filepath.Dir(fe.OriginalPath)
		if err := os.MkdirAll(destDir, expect.DirPerm); err != nil {
			src.Close()
			return fmt.Errorf("failed to create directories for %s: %w", fe.OriginalPath, err)
		}

		tmpPath := fe.OriginalPath + ".agbero_restore_tmp"
		dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fe.Mode)
		if err != nil {
			src.Close()
			return fmt.Errorf("failed to create temp file %s: %w", tmpPath, err)
		}

		hasher := sha256.New()
		mw := io.MultiWriter(dst, hasher)
		if _, err := io.Copy(mw, src); err != nil {
			dst.Close()
			src.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("failed to write %s: %w", tmpPath, err)
		}
		dst.Close()
		src.Close()

		if computed := hex.EncodeToString(hasher.Sum(nil)); computed != fe.SHA256 {
			os.Remove(tmpPath)
			return fmt.Errorf("CORRUPTION DETECTED — hash mismatch for %s", fe.OriginalPath)
		}

		if err := os.Rename(tmpPath, fe.OriginalPath); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("failed to finalise %s: %w", fe.OriginalPath, err)
		}

		u.Step("ok", fmt.Sprintf("%-48s  %s",
			truncatePath(fe.OriginalPath, 48),
			humanize.Bytes(uint64(fe.Size)),
		))
		restored++
	}

	u.RestoreDone(restored)
	return nil
}

// Update fetches the latest release from GitHub, verifies the SHA-256 checksum
// from the release's checksums.txt, and applies the binary replacement atomically.
// force skips the version comparison. autoYes skips the confirmation prompt.
// SHA-256 verification is never skipped regardless of flags.
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
		{Label: "Size", Value: humanize.Bytes(uint64(binaryAsset.Size))},
	})

	if !autoYes {
		var confirm bool
		_ = huh.NewConfirm().
			Title("Apply Update").
			Description(fmt.Sprintf("Download and apply %s from GitHub?", release.TagName)).
			Value(&confirm).Run()
		if !confirm {
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

// readAndVerifyManifest reads agbero.manifest.json and verifies the HMAC
// signature in agbero.manifest.sig when present. A missing signature file is
// tolerated for backwards compatibility. A present but invalid signature is an error.
func (s *System) readAndVerifyManifest(zr *zip.ReadCloser, password string) (BackupManifest, error) {
	var manifestFile, sigFile *zip.File
	for _, f := range zr.File {
		switch f.Name {
		case "agbero.manifest.json":
			manifestFile = f
		case "agbero.manifest.sig":
			sigFile = f
		}
	}

	if manifestFile == nil {
		return BackupManifest{}, fmt.Errorf("invalid backup — agbero.manifest.json not found")
	}

	if manifestFile.IsEncrypted() {
		if password == "" {
			return BackupManifest{}, fmt.Errorf("backup is encrypted but no password was provided (-p)")
		}
		manifestFile.SetPassword(password)
	}

	rc, err := manifestFile.Open()
	if err != nil {
		return BackupManifest{}, fmt.Errorf("failed to open manifest (wrong password?): %w", err)
	}
	manifestBytes, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return BackupManifest{}, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest BackupManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return BackupManifest{}, fmt.Errorf("failed to parse manifest: %w", err)
	}

	if sigFile != nil {
		if sigFile.IsEncrypted() {
			sigFile.SetPassword(password)
		}
		sigRC, err := sigFile.Open()
		if err == nil {
			sigBytes, err := io.ReadAll(sigRC)
			sigRC.Close()
			if err == nil {
				expected := computeManifestHMAC(manifestBytes, password, manifest.Timestamp)
				if !hmac.Equal(sigBytes, []byte(expected)) {
					return BackupManifest{}, fmt.Errorf("manifest signature verification failed — backup may be tampered")
				}
			}
		}
	}

	return manifest, nil
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

// buildAssetName returns the expected binary asset filename for the current
// platform matching the release workflow naming convention:
// agbero-{os}-{arch}.tar.gz  (or .zip on Windows)
func (s *System) buildAssetName(tagName string) string {
	_ = tagName
	if runtime.GOOS == def.Windows {
		return fmt.Sprintf("agbero-%s-%s.zip", runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("agbero-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

// buildChecksumName returns the checksums filename as produced by the release
// workflow: a single checksums.txt file covering all platform assets.
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

// downloadArchive downloads rawURL to a temp file as-is (no extraction).
// The archive is kept intact so its SHA-256 can be verified against checksums.txt
// before any extraction occurs. The caller must remove the file when done.
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
		// Correctly extract .zip files (Windows) instead of raw copying
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

func computeManifestHMAC(manifestBytes []byte, password string, ts time.Time) string {
	var key []byte
	if password != "" {
		key = []byte(password)
	} else {
		k := sha256.Sum256([]byte(fmt.Sprintf("agbero-backup-%d", ts.UnixNano())))
		key = k[:]
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(manifestBytes)
	return hex.EncodeToString(mac.Sum(nil))
}

// buildAllowedRoots returns the unique set of parent directories present in
// the manifest. These are the only directories to which Restore may write.
func buildAllowedRoots(files []BackupEntry) []string {
	seen := make(map[string]bool)
	var roots []string
	for _, fe := range files {
		abs, err := filepath.Abs(fe.OriginalPath)
		if err != nil {
			continue
		}
		dir := filepath.Dir(abs)
		if !seen[dir] {
			seen[dir] = true
			roots = append(roots, dir)
		}
	}
	return roots
}

// isSafeRestorePath resolves target to an absolute path and verifies it falls
// under at least one allowed root. Returns an error on any path escape.
func isSafeRestorePath(target string, allowedRoots []string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	for _, root := range allowedRoots {
		rel, err := filepath.Rel(root, abs)
		if err == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}
	}
	return fmt.Errorf("path %q escapes all allowed restore roots", target)
}

// rejectInsecureURL returns an error when rawURL does not use HTTPS.
// Only HTTPS is accepted for update asset downloads.
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
// checksums.txt (format per line: "<hash>  <filename>").
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

// loadGlobalConfig loads and applies defaults to a global configuration file.
func loadGlobalConfig(configFile string) (*alaye.Global, error) {
	global, err := parser.LoadGlobal(configFile)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(configFile)
	woos.DefaultApply(global, abs)
	return global, nil
}

// truncatePath shortens a filesystem path for display while preserving the filename.
func truncatePath(path string, maxLen int) string {
	if len([]rune(path)) <= maxLen {
		return path
	}
	base := filepath.Base(path)
	if len([]rune(base)) >= maxLen {
		return base
	}
	available := maxLen - len([]rune(base)) - 4
	dir := filepath.Dir(path)
	dirRunes := []rune(dir)
	if len(dirRunes) > available {
		dir = "…/" + string(dirRunes[len(dirRunes)-available:])
	}
	return dir + string(filepath.Separator) + base
}
