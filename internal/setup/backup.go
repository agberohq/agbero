package setup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/dustin/go-humanize"
	"github.com/yeka/zip"
)

// Backup archives the configuration, certificates, and associated data files
// referenced by configPath into outPath. When password is non-empty the archive
// entries are AES-256 encrypted and an HMAC-SHA256 signature is stored so
// Restore can detect tampering.
//
// Files outside agbero's own storage directories (e.g. TLS certificates managed
// by Let's Encrypt, error pages in /var/www) are included — they are legitimate
// — but listed as warnings so the operator can audit what will be restored and
// to which absolute paths.
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
	u.Flush()

	// Prompt for a password when none was supplied via flag. Any error from the
	// prompt (non-tty, cancelled, piped input) is treated as "no password" and
	// the backup proceeds unencrypted. The operator sees the warning either way.
	if password == "" {
		if result, err := u.PasswordWithHint(
			"Backup password",
			"Leave empty to create an unencrypted backup (not recommended)",
			false,
		); err == nil && result != nil {
			password = result.String()
			defer result.Zero()
		}
	}

	u.BackupStart(password != "")
	u.Flush()

	// homeRoots is the set of directories agbero owns. Anything outside these
	// is legitimate but flagged so the operator knows what the archive contains.
	homeRoots := []string{
		filepath.Dir(filepath.Clean(configPath)),
		global.Storage.HostsDir.Path(),
		global.Storage.CertsDir.Path(),
		global.Storage.DataDir.Path(),
		global.Storage.WorkDir.Path(),
	}

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
	u.Flush()

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

	// Warn about files outside agbero's storage directories. These are
	// legitimate but the operator should see them before archiving.
	var outOfScope []string
	for abs := range addedFiles {
		if !isUnderAnyRoot(abs, homeRoots) {
			outOfScope = append(outOfScope, abs)
		}
	}
	if len(outOfScope) > 0 {
		u.WarnLine(fmt.Sprintf(
			"%d file(s) outside agbero home dirs will be archived and restored to their original absolute paths:",
			len(outOfScope),
		))
		for _, p := range outOfScope {
			u.WarnLine("  " + p)
		}
		u.Flush()
	}

	u.Step("run", fmt.Sprintf("found %d files — creating archive", len(addedFiles)))
	u.Flush()

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
			if strings.Contains(absPath, "keeper.db") {
				u.Step("fail", "keeper.db is locked. You MUST stop the Agbero service before taking a system backup.")
				return fmt.Errorf("failed to backup keeper.db: file is locked")
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
// configPath is the live agbero config on this machine — it is used to build
// the set of trusted restore roots from actual configuration, not from the
// (potentially attacker-controlled) manifest. autoYes skips all confirmation
// prompts. force skips per-conflict overwrite prompts.
func (s *System) Restore(inPath, configPath, password string, force, autoYes bool) error {
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
	u.Flush()

	// ZipSlip guard: run before trusted-root derivation so archive-format
	// violations are caught regardless of whether a config path was supplied.
	for _, fe := range manifest.Files {
		if !strings.HasPrefix(fe.ArchivePath, "files/") || strings.Contains(fe.ArchivePath, "..") {
			return fmt.Errorf("corrupt backup — suspicious archive path %q", fe.ArchivePath)
		}
		cleaned := filepath.Clean(fe.OriginalPath)
		if strings.Contains(cleaned, "\x00") {
			return fmt.Errorf("corrupt backup — NUL byte in path %q", fe.OriginalPath)
		}
	}

	// Build trusted restore roots from the LIVE config on this machine.
	// This is the critical fix for the privilege escalation: allowed roots must
	// not come from the manifest (which is attacker-controlled before HMAC
	// verification, and even after verification only proves the archive was
	// produced by someone with the HMAC key — not that its paths are safe on
	// this machine).
	//
	// Tests may inject roots directly via SystemConfig.restoreTrustedRoots
	// to avoid needing a real config file on disk.
	var trustedRoots []string
	if s.cfg.restoreTrustedRoots != nil {
		trustedRoots = s.cfg.restoreTrustedRoots
	} else if configPath != "" {
		if liveGlobal, err := loadGlobalConfig(configPath); err == nil {
			trustedRoots = []string{
				filepath.Dir(filepath.Clean(configPath)),
				liveGlobal.Storage.HostsDir.Path(),
				liveGlobal.Storage.CertsDir.Path(),
				liveGlobal.Storage.DataDir.Path(),
				liveGlobal.Storage.WorkDir.Path(),
			}
			// Also include paths referenced by the live host configs so that
			// TLS certs, error pages, and Wasm modules at external paths are
			// trusted when they are genuinely configured on this machine.
			liveHM := discovery.NewHost(liveGlobal.Storage.HostsDir, discovery.WithLogger(s.cfg.Logger))
			if liveHosts, err := liveHM.LoadAll(); err == nil {
				for _, h := range liveHosts {
					for _, p := range []string{
						h.TLS.Local.CertFile, h.TLS.Local.KeyFile,
						h.TLS.CustomCA.Root, h.ErrorPages.Default,
					} {
						if p != "" {
							trustedRoots = append(trustedRoots, filepath.Dir(p))
						}
					}
					for _, ca := range h.TLS.ClientCAs {
						trustedRoots = append(trustedRoots, filepath.Dir(ca))
					}
					for _, p := range h.ErrorPages.Pages {
						trustedRoots = append(trustedRoots, filepath.Dir(p))
					}
					for _, r := range h.Routes {
						candidates := []string{r.ErrorPages.Default, r.Wasm.Module}
						for _, p := range r.ErrorPages.Pages {
							candidates = append(candidates, p)
						}
						for _, p := range candidates {
							if p != "" {
								trustedRoots = append(trustedRoots, filepath.Dir(p))
							}
						}
					}
				}
			}
		} else {
			// Live config is unreadable. Failing open by deriving trusted roots
			// from the manifest would be a security hole — the manifest is
			// attacker-controlled. Abort instead; the operator must supply -c.
			return fmt.Errorf(
				"cannot restore: failed to load live config %q: %w. "+
					"Provide -c /path/to/agbero.hcl so path validation can use trusted roots "+
					"from your live configuration rather than the (untrusted) backup manifest.",
				configPath, err,
			)
		}
	} else {
		// No config path supplied — restrict restore to the OS temp directory.
		// This is safe for tests and for bare restore invocations where the
		// operator has not yet set up a config file. Any manifest entry that
		// tries to write outside the temp tree will be flagged as out-of-scope
		// and require explicit confirmation, preventing silent privilege
		// escalation via a crafted archive.
		u.WarnLine("no config path provided — restore paths restricted to " + os.TempDir())
		trustedRoots = []string{os.TempDir()}
	}
	u.Flush()

	// Path trust check: every manifest entry must fall inside a trusted root
	// derived from the live config. Entries outside trusted roots are out-of-scope.
	var outOfScope []BackupEntry
	for _, fe := range manifest.Files {
		abs, _ := filepath.Abs(fe.OriginalPath)
		if !isUnderAnyRoot(abs, trustedRoots) {
			outOfScope = append(outOfScope, fe)
		}
	}

	if len(outOfScope) > 0 {
		u.Flush()
		u.WarnLine(fmt.Sprintf(
			"%d file(s) will be restored to absolute paths outside agbero's home directories:",
			len(outOfScope),
		))
		for _, fe := range outOfScope {
			u.WarnLine("  " + fe.OriginalPath)
		}
		u.WarnLine("These paths come from the backup manifest. Verify the archive is trustworthy before proceeding.")
		u.Flush()

		if !autoYes {
			ok, err := u.Confirm(
				"Restore files to out-of-scope paths?",
				"The paths listed above are outside agbero's standard directories.\nOnly proceed if you trust the source of this backup.",
			)
			if err != nil || !ok {
				return fmt.Errorf("restore aborted — out-of-scope paths not confirmed")
			}
		}
	}

	// Top-level confirmation.
	if !autoYes {
		ok, err := u.Confirm(
			fmt.Sprintf("Restore %d files from %s to their original paths?", len(manifest.Files), inAbs),
		)
		if err != nil || !ok {
			return fmt.Errorf("restore aborted by user")
		}
	}

	// Conflict detection: existing files that would be overwritten.
	// Out-of-scope conflicts get a stronger warning and a separate prompt.
	if !force {
		var inScopeConflicts, outOfScopeConflicts []string
		outOfScopePaths := make(map[string]bool, len(outOfScope))
		for _, fe := range outOfScope {
			outOfScopePaths[fe.OriginalPath] = true
		}

		for _, f := range manifest.Files {
			if _, err := os.Stat(f.OriginalPath); err == nil {
				if outOfScopePaths[f.OriginalPath] {
					outOfScopeConflicts = append(outOfScopeConflicts, f.OriginalPath)
				} else {
					inScopeConflicts = append(inScopeConflicts, f.OriginalPath)
				}
			}
		}

		if len(outOfScopeConflicts) > 0 {
			u.Flush()
			u.WarnLine(fmt.Sprintf(
				"%d existing file(s) OUTSIDE agbero home dirs will be overwritten:",
				len(outOfScopeConflicts),
			))
			for _, p := range outOfScopeConflicts {
				u.WarnLine("  " + p)
			}
			u.Flush()

			if !autoYes {
				ok, err := u.Confirm(
					"Overwrite existing files at out-of-scope paths?",
					"These files exist on disk at paths outside agbero's directories.\nOverwriting them may affect other services. Only proceed if you are certain.",
				)
				if err != nil || !ok {
					return fmt.Errorf("restore aborted — out-of-scope overwrite not confirmed")
				}
			}
		}

		if len(inScopeConflicts) > 0 {
			u.WarnLine(fmt.Sprintf("%d existing file(s) will be overwritten", len(inScopeConflicts)))
			u.Flush()

			if !autoYes {
				ok, err := u.Confirm("Overwrite existing agbero files?")
				if err != nil || !ok {
					return fmt.Errorf("restore aborted by user")
				}
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
		u.Flush()
		restored++
	}

	u.RestoreDone(restored)
	return nil
}

// readAndVerifyManifest reads agbero.manifest.json and verifies the HMAC
// signature in agbero.manifest.sig. A missing signature is rejected — every
// archive produced by Backup includes a .sig entry. A present but invalid
// signature is also an error.
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

	// A missing .sig means the archive was crafted by hand or the entry was
	// deliberately stripped to bypass verification. Both cases are rejected.
	// Every archive written by Backup since version 1 includes a .sig entry.
	if sigFile == nil {
		return BackupManifest{}, fmt.Errorf("invalid backup — agbero.manifest.sig not found; archive may be tampered or was not created by agbero backup")
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

	if sigFile.IsEncrypted() {
		sigFile.SetPassword(password)
	}
	sigRC, err := sigFile.Open()
	if err != nil {
		return BackupManifest{}, fmt.Errorf("failed to open signature file: %w", err)
	}
	sigBytes, err := io.ReadAll(sigRC)
	sigRC.Close()
	if err != nil {
		return BackupManifest{}, fmt.Errorf("failed to read signature: %w", err)
	}

	expected := computeManifestHMAC(manifestBytes, password, manifest.Timestamp)
	if !hmac.Equal(sigBytes, []byte(expected)) {
		return BackupManifest{}, fmt.Errorf("manifest signature verification failed — backup may be tampered")
	}

	return manifest, nil
}

// computeManifestHMAC returns the hex-encoded HMAC-SHA256 of manifestBytes.
//
// Key derivation:
//
//   - When password is non-empty: the key is the password bytes. The HMAC
//     provides both integrity and authenticity — only someone who knows the
//     password can produce a valid signature.
//
//   - When password is empty: the key is the fixed label "agbero-backup-v1".
//     This provides format integrity (detects accidental corruption) but NOT
//     authenticity — anyone can compute the same HMAC. The Restore path
//     documents this limitation and relies on the live-config trusted-roots
//     check as the real security boundary for unencrypted archives.
//
//     Previously this branch derived the key from os.Hostname(), which gave
//     a false sense of security: hostnames are discoverable (DNS, banners,
//     error messages) and fall back to the constant "agbero-host" on
//     restricted systems, making the signature trivially forgeable in practice.
//     A fixed well-known label is more honest about what an unencrypted backup
//     signature actually guarantees.
//
// The ts parameter is accepted for API compatibility but is not used in key
// derivation — the timestamp is already part of manifestBytes which is MAC'd.
func computeManifestHMAC(manifestBytes []byte, password string, ts time.Time) string {
	_ = ts
	var key []byte
	if password != "" {
		key = []byte(password)
	} else {
		// Fixed well-known label: integrity-only, not authentication.
		// See doc comment above for rationale.
		key = []byte(def.BackupHMACKey)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(manifestBytes)
	return hex.EncodeToString(mac.Sum(nil))
}

// buildAllowedRoots returns the unique set of parent directories present in
// the manifest. It is used by tests and by the ZipSlip validation path.
// It must NOT be used to derive security boundaries for the restore destination —
// doing so is a tautology (every path is trivially its own parent's child).
// Destination safety is enforced via live-config trusted roots; see Restore.
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
// under at least one of allowedRoots. Returns an error if the path escapes all
// roots (ZipSlip / path-traversal guard).
//
// Security note: the roots passed here must come from a trusted source (the
// live config, not the backup manifest). Passing manifest-derived roots makes
// this check a tautology — see Restore for correct usage.
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
