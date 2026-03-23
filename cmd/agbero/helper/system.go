package helper

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
	"time"

	"charm.land/huh/v2"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/dustin/go-humanize"
	"github.com/yeka/zip"
)

type System struct {
	p *Helper
}

type Manifest struct {
	Version   int         `json:"version"`
	Timestamp time.Time   `json:"timestamp"`
	OS        string      `json:"os"`
	Arch      string      `json:"arch"`
	Files     []FileEntry `json:"files"`
}

type FileEntry struct {
	OriginalPath string      `json:"original_path"`
	ArchivePath  string      `json:"archive_path"`
	SHA256       string      `json:"sha256"`
	Size         int64       `json:"size"`
	Mode         os.FileMode `json:"mode"`
}

func (s *System) Backup(configPath, outPath, password string) {
	global, err := loadGlobal(configPath)
	if err != nil {
		s.p.Logger.Fatal("failed to load global config for backup: ", err)
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
			_ = filepath.Walk(abs, func(walkPath string, walkInfo os.FileInfo, walkErr error) error {
				if walkErr == nil && !walkInfo.IsDir() {
					addedFiles[walkPath] = true
				}
				return nil
			})
		} else {
			addedFiles[abs] = true
		}
	}

	u.Step("run", "scanning configuration for associated files")

	addPath(configPath)
	addPath(global.Storage.HostsDir)
	addPath(global.Storage.CertsDir)
	addPath(global.Storage.DataDir)
	addPath(global.Storage.WorkDir)

	if global.Security.InternalAuthKey != "" {
		addPath(global.Security.InternalAuthKey)
	}

	addPath(global.ErrorPages.Default)
	for _, p := range global.ErrorPages.Pages {
		addPath(p)
	}

	hm := discovery.NewHost(woos.NewFolder(global.Storage.HostsDir), discovery.WithLogger(s.p.Logger))
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
		s.p.Logger.Fatal("failed to create backup file: ", err)
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	manifest := Manifest{
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

		// Show each file being added with its size.
		u.Step("ok", fmt.Sprintf("%-48s  %s",
			truncatePath(absPath, 48),
			humanize.Bytes(uint64(info.Size())),
		))

		manifest.Files = append(manifest.Files, FileEntry{
			OriginalPath: absPath,
			ArchivePath:  archivePath,
			SHA256:       hashString,
			Size:         info.Size(),
			Mode:         info.Mode(),
		})
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		s.p.Logger.Fatal("Failed to serialize manifest: ", err)
	}

	var mWriter io.Writer
	if password != "" {
		mWriter, err = zipWriter.Encrypt("agbero.manifest.json", password, zip.AES256Encryption)
	} else {
		mWriter, err = zipWriter.Create("agbero.manifest.json")
	}
	if err != nil {
		s.p.Logger.Fatal("Failed to create manifest entry in zip: ", err)
	}

	if _, err := mWriter.Write(manifestBytes); err != nil {
		s.p.Logger.Fatal("Failed to write manifest data: ", err)
	}

	u.BackupDone(outAbs, len(manifest.Files))
}

func (s *System) Restore(inPath, password string, force bool) {
	if inPath == "" {
		s.p.Logger.Fatal("Input file path (-i) is required for restore.")
	}

	inAbs, _ := filepath.Abs(inPath)
	zr, err := zip.OpenReader(inAbs)
	if err != nil {
		s.p.Logger.Fatal("Failed to open backup zip: ", err)
	}
	defer zr.Close()

	var manifestFile *zip.File
	for _, f := range zr.File {
		if f.Name == "agbero.manifest.json" {
			manifestFile = f
			break
		}
	}

	if manifestFile == nil {
		s.p.Logger.Fatal("Invalid backup: agbero.manifest.json not found")
	}

	if manifestFile.IsEncrypted() {
		if password == "" {
			s.p.Logger.Fatal("Backup is encrypted but no password was provided (-p).")
		}
		manifestFile.SetPassword(password)
	}

	rc, err := manifestFile.Open()
	if err != nil {
		s.p.Logger.Fatal("Failed to open manifest. Incorrect password?: ", err)
	}
	manifestBytes, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		s.p.Logger.Fatal("Failed to read manifest: ", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		s.p.Logger.Fatal("Failed to parse manifest: ", err)
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
				Value(&confirm).
				Run()
			if err != nil || !confirm {
				s.p.Logger.Fatal("Restore aborted by user.")
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
			s.p.Logger.Fatalf("Corrupt backup: missing file inside zip %s", fe.ArchivePath)
		}

		if zf.IsEncrypted() {
			zf.SetPassword(password)
		}

		src, err := zf.Open()
		if err != nil {
			s.p.Logger.Fatalf("Failed to extract %s: %v", fe.ArchivePath, err)
		}

		destDir := filepath.Dir(fe.OriginalPath)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			src.Close()
			s.p.Logger.Fatalf("Failed to create directories for %s: %v", fe.OriginalPath, err)
		}

		tmpPath := fe.OriginalPath + ".tmp"
		dst, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fe.Mode)
		if err != nil {
			src.Close()
			s.p.Logger.Fatalf("Failed to create temp file %s: %v", tmpPath, err)
		}

		hasher := sha256.New()
		mw := io.MultiWriter(dst, hasher)

		if _, err := io.Copy(mw, src); err != nil {
			dst.Close()
			src.Close()
			os.Remove(tmpPath)
			s.p.Logger.Fatalf("Failed to write data to %s: %v", tmpPath, err)
		}

		dst.Close()
		src.Close()

		computedHash := hex.EncodeToString(hasher.Sum(nil))
		if computedHash != fe.SHA256 {
			os.Remove(tmpPath)
			s.p.Logger.Fatalf("CORRUPTION DETECTED: Hash mismatch for %s. Restore aborted to protect system integrity.", fe.OriginalPath)
		}

		if err := os.Rename(tmpPath, fe.OriginalPath); err != nil {
			os.Remove(tmpPath)
			s.p.Logger.Fatalf("Failed to finalize restoration of %s: %v", fe.OriginalPath, err)
		}

		// Show each file restored with its size.
		u.Step("ok", fmt.Sprintf("%-48s  %s",
			truncatePath(fe.OriginalPath, 48),
			humanize.Bytes(uint64(fe.Size)),
		))

		restored++
	}

	u.RestoreDone(restored)
}

// truncatePath shortens a path to maxLen by keeping the filename and
// as much of the directory as fits, prefixing with "…/" if truncated.
func truncatePath(path string, maxLen int) string {
	if len([]rune(path)) <= maxLen {
		return path
	}
	base := filepath.Base(path)
	if len([]rune(base)) >= maxLen {
		return base
	}
	available := maxLen - len([]rune(base)) - 4 // 4 = "…/" + some dir chars
	dir := filepath.Dir(path)
	dirRunes := []rune(dir)
	if len(dirRunes) > available {
		dir = "…/" + string(dirRunes[len(dirRunes)-available:])
	}
	return dir + string(filepath.Separator) + base
}
