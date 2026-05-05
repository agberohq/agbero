package setup

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/olekukonko/ll"
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

// isUnderAnyRoot reports whether abs falls inside at least one of roots.
// Used to classify files as agbero-home vs externally managed.
func isUnderAnyRoot(abs string, roots []string) bool {
	for _, root := range roots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootAbs, abs)
		if err == nil && !strings.HasPrefix(rel, "..") {
			return true
		}
	}
	return false
}
