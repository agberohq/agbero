package tlss

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

// IsMkcertInstalled checks if mkcert is available on the system.
// It checks PATH and common installation directories.
func IsMkcertInstalled() bool {
	// 1) PATH
	if path, err := exec.LookPath("mkcert"); err == nil {
		cmd := exec.Command(path, "-version")
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// 2) Common locations
	home, _ := os.UserHomeDir()
	commonPaths := []string{
		"/usr/local/bin/mkcert",
		"/usr/bin/mkcert",
		"/opt/homebrew/bin/mkcert",
		filepath.Join(home, "go", "bin", "mkcert"),
		filepath.Join(home, ".local", "bin", "mkcert"),
	}

	if runtime.GOOS == "windows" {
		commonPaths = append(commonPaths,
			filepath.Join(home, "scoop", "shims", "mkcert.exe"),
			filepath.Join(home, "choco", "bin", "mkcert.exe"),
		)
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// BootstrapEnv makes service environments sane for mkcert/trust tooling.
// It DOES NOT force CAROOT.
// It only ensures HOME/USER/LOGNAME are set (mkcert uses them to discover its default CAROOT).
func BootstrapEnv(logger *ll.Logger) error {
	changed := false

	// HOME
	if os.Getenv("HOME") == "" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			_ = os.Setenv("HOME", u.HomeDir)
			changed = true
		}
	}

	// USER + LOGNAME
	if os.Getenv("USER") == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			_ = os.Setenv("USER", u.Username)
			changed = true
		}
	}
	if os.Getenv("LOGNAME") == "" && os.Getenv("USER") != "" {
		_ = os.Setenv("LOGNAME", os.Getenv("USER"))
		changed = true
	}

	if logger != nil && changed {
		logger.Debugf("tlss: bootstrapped env (HOME=%q USER=%q LOGNAME=%q)",
			os.Getenv("HOME"), os.Getenv("USER"), os.Getenv("LOGNAME"))
	}

	// No fatal condition here: we allow running without mkcert too.
	return nil
}

// mkcertEnv builds a stable env slice for exec.Command when under launchd/systemd.
func mkcertEnv(extra ...string) []string {
	env := append([]string(nil), os.Environ()...)

	// Ensure HOME is set (mkcert needs it to find its default CAROOT).
	if os.Getenv("HOME") == "" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			env = append(env, "HOME="+u.HomeDir)
		}
	}

	// Ensure USER/LOGNAME are set.
	if os.Getenv("USER") == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			env = append(env, "USER="+u.Username)
		}
	}
	if os.Getenv("LOGNAME") == "" {
		if os.Getenv("USER") != "" {
			env = append(env, "LOGNAME="+os.Getenv("USER"))
		}
	}

	env = append(env, extra...)
	return env
}

// MkcertDefaultCAROOT returns mkcert's own default CA root directory (as mkcert reports it).
// Works even under services because mkcertEnv guarantees HOME/USER.
func MkcertDefaultCAROOT(mkcertPath string) (string, error) {
	cmd := exec.Command(mkcertPath, "-CAROOT")
	cmd.Env = mkcertEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mkcert -CAROOT failed: %s", strings.TrimSpace(string(out)))
	}
	caroot := strings.TrimSpace(string(out))
	if caroot == "" {
		return "", fmt.Errorf("mkcert returned empty CAROOT")
	}
	return filepath.Clean(caroot), nil
}

// IsMkcertRootPresent checks if rootCA.pem exists inside mkcert's default CAROOT.
func IsMkcertRootPresent(mkcertPath string) bool {
	caroot, err := MkcertDefaultCAROOT(mkcertPath)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(caroot, "rootCA.pem"))
	return err == nil
}

// IsCARootInstalled checks whether mkcert's CA appears to be trusted/installed on this OS.
//
// Important: "present on disk" != "trusted by OS".
// This function is a best-effort trust check.
func IsCARootInstalled() bool {
	switch runtime.GOOS {
	case woos.Darwin:
		// "mkcert development CA" is the usual subject label.
		// Query system keychain for that exact label.
		cmd := exec.Command("security", "find-certificate", "-c", "mkcert development CA")
		return cmd.Run() == nil

	case woos.Linux:
		// Linux is distro-dependent. We check common trust store paths.
		paths := []string{
			"/etc/ssl/certs/mkcert-root.pem",
			"/usr/local/share/ca-certificates/mkcert-root.crt",
			filepath.Join(os.Getenv("HOME"), ".local/share/mkcert/rootCA.pem"),
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return true
			}
		}
		return false

	case woos.Windows:
		// Check both LocalMachine and CurrentUser Root stores (because mkcert can install to user).
		ps := `
$found = $false
try { if (Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "mkcert development CA"} | Select-Object -First 1) { $found = $true } } catch {}
try { if (-not $found) { if (Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object {$_.Subject -match "mkcert development CA"} | Select-Object -First 1) { $found = $true } } } catch {}
if ($found) { "yes" }
`
		cmd := exec.Command("powershell", "-NoProfile", "-Command", ps)
		out, err := cmd.Output()
		return err == nil && strings.Contains(strings.ToLower(string(out)), "yes")
	}
	return false
}
