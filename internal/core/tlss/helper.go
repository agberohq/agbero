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

const (
	MkCertBinary        = "mkcert"
	MkCertRootCAFile    = "rootCA.pem"
	MkCertDefaultCAName = "mkcert development CA"
	MkCertCAROOTFlag    = "-CAROOT"

	EnvHome    = "HOME"
	EnvUser    = "USER"
	EnvLogName = "LOGNAME"

	UnixUsrLocalBinMkCert    = "/usr/local/bin/mkcert"
	UnixUsrBinMkCert         = "/usr/bin/mkcert"
	UnixOptHomebrewBinMkCert = "/opt/homebrew/bin/mkcert"
	UnixLocalBinMkCert       = ".local/bin/mkcert"
	UnixGoBinMkCert          = "go/bin/mkcert"

	UnixSSLCertsMakeCertRoot = "/etc/ssl/certs/mkcert-root.pem"
	UnixLocalCACertificates  = "/usr/local/share/ca-certificates/mkcert-root.crt"
	UnixHomeMakeCertRoot     = ".local/share/mkcert/rootCA.pem"

	PowershellYes = "yes"
)

// IsMkcertInstalled checks if mkcert is available on the system.
// It checks PATH and common installation directories.

func IsMkcertInstalled() bool {
	if path, err := exec.LookPath(MkCertBinary); err == nil {
		cmd := exec.Command(path, "-version")
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// 2) Common locations
	home, _ := os.UserHomeDir()
	commonPaths := []string{
		UnixUsrLocalBinMkCert,
		UnixUsrBinMkCert,
		UnixOptHomebrewBinMkCert,
		filepath.Join(home, UnixGoBinMkCert),
		filepath.Join(home, UnixLocalBinMkCert),
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
	if os.Getenv(EnvHome) == "" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			_ = os.Setenv(EnvHome, u.HomeDir)
			changed = true
		}
	}

	// USER + LOGNAME
	if os.Getenv(EnvUser) == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			_ = os.Setenv(EnvUser, u.Username)
			changed = true
		}
	}
	if os.Getenv(EnvLogName) == "" && os.Getenv(EnvUser) != "" {
		_ = os.Setenv(EnvLogName, os.Getenv(EnvUser))
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
	if os.Getenv(EnvHome) == "" {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			env = append(env, EnvUser+"="+u.Username)
		}
	}

	// Ensure USER/LOGNAME are set.
	if os.Getenv(EnvUser) == "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			env = append(env, EnvUser+"="+u.Username)
		}
	}
	if os.Getenv(EnvLogName) == "" {
		if os.Getenv(EnvUser) != "" {
			env = append(env, EnvLogName+"="+os.Getenv(EnvUser))
		}
	}

	env = append(env, extra...)
	return env
}

// MkcertDefaultCAROOT returns mkcert's own default CA root directory (as mkcert reports it).
// Works even under services because mkcertEnv guarantees HOME/USER.
func MkcertDefaultCAROOT(mkcertPath string) (string, error) {
	cmd := exec.Command(mkcertPath, MkCertCAROOTFlag)
	cmd.Env = mkcertEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", woos.ErrMkCertCAROOTFail, strings.TrimSpace(string(out)))
	}
	caroot := strings.TrimSpace(string(out))
	if caroot == "" {
		return "", woos.ErrMkCertEmptyCAROOT
	}
	return filepath.Clean(caroot), nil
}

// IsMkcertRootPresent checks if rootCA.pem exists inside mkcert's default CAROOT.
func IsMkcertRootPresent(mkcertPath string) bool {
	caroot, err := MkcertDefaultCAROOT(mkcertPath)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(caroot, MkCertCAROOTFlag))
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
		cmd := exec.Command("security", "find-certificate", "-c", MkCertDefaultCAName)
		return cmd.Run() == nil

	case woos.Linux:
		// Linux is distro-dependent. We check common trust store paths.
		paths := []string{
			UnixSSLCertsMakeCertRoot,
			UnixLocalCACertificates,
			filepath.Join(os.Getenv(EnvHome), UnixHomeMakeCertRoot),
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
		return err == nil && strings.Contains(strings.ToLower(string(out)), PowershellYes)
	}
	return false
}
