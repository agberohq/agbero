package tlss

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// IsMkcertInstalled checks if mkcert is available on the system.
// It checks the PATH and common installation directories.
//
// Refactored from (ci *Installer) method to standalone function
// so it can be used during server startup.
func IsMkcertInstalled() bool {
	// 1. Check PATH
	if path, err := exec.LookPath("mkcert"); err == nil {
		// Verify it's actually mkcert and works
		cmd := exec.Command(path, "-version")
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// 2. Check common installation locations
	// We use UserHomeDir for better cross-platform compatibility than GetEnv("HOME")
	home, _ := os.UserHomeDir()

	commonPaths := []string{
		"/usr/local/bin/mkcert",
		"/usr/bin/mkcert",
		"/opt/homebrew/bin/mkcert",
		filepath.Join(home, "go", "bin", "mkcert"),
		filepath.Join(home, ".local", "bin", "mkcert"),
	}

	// Windows specific common paths
	if runtime.GOOS == "windows" {
		commonPaths = append(commonPaths,
			filepath.Join(home, "scoop", "shims", "mkcert.exe"),
			filepath.Join(home, "choco", "bin", "mkcert.exe"),
		)
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

func IsCARootInstalled() bool {
	// Platform-specific checks for CA installation
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "find-certificate", "-c", "mkcert")
		return cmd.Run() == nil
	case "linux":
		paths := []string{
			"/etc/ssl/certs/mkcert-root.pem",
			"/usr/local/share/ca-certificates/mkcert-root.crt",
			filepath.Join(os.Getenv("HOME"), ".local/share/mkcert/rootCA.pem"),
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				return true
			}
		}
	case "windows":
		psCmd := `Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -match "mkcert"} | Select-Object -First 1`
		cmd := exec.Command("powershell", "-Command", psCmd)
		output, err := cmd.Output()
		return err == nil && len(strings.TrimSpace(string(output))) > 0
	}
	return false
}
