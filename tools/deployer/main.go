// Command deployer is Agbero's local build-and-deploy helper.
//
// It is intentionally outside cmd/: it is an operator tool, not a shipped
// Agbero subcommand. The Makefile invokes it with `go run ./tools/deployer`.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"charm.land/huh/v2"
)

type options struct {
	host       string
	user       string
	mode       string
	path       string
	service    string
	health     string
	goos       string
	goarch     string
	sudo       bool
	yes        bool
	test       bool
	noRestart  bool
	noHealth   bool
	noRollback bool
	dryRun     bool
	keepOld    bool
}

type remoteState struct {
	OS      string
	Arch    string
	Binary  string
	Home    string
	Unit    string
	Active  string
	Exec    string
	PID     string
	UID     string
	Config  bool
	Control string
	HasCurl bool
	HasWget bool
}

func main() {
	var o options
	flag.StringVar(&o.host, "host", "", "SSH host or host alias (e.g. host.example)")
	flag.StringVar(&o.user, "user", "root", "SSH user")
	flag.StringVar(&o.mode, "mode", "auto", "auto, update, install, or service")
	flag.StringVar(&o.path, "path", "", "remote binary path (default: detected or /usr/local/bin/agbero)")
	flag.StringVar(&o.service, "service", "auto", "auto, agbero, or none")
	flag.StringVar(&o.health, "health", "http://127.0.0.1:9090/healthz", "health URL checked on the server")
	flag.StringVar(&o.goos, "os", "", "target GOOS (default: detected; fallback linux)")
	flag.StringVar(&o.goarch, "arch", "", "target GOARCH (default: detected; fallback amd64)")
	flag.BoolVar(&o.yes, "yes", false, "skip confirmations")
	flag.BoolVar(&o.test, "test", false, "run tests before building")
	flag.BoolVar(&o.noRestart, "no-restart", false, "replace the binary but do not restart")
	flag.BoolVar(&o.noHealth, "no-health", false, "skip the HTTP health check")
	flag.BoolVar(&o.noRollback, "no-rollback", false, "do not restore the previous binary on failure")
	flag.BoolVar(&o.dryRun, "dry-run", false, "print actions without applying them")
	flag.BoolVar(&o.keepOld, "keep-previous", true, "keep the previous binary until the next deploy")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "deploy:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if !isTTY() && o.host == "" {
		return errors.New("--host is required when stdin is not a TTY")
	}
	if o.host == "" {
		if err := huh.NewInput().Title("Server").Description("SSH host or host alias").Value(&o.host).Run(); err != nil {
			return err
		}
	}
	if strings.TrimSpace(o.host) == "" {
		return errors.New("host is required")
	}
	target := sshTarget(o.host, o.user)

	fmt.Printf("Preflight %s\n", target)
	remote, err := preflight(target, o.sudo)
	if err != nil {
		return err
	}
	printState(remote)

	if o.mode == "" || o.mode == "auto" {
		o.mode, err = chooseMode(remote, o.yes)
		if err != nil {
			return err
		}
	}
	if o.mode == "service" {
		o.mode = "repair"
	}
	switch o.mode {
	case "push", "update", "install", "repair":
	default:
		return fmt.Errorf("unknown mode %q (want push, update, install, or repair)", o.mode)
	}
	if (o.mode == "update" || o.mode == "repair") && remote.Binary == "" {
		return errors.New("no remote agbero binary found; use --mode install")
	}
	if o.mode == "push" {
		o.noRestart = true
		o.noHealth = true
		o.noRollback = true
	}
	binaryPath := o.path
	if binaryPath == "" {
		binaryPath = remote.Binary
	}
	if binaryPath == "" {
		binaryPath = "/usr/local/bin/agbero"
	}

	if o.mode == "repair" {
		if err := runServiceOnly(target, remote, binaryPath, o); err != nil {
			return err
		}
		return nil
	}
	if o.mode == "install" && remote.Binary != "" && !o.yes {
		ok, err := confirm(fmt.Sprintf("%s already exists. Replace it?", remote.Binary))
		if err != nil || !ok {
			return errors.New("aborted")
		}
	}

	if o.test {
		if err := runTests(); err != nil {
			return err
		}
	}

	version, commit, date, err := gitVersion()
	if err != nil {
		return err
	}
	goos, goarch := o.goos, o.goarch
	if goos == "" {
		goos = mapOS(remote.OS)
	}
	if goarch == "" {
		goarch = mapArch(remote.Arch)
	}
	artifact, err := buildBinary(goos, goarch, version, commit, date, o.dryRun)
	if err != nil {
		return err
	}
	fmt.Printf("Built %s (%s/%s)\n", artifact, goos, goarch)

	if o.dryRun {
		fmt.Printf("[dry-run] would upload %s to %s\n", artifact, binaryPath)
		return nil
	}

	tmp := filepath.Join(filepath.Dir(binaryPath), ".agbero.new")
	if err := upload(artifact, target, tmp); err != nil {
		return err
	}
	sum, err := fileSHA(artifact)
	if err != nil {
		return err
	}
	if err := remoteChecksum(target, tmp, sum, o.sudo); err != nil {
		return err
	}

	if !o.yes {
		ok, err := confirm(fmt.Sprintf("Install %s on %s?", version, target))
		if err != nil || !ok {
			return errors.New("aborted")
		}
	}

	hadOld := remote.Binary != ""
	if err := installRemote(target, tmp, binaryPath, sum, o.sudo); err != nil {
		return err
	}

	if o.mode == "install" && !remote.Config {
		fmt.Printf("No config at %s/agbero.hcl yet.\n", remote.Home)
		if isTTY() {
			ok, err := confirm("Run `agbero init` on the server now?")
			if err != nil {
				return err
			}
			if ok {
				if err := sshInteractive(target, sudo(o.sudo, binaryPath)+" init"); err != nil {
					return fmt.Errorf("agbero init: %w", err)
				}
			} else {
				fmt.Printf("Run later: ssh -t %s '%s init'\n", target, sudo(o.sudo, binaryPath))
			}
		} else {
			fmt.Printf("Run later: ssh -t %s '%s init'\n", target, sudo(o.sudo, binaryPath))
		}
	}

	if o.mode == "repair" || o.mode == "install" {
		if remote.Unit == "" && strings.EqualFold(o.service, "auto") {
			if err := sshScript(target, sudo(o.sudo, binaryPath)+" service install", false); err != nil {
				fmt.Fprintf(os.Stderr, "warning: service install failed: %v\n", err)
			} else if remote, err = preflight(target, o.sudo); err != nil {
				fmt.Fprintf(os.Stderr, "warning: service re-check failed: %v\n", err)
			}
		}
	}

	restarted := false
	if !o.noRestart {
		var err error
		restarted, err = restartRemote(target, remote, binaryPath, o.service, o.sudo)
		if err != nil {
			if hadOld && !o.noRollback {
				_ = rollback(target, remote, o.sudo)
			}
			return err
		}
		if !restarted {
			fmt.Println("Binary installed; no service or managed process was restarted.")
			if remote.PID != "" {
				fmt.Printf("The running process is still the old binary; restart it manually.\n")
			}
		} else if r2, rerr := preflight(target, o.sudo); rerr == nil {
			remote = r2
		}
	}

	if !o.noHealth && !o.noRestart && restarted {
		if err := healthRemote(target, o.health, binaryPath, version, remote); err != nil {
			if hadOld && !o.noRollback {
				fmt.Println("Health check failed; rolling back…")
				_ = rollback(target, remote, o.sudo)
			}
			return err
		}
	}

	fmt.Printf("Deployed %s (%s/%s)\n", version, goos, goarch)
	fmt.Printf("Path: %s\n", binaryPath)
	if hadOld && o.keepOld {
		fmt.Printf("Previous binary: %s.prev\n", binaryPath)
	}
	return nil
}

func chooseMode(r remoteState, yes bool) (string, error) {
	mode := "update"
	if r.Binary == "" {
		mode = "install"
	}
	if !isTTY() || yes {
		return mode, nil
	}
	err := huh.NewSelect[string]().
		Title("Deployment").
		Description("What should be applied to this server?").
		Options(
			huh.NewOption("Push binary only (no restart)", "push"),
			huh.NewOption("Update existing installation", "update"),
			huh.NewOption("Fresh install", "install"),
			huh.NewOption("Repair service only", "repair"),
		).
		Value(&mode).Run()
	return mode, err
}

func confirm(title string) (bool, error) {
	var ok bool
	err := huh.NewConfirm().Title(title).Affirmative("Yes").Negative("No").Value(&ok).Run()
	return ok, err
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func sshTarget(host, user string) string {
	if user == "" || strings.Contains(host, "@") {
		return host
	}
	return user + "@" + host
}

func mapOS(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "darwin":
		return "darwin"
	case "windows", "mingw", "msys":
		return "windows"
	default:
		return "linux"
	}
}

func mapArch(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv7":
		return "arm"
	default:
		if s == "" {
			return "amd64"
		}
		return s
	}
}

func runServiceOnly(target string, remote remoteState, binaryPath string, o options) error {
	if remote.Binary == "" {
		return errors.New("no remote agbero binary found; install the binary first")
	}
	if remote.Unit == "" {
		if err := sshScript(target, sudo(o.sudo, binaryPath)+" service install", true); err != nil {
			return fmt.Errorf("service install: %w", err)
		}
		if r, err := preflight(target, o.sudo); err == nil {
			remote = r
		}
	}
	if !o.yes {
		ok, err := confirm("Restart the agbero service?")
		if err != nil || !ok {
			return errors.New("aborted")
		}
	}
	restarted, err := restartRemote(target, remote, binaryPath, o.service, o.sudo)
	if err != nil {
		return err
	}
	if !restarted {
		return errors.New("no systemd unit found; cannot restart the service")
	}
	if r2, rerr := preflight(target, o.sudo); rerr == nil {
		remote = r2
	}
	if !o.noHealth {
		return healthRemote(target, o.health, binaryPath, "", remote)
	}
	return nil
}

func gitVersion() (version, commit, date string, err error) {
	version = "dev"
	commit = "unknown"
	date = time.Now().UTC().Format(time.RFC3339)
	if v, e := git("describe", "--tags", "--always", "--dirty"); e == nil {
		version = v
	}
	if c, e := git("rev-parse", "--short", "HEAD"); e == nil {
		commit = c
	}
	return version, commit, date, nil
}

func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func runTests() error {
	fmt.Println("Running tests…")
	cmd := exec.Command("go", "test", "./...")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tests failed: %w", err)
	}
	return nil
}

func buildBinary(goos, goarch, version, commit, date string, dry bool) (string, error) {
	if err := os.MkdirAll("dist", 0755); err != nil {
		return "", err
	}
	out := filepath.Join("dist", fmt.Sprintf("agbero-%s-%s", goos, goarch))
	if goos == "windows" {
		out += ".exe"
	}
	ld := fmt.Sprintf("-s -w -X github.com/agberohq/agbero/internal/core/woos.Version=%s -X github.com/agberohq/agbero/internal/core/woos.Commit=%s -X github.com/agberohq/agbero/internal/core/woos.Date=%s", version, commit, date)
	fmt.Printf("Building %s/%s %s…\n", goos, goarch, version)
	if dry {
		fmt.Printf("[dry-run] CGO_ENABLED=0 GOOS=%s GOARCH=%s go build -trimpath -ldflags=%q -o %s ./cmd/agbero\n", goos, goarch, ld, out)
		return out, nil
	}
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ld, "-o", out, "./cmd/agbero")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build failed: %w", err)
	}
	return out, nil
}

func fileSHA(path string) (string, error) {
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

func preflight(target string, useSudo bool) (remoteState, error) {
	script := `set -eu
os=$(uname -s 2>/dev/null || true)
arch=$(uname -m 2>/dev/null || true)
bin=$(command -v agbero 2>/dev/null || true)
if [ -n "$bin" ]; then bin=$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin"); fi
home=""
if command -v agbero >/dev/null 2>&1; then home=$(agbero home 2>/dev/null | tail -n 1 || true); fi
unit=""
active=""
execstart=""
if command -v systemctl >/dev/null 2>&1; then
  unit=$(systemctl show -p FragmentPath --value agbero 2>/dev/null || true)
  active=$(systemctl is-active agbero 2>/dev/null || true)
  execstart=$(systemctl show -p ExecStart --value agbero 2>/dev/null || true)
fi
pid=$(pgrep -af '[a]gbero (run|serve)' 2>/dev/null | head -n 1 || true)
uid=$(id -u 2>/dev/null || true)
cfg=0; [ -n "$home" ] && [ -f "$home/agbero.hcl" ] && cfg=1
control=""
if [ -n "$home" ]; then control=$(find "$home" -maxdepth 3 -name keeper-control.json 2>/dev/null | head -n 1 || true); fi
curl=0; command -v curl >/dev/null 2>&1 && curl=1
wget=0; command -v wget >/dev/null 2>&1 && wget=1
printf 'OS=%s\nARCH=%s\nBINARY=%s\nHOME=%s\nUNIT=%s\nACTIVE=%s\nEXEC=%s\nPID=%s\nUID=%s\nCONFIG=%s\nCONTROL=%s\nCURL=%s\nWGET=%s\n' "$os" "$arch" "$bin" "$home" "$unit" "$active" "$execstart" "$pid" "$uid" "$cfg" "$control" "$curl" "$wget"`
	out, err := sshOutput(target, script)
	if err != nil {
		return remoteState{}, err
	}
	r := remoteState{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "OS":
			r.OS = v
		case "ARCH":
			r.Arch = v
		case "BINARY":
			r.Binary = v
		case "HOME":
			r.Home = v
		case "UNIT":
			r.Unit = v
		case "ACTIVE":
			r.Active = v
		case "EXEC":
			r.Exec = v
		case "PID":
			r.PID = v
		case "UID":
			r.UID = v
		case "CONFIG":
			r.Config = v == "1"
		case "CONTROL":
			r.Control = v
		case "CURL":
			r.HasCurl = v == "1"
		case "WGET":
			r.HasWget = v == "1"
		}
	}
	if r.UID != "0" {
		return r, fmt.Errorf("remote user is not root; use root SSH for deployment")
	}
	return r, nil
}

func printState(r remoteState) {
	fmt.Printf("Host:        %s/%s\n", r.OS, r.Arch)
	fmt.Printf("Binary:      %s\n", dash(r.Binary))
	fmt.Printf("Home:        %s\n", dash(r.Home))
	fmt.Printf("Config:      %t\n", r.Config)
	fmt.Printf("Service:     %s (%s)\n", dash(r.Unit), dash(r.Active))
	if r.Exec != "" {
		fmt.Printf("ExecStart:   %s\n", r.Exec)
	}
	if r.PID != "" {
		fmt.Printf("Process:     %s\n", r.PID)
	}
	fmt.Println()
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func sshOutput(target, script string) (string, error) {
	cmd := exec.Command("ssh", target, "sh -s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssh %s: %w", target, err)
	}
	return string(out), nil
}

func sshScript(target, script string, interactive bool) error {
	args := []string{}
	if interactive {
		args = append(args, "-t")
	}
	args = append(args, target, script)
	cmd := exec.Command("ssh", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func sshInteractive(target, command string) error {
	return sshScript(target, command, true)
}

func upload(local, target, remotePath string) error {
	fmt.Printf("Uploading to %s:%s…\n", target, remotePath)
	cmd := exec.Command("scp", local, target+":"+remotePath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func remoteChecksum(target, path, want string, useSudo bool) error {
	script := fmt.Sprintf(`set -eu
if command -v sha256sum >/dev/null 2>&1; then h=$(sha256sum %s | awk '{print $1}'); else h=$(shasum -a 256 %s | awk '{print $1}'); fi
[ "$h" = %s ]
`, shellQuote(path), shellQuote(path), shellQuote(want))
	if err := sshScript(target, script, false); err != nil {
		return errors.New("checksum verification failed on server")
	}
	return nil
}

func installRemote(target, tmp, dest, sum string, useSudo bool) error {
	dir := filepath.Dir(dest)
	script := fmt.Sprintf(`set -eu
mkdir -p %s
if [ ! -f %s ]; then echo "uploaded binary missing" >&2; exit 1; fi
if command -v sha256sum >/dev/null 2>&1; then h=$(sha256sum %s | awk '{print $1}'); else h=$(shasum -a 256 %s | awk '{print $1}'); fi
[ "$h" = %s ] || { echo "remote checksum mismatch" >&2; exit 1; }
chmod 0755 %s
if [ -f %s ]; then cp -p %s %s.prev; fi
mv -f %s %s
`, shellQuote(dir), shellQuote(tmp), shellQuote(tmp), shellQuote(tmp), shellQuote(sum), shellQuote(tmp), shellQuote(dest), shellQuote(dest), shellQuote(dest), shellQuote(tmp), shellQuote(dest))
	return sshScript(target, script, false)
}

func restartRemote(target string, r remoteState, binary, service string, useSudo bool) (bool, error) {
	if r.Unit != "" && service != "none" {
		name := strings.TrimSuffix(filepath.Base(r.Unit), ".service")
		script := sudo(useSudo, "systemctl restart "+name)
		if err := sshScript(target, script, false); err != nil {
			return false, fmt.Errorf("service restart failed: %w", err)
		}
		return true, nil
	}
	if r.PID != "" {
		fmt.Printf("A manual process is running (%s); not killing it automatically.\n", r.PID)
		fmt.Println("Restart it yourself to load the new binary.")
		return false, nil
	}
	return false, nil
}

func healthRemote(target, url, binaryPath, version string, remote remoteState) error {
	if remote.Control != "" {
		// The service is intentionally waiting for a manual Keeper unlock.
		// The binary is deployed; HTTP is not expected yet.
		fmt.Println("Service is running locked and waiting for `agbero keeper unlock`; health check deferred.")
		return nil
	}
	check := fmt.Sprintf(`set -eu
ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  if command -v curl >/dev/null 2>&1; then
    code=$(curl -sS -o /dev/null -w '%%{http_code}' --max-time 2 %s || true)
    if [ "$code" = "200" ]; then ok=1; break; fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -q -O /dev/null --timeout=2 %s; then ok=1; break; fi
  else
    ok=1
    break
  fi
  sleep 1
done
if [ "$ok" != "1" ]; then echo "health endpoint did not return 200" >&2; exit 1; fi
ver=$(%s --version 2>/dev/null | tail -n 1 || true)
printf 'VERSION=%%s\n' "$ver"
`, shellQuote(url), shellQuote(url), shellQuote(binaryPath))
	out, err := sshOutput(target, check)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	if version != "" && !strings.Contains(out, version) {
		return fmt.Errorf("version check failed: expected %q in %q", version, strings.TrimSpace(out))
	}
	fmt.Printf("Health check passed (%s)\n", strings.TrimSpace(out))
	return nil
}

func rollback(target string, r remoteState, useSudo bool) error {
	if r.Binary == "" {
		return nil
	}
	fmt.Println("Restoring previous binary…")
	script := fmt.Sprintf(`set -eu
if [ -f %s.prev ]; then mv -f %s.prev %s; fi
`, shellQuote(r.Binary), shellQuote(r.Binary), shellQuote(r.Binary))
	if err := sshScript(target, script, false); err != nil {
		return err
	}
	if r.Unit != "" {
		name := strings.TrimSuffix(filepath.Base(r.Unit), ".service")
		return sshScript(target, sudo(useSudo, "systemctl restart "+name), false)
	}
	return nil
}

func sudo(use bool, cmd string) string {
	if use {
		return "sudo -n " + cmd
	}
	return cmd
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
