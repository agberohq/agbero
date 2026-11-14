package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/prompter"
	"github.com/olekukonko/zero"
)

const maxPassphraseFileBytes = 4 << 10

// Config controls how secrets.Open initialises the Keeper store.
type Config struct {
	DataDir     expect.Folder
	Logger      *ll.Logger
	Setting     *alaye.Keeper
	Interactive bool
	// AllowLocked returns an opened-but-locked store when a configured
	// passphrase source is unavailable. Service startup uses this to expose
	// the local unlock endpoint instead of exiting.
	AllowLocked bool

	DisableAutoLock bool
}

// Open opens or creates the Keeper store according to kfg.
// It attempts passphrase resolution in the following order:
// systemd CREDENTIALS_DIRECTORY/keeper_passphrase
// alaye.Keeper.Passphrase (config file value, may itself be a secret ref)
// alaye.Keeper.PassphraseFile (legacy existing deployments)
// AGBERO_KEEPER_PASSPHRASE environment variable
// AGBERO_PASSPHRASE environment variable (deprecated alias)
// Interactive prompt — only when kfg.Interactive == true
//
// If the store remains locked after all attempts and kfg.Interactive is false
// the unlocked store is still returned; the caller must check store.IsLocked()
// and decide whether to fail fast (server) or proceed (library embed).
func Open(kfg Config) (*keeper.Keeper, error) {
	var (
		store *keeper.Keeper
		err   error
	)

	if kfg.Logger == nil {
		kfg.Logger = ll.New("secrets").Disable()
	} else {
		kfg.Logger = kfg.Logger.Namespace("secrets")
	}

	if err = kfg.DataDir.Make(true); err != nil {
		return nil, fmt.Errorf("failed to initialize data directory: %w", err)
	}

	dbPath := filepath.Join(kfg.DataDir.Path(), def.DefaultKeeperName)

	kConfig := keeper.Config{
		DBPath:      dbPath,
		Logger:      kfg.Logger,
		EnableAudit: true,
	}

	if kfg.Setting != nil {
		if !kfg.Setting.Logging.Active() {
			kConfig.Logger = kfg.Logger.Disable()
		}

		if kfg.Setting.Enabled.Inactive() {
			kfg.Logger.Warn("keeper is marked disabled in config but is a compulsory component — proceeding")
		}

		if !kfg.DisableAutoLock && kfg.Setting.AutoLock > 0 {
			kConfig.AutoLockInterval = kfg.Setting.AutoLock.StdDuration()
		}

		if kfg.Setting.Audit.Active() {
			kConfig.EnableAudit = true
		}
	}

	isNew := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		isNew = true
	}

	if isNew {
		store, err = keeper.New(kConfig)
	} else {
		store, err = keeper.Open(kConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open keeper database: %w", err)
	}

	if !store.IsLocked() {
		return store, nil
	}

	passphrase, passErr := resolvePassphraseChecked(kfg.Setting)
	if passErr != nil {
		if kfg.AllowLocked {
			kfg.Logger.Warn("keeper passphrase source unavailable; starting locked", "err", passErr)
			return store, nil
		}
		store.Close()
		return nil, passErr
	}

	if passphrase != "" {
		kfg.Logger.Debug("attempting to unlock keeper with configured passphrase")
		passBytes := []byte(passphrase)
		unlockErr := store.Unlock(passBytes)
		zero.Bytes(passBytes)

		if unlockErr == nil {
			kfg.Logger.Info("keeper unlocked successfully using configured passphrase")
			return store, nil
		}

		store.Close()
		return nil, fmt.Errorf("failed to unlock keeper database: %w", unlockErr)
	}

	if store.IsLocked() && kfg.Interactive {
		kfg.Logger.Debug("keeper locked, prompting user for passphrase")

		var result *prompter.Result
		var promptErr error

		if isNew {
			result, promptErr = prompter.NewSecret("Create Keeper Master Passphrase",
				prompter.WithRequired(true),
			).WithConfirmation("Confirm Passphrase").Run()
		} else {
			result, promptErr = prompter.NewSecret("Keeper Passphrase",
				prompter.WithRequired(true),
			).Run()
		}

		if promptErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to prompt for passphrase: %w", promptErr)
		}

		pass := result.Bytes()
		unlockErr := store.Unlock(pass)

		zero.Bytes(pass)
		result.Zero()

		if unlockErr != nil {
			store.Close()
			return nil, fmt.Errorf("failed to unlock keeper database: %w", unlockErr)
		}
		kfg.Logger.Info("keeper unlocked via interactive prompt")
		return store, nil
	}

	if store.IsLocked() {
		kfg.Logger.Debug("keeper remains locked — caller must unlock via store.Unlock()")
	}
	return store, nil
}

// MustOpen opens the keeper and returns an error if the store is still locked
// after all unlock attempts.  Useful for non-interactive server startup paths
// that require a fully unlocked store before proceeding.
func MustOpen(kfg Config) (*keeper.Keeper, error) {
	store, err := Open(kfg)
	if err != nil {
		return nil, err
	}
	if store.IsLocked() {
		store.Close()
		return nil, fmt.Errorf("keeper is locked. Set AGBERO_KEEPER_PASSPHRASE (or the deprecated AGBERO_PASSPHRASE), configure keeper.passphrase_file, or set keeper.passphrase in agbero.hcl")
	}
	return store, nil
}

func resolvePassphrase(cfg *alaye.Keeper) string {
	p, _ := resolvePassphraseChecked(cfg)
	return p
}

// resolvePassphraseChecked resolves the passphrase and reports hard failures
// (unreadable or insecure passphrase_file) instead of silently falling back.
func resolvePassphraseChecked(cfg *alaye.Keeper) (string, error) {
	// systemd credentials are deliberately preferred for services. Both
	// LoadCredential and LoadCredentialEncrypted expose the same decrypted
	// file here; use Encrypted in production so the source is not plaintext.
	if dir := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY")); dir != "" {
		for _, name := range []string{"keeper_passphrase", "keeper-passphrase"} {
			if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				if pass := strings.TrimRight(string(data), "\r\n"); pass != "" {
					return pass, nil
				}
			}
		}
	}
	if cfg != nil {
		if p := cfg.Passphrase.String(); p != "" {
			return p, nil
		}
		if cfg.PassphraseFile != "" {
			return readPassphraseFile(cfg.PassphraseFile)
		}
	}
	if p := os.Getenv("AGBERO_KEEPER_PASSPHRASE"); p != "" {
		return p, nil
	}
	if p := os.Getenv("AGBERO_PASSPHRASE"); p != "" {
		return p, nil
	}
	return "", nil
}

// readPassphraseFile reads a service passphrase file. It rejects symlinks,
// non-regular files, group-writable/executable modes, and world-accessible
// modes. Group-read is allowed so root:agbero 0640 works when the service
// runs as agbero.
func readPassphraseFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("read keeper.passphrase_file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("keeper.passphrase_file %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("keeper.passphrase_file %q must be a regular file", path)
	}
	if runtime.GOOS != def.Windows {
		perm := info.Mode().Perm()
		if perm&0007 != 0 {
			return "", fmt.Errorf("keeper.passphrase_file %q is accessible by other users (mode %04o); use 0600 or 0640", path, perm)
		}
		if perm&0030 != 0 {
			return "", fmt.Errorf("keeper.passphrase_file %q is group-writable/executable (mode %04o); use 0600 or 0640", path, perm)
		}
	}
	if info.Size() > maxPassphraseFileBytes {
		return "", fmt.Errorf("keeper.passphrase_file %q is larger than %d bytes", path, maxPassphraseFileBytes)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read keeper.passphrase_file %q: %w", path, err)
	}
	pass := strings.TrimRight(string(data), "\r\n")
	if strings.ContainsRune(pass, '\x00') {
		return "", fmt.Errorf("keeper.passphrase_file %q contains a NUL byte", path)
	}
	if pass == "" {
		return "", fmt.Errorf("keeper.passphrase_file %q is empty", path)
	}
	return pass, nil
}

// PassphraseAvailable reports whether a real passphrase is available after
// fully resolving any secret references (e.g. "env.AGBERO_KEEPER_PASSPHRASE")
// or a passphrase file. Use this instead of checking the raw config string,
// which is non-empty even when the referenced env var is unset.
func PassphraseAvailable(cfg *alaye.Keeper) bool {
	p, err := resolvePassphraseChecked(cfg)
	return err == nil && p != ""
}
