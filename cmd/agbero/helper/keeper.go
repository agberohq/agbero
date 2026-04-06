package helper

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	keeperlib "github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keepcmd"
	"github.com/olekukonko/zero"
)

// Keeper handles all `agbero keeper` CLI commands.
type Keeper struct {
	p *Helper
}

// uiOutput implements keepcmd.Output by delegating to agbero's ui.UI.
type uiOutput struct{ u *ui.UI }

func (o *uiOutput) Table(headers []string, rows [][]string) {
	o.u.Println("")
	o.u.Table(headers, rows)
}
func (o *uiOutput) KeyValue(label, value string) { o.u.Println(""); o.u.KeyValue(label, value) }
func (o *uiOutput) Success(msg string)           { o.u.SuccessLine(msg) }
func (o *uiOutput) Info(msg string)              { o.u.InfoLine(msg) }
func (o *uiOutput) Error(msg string)             { o.u.WarnLine(msg) }

// openStore opens an unlocked keeper.Keeper.
//
// Resolution order (same as service.go::preflightCheck):
// cfg.Passphrase in agbero.hcl (any expect.Value — env., vault://, b64. …)
// AGBERO_PASSPHRASE environment variable
// Interactive prompt — used in run mode; never in service mode.
func (k *Keeper) openStore(configPath string) *keeperlib.Keeper {
	global, err := loadGlobal(configPath)
	if err != nil {
		k.p.Logger.Fatal("failed to load config: ", err)
	}

	dataDir := global.Storage.DataDir
	if dataDir == "" {
		ctx := setup.NewContext(k.p.Logger)
		dataDir = ctx.Paths.DataDir.Path()
	}

	store, openErr := secrets.OpenStore(dataDir, &global.Security.Keeper, k.p.Logger)
	if openErr != nil {
		k.p.Logger.Fatal("failed to open keeper: ", openErr)
	}

	if store.IsLocked() {
		u := ui.New()
		result, promptErr := u.PasswordRequired("Keeper passphrase")
		if promptErr != nil {
			store.Close()
			k.p.Logger.Fatal("passphrase required: ", promptErr)
		}
		pass := result.Bytes()
		unlockErr := store.Unlock(pass)
		zero.Bytes(pass)
		result.Zero()
		if unlockErr != nil {
			store.Close()
			k.p.Logger.Fatal("invalid passphrase: ", unlockErr)
		}
	}

	return store
}

// cmds returns keepcmd.Commands wired to an already-open store.
// Used only by REPL where one store is shared across many operations.
func (k *Keeper) cmds(store *keeperlib.Keeper) *keepcmd.Commands {
	return &keepcmd.Commands{
		Store:   func() (*keeperlib.Keeper, error) { return store, nil },
		Out:     &uiOutput{u: ui.New()},
		NoClose: true,
	}
}

func (k *Keeper) List(configPath string) {
	store := k.openStore(configPath)
	defer store.Close()
	if err := k.cmds(store).List(); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Get(configPath, key string) {
	store := k.openStore(configPath)
	defer store.Close()
	// Normalise key — accept vault://, ss://, or plain ns/key.
	key = normaliseKey(key)
	if err := k.cmds(store).Get(key); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Set(configPath, key, value string, asB64 bool, fromFile string) {
	store := k.openStore(configPath)
	defer store.Close()

	u := ui.New()

	// Normalise and resolve the key so vault://, ss://, plain ns/key all work.
	rawKey := key
	key = normaliseKey(key)

	// Auto-provision the bucket if it does not exist yet.
	if err := store.EnsureBucket(key); err != nil {
		k.p.Logger.Fatal("failed to prepare bucket: ", err)
	}

	if err := k.cmds(store).Set(key, value, keepcmd.SetOptions{Base64: asB64, FromFile: fromFile}); err != nil {
		k.p.Logger.Fatal(err)
	}

	// Show the canonical reference the operator should use in agbero.hcl.
	// If they supplied a scheme prefix, preserve it; otherwise default to ss://.
	ref := rawKey
	if !strings.Contains(rawKey, "://") {
		ref = "ss://" + key
	}
	u.InfoLine("reference in agbero.hcl as:  " + ref)
}

func (k *Keeper) Delete(configPath, key string, force bool) {
	if key == "" {
		k.p.Logger.Fatal("key is required")
	}
	if !force {
		u := ui.New()
		confirm, err := u.Confirm(fmt.Sprintf("Delete %q from the keeper?", key), "This cannot be undone.")
		if err != nil || !confirm {
			fmt.Println("aborted")
			return
		}
	}
	store := k.openStore(configPath)
	defer store.Close()
	key = normaliseKey(key)
	if err := k.cmds(store).Delete(key); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Backup(configPath, dest string) {
	store := k.openStore(configPath)
	defer store.Close()
	if err := k.cmds(store).Backup(keepcmd.BackupOptions{Dest: dest}); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Status(configPath string) {
	store := k.openStore(configPath)
	defer store.Close()
	if err := k.cmds(store).Status(); err != nil {
		k.p.Logger.Fatal(err)
	}
}

// normaliseKey strips a scheme prefix and returns the plain namespace/key
// form that keeper's Set/Get/Delete methods expect.
// vault://admin/totp/alice  →  admin/totp/alice
// ss://prod/db_pass         →  prod/db_pass
// prod/db_pass              →  prod/db_pass  (unchanged)
func normaliseKey(key string) string {
	e := expect.NewRaw(key)
	if ref, err := e.SecretRef(); err == nil {
		return ref.WithoutScheme()
	}
	return key
}

// Rotate prompts for the current passphrase (via openStore), then prompts
// for a new passphrase and re-encrypts everything under it.
func (k *Keeper) Rotate(configPath string) {
	// openStore prompts for and verifies the current passphrase.
	// Lock it again so Rotate can re-derive the master key from scratch.
	store := k.openStore(configPath)
	defer store.Close()
	store.Lock() //nolint:errcheck

	u := ui.New()
	newResult, err := u.PasswordConfirm("New passphrase")
	if err != nil {
		k.p.Logger.Fatal("new passphrase required: ", err)
	}
	newPass := newResult.Bytes()
	defer newResult.Zero()

	if err := store.Rotate(newPass); err != nil {
		k.p.Logger.Fatal("rotation failed: ", err)
	}

	zero.Bytes(newPass)
	ui.New().SuccessLine("passphrase rotated — update keeper.passphrase in agbero.hcl if stored there")
}

// REPL opens an interactive keeper session.
//
// If the store is locked, the passphrase is prompted transparently — the
// operator never sees a "keeper is locked" error. Once unlocked the session
// stays open until the operator types exit or quit (or sends EOF).
//
// Commands available inside the REPL:
//
//	list                  — list all keys
//	get <key>             — retrieve a value
//	set <key> <value>     — store a plain-text value
//	set <key> --file <f>  — store a file's contents
//	delete <key>          — delete a key (confirms interactively)
//	delete <key> --force  — delete without confirmation
//	status                — show locked/unlocked state
//	help                  — show this help
//	exit | quit           — leave the REPL
func (k *Keeper) REPL(configPath string) {
	store := k.openStore(configPath)
	defer store.Close()

	u := ui.New()
	u.InfoLine("Keeper REPL — type 'help' for commands, 'exit' to quit")
	u.Blank()

	cmds := &keepcmd.Commands{
		Store:   func() (*keeperlib.Keeper, error) { return store, nil },
		Out:     &uiOutput{u: u},
		NoClose: true,
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("keeper> ")
		if !scanner.Scan() {
			// EOF (Ctrl-D) — exit cleanly.
			fmt.Println()
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		switch cmd {
		case "exit", "quit":
			u.InfoLine("bye")
			return

		case "help":
			k.replHelp()

		case "status":
			if err := cmds.Status(); err != nil {
				u.WarnLine(err.Error())
			}

		case "list", "ls":
			if err := cmds.List(); err != nil {
				u.WarnLine(err.Error())
			}

		case "get":
			if len(args) == 0 {
				u.WarnLine("usage: get <key>")
				continue
			}
			if err := cmds.Get(normaliseKey(args[0])); err != nil {
				u.WarnLine(err.Error())
			}

		case "set":
			// set <key> <value>
			// set <key> --file <path>
			if len(args) < 1 {
				u.WarnLine("usage: set <key> <value>  |  set <key> --file <path>")
				continue
			}
			key := args[0]
			opts := keepcmd.SetOptions{}
			value := ""
			rest := args[1:]
			for i := 0; i < len(rest); i++ {
				switch rest[i] {
				case "--file", "-f":
					if i+1 < len(rest) {
						opts.FromFile = rest[i+1]
						i++
					}
				default:
					value = strings.Join(rest[i:], " ")
					i = len(rest) // consumed all
				}
			}
			if opts.FromFile == "" && value == "" {
				u.WarnLine("usage: set <key> <value>  |  set <key> --file <path>")
				continue
			}
			// Resolve the key via expect so vault://, ss:// etc. all work.
			key = normaliseKey(key)
			if err := store.EnsureBucket(key); err != nil {
				u.WarnLine("bucket error: " + err.Error())
				continue
			}
			if err := cmds.Set(key, value, opts); err != nil {
				u.WarnLine(err.Error())
			}

		case "delete", "del", "rm":
			if len(args) == 0 {
				u.WarnLine("usage: delete <key> [--force]")
				continue
			}
			key := normaliseKey(args[0])
			force := len(args) > 1 && (args[1] == "--force" || args[1] == "-f")
			if !force {
				ok, err := u.Confirm(fmt.Sprintf("Delete %q?", key), "This cannot be undone.")
				if err != nil || !ok {
					u.InfoLine("aborted")
					continue
				}
			}
			if err := cmds.Delete(key); err != nil {
				u.WarnLine(err.Error())
			}

		default:
			u.WarnLine(fmt.Sprintf("unknown command %q — type 'help' for available commands", cmd))
		}
	}
}

func (k *Keeper) replHelp() {
	u := ui.New()
	u.Blank()
	u.InfoLine("Keeper REPL commands:")
	u.Blank()
	u.KeyValue("list", "list all keys in the store")
	u.KeyValue("get <key>", "retrieve a secret value")
	u.KeyValue("set <key> <value>", "store a plain-text secret")
	u.KeyValue("set <key> --file <path>", "store a file's contents as a secret")
	u.KeyValue("delete <key>", "delete a secret (prompts for confirmation)")
	u.KeyValue("delete <key> --force", "delete without confirmation prompt")
	u.KeyValue("status", "show whether the store is locked or unlocked")
	u.KeyValue("help", "show this help")
	u.KeyValue("exit / quit", "leave the REPL")
	u.Blank()
	u.InfoLine("Keys accept any scheme: ss://ns/key, vault://ns/key, or plain ns/key")
	u.Blank()
}
