package helper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	keeperlib "github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keepcmd"
	"github.com/olekukonko/zero"
)

type Keeper struct {
	p *Helper
}

type uiOutput struct{ u *ui.UI }

func (o *uiOutput) Table(headers []string, rows [][]string) {
	o.u.Render(func() { o.u.Table(headers, rows) })
}
func (o *uiOutput) KeyValue(label, value string) { o.u.Render(func() { o.u.KeyValue(label, value) }) }
func (o *uiOutput) Success(msg string)           { o.u.Render(func() { o.u.SuccessLine(msg) }) }
func (o *uiOutput) Info(msg string)              { o.u.Render(func() { o.u.InfoLine(msg) }) }
func (o *uiOutput) Error(msg string)             { o.u.Render(func() { o.u.WarnLine(msg) }) }

func (k *Keeper) cmds(store *keeperlib.Keeper) *keepcmd.Commands {
	return &keepcmd.Commands{
		Store:   func() (*keeperlib.Keeper, error) { return store, nil },
		Out:     &uiOutput{u: ui.New()},
		NoClose: true,
	}
}

// requireStore returns the injected store or fatals with a clear message.
// All Keeper CLI methods call this first so the error is consistent.
func (k *Keeper) requireStore() *keeperlib.Keeper {
	if k.p.Store == nil {
		k.p.UI().Abort("keeper store is not available — run 'agbero init' first or check AGBERO_KEEPER_PASSPHRASE / keeper.passphrase_file")
	}
	return k.p.Store
}

func (k *Keeper) Unlock(configPath string) {
	global, err := LoadGlobal(configPath)
	if err != nil {
		k.p.UI().Abort("load config: ", err)
	}
	dataDir := global.Storage.DataDir
	if !dataDir.IsSet() {
		k.p.UI().Abort("storage.data_dir is not configured")
	}
	if _, err := secrets.ReadControlFile(dataDir); err != nil {
		pidPath := dataDir.FilePath(def.DefaultPIDName)
		if pid, perr := os.ReadFile(pidPath); perr == nil && strings.TrimSpace(string(pid)) != "" {
			k.p.UI().Abortf("keeper unlock endpoint is not available (pid %s is running; it may already be unlocked or running an older binary). Restart with the current build and retry.", strings.TrimSpace(string(pid)))
		}
		k.p.UI().Abort("service is not running; start it with 'agbero service start' first, then retry: ", err)
	}
	k.p.UI().Start("Unlocking keeper")
	u := ui.New()
	result, err := u.PasswordRequired("Keeper passphrase")
	if err != nil {
		k.p.UI().Abort("read passphrase: ", err)
	}
	pass := result.Bytes()
	defer result.Zero()
	if err := secrets.UnlockControl(dataDir, pass); err != nil {
		zero.Bytes(pass)
		k.p.UI().Abort("unlock failed: ", err)
	}
	zero.Bytes(pass)
	k.p.UI().Done("Keeper unlocked")
}

func (k *Keeper) List(_ string) {
	store := k.requireStore()
	k.p.UI().Start("Reading keeper index")
	if err := k.cmds(store).List(); err != nil {
		k.p.UI().Abort(err)
	}
	k.p.UI().Done("Keeper index loaded")
}

func (k *Keeper) Get(_ string, key string) {
	store := k.requireStore()
	key = normaliseKey(key)
	k.p.UI().Start("Reading %s", key)
	if err := k.cmds(store).Get(key); err != nil {
		k.p.UI().Abort(err)
	}
	k.p.UI().Done("Secret retrieved")
}

// Make generates a random secret, stores it once, and prints it so the same
// value can be copied to another node's keeper.
func (k *Keeper) Make(_ string, key string, length int) {
	store := k.requireStore()
	if strings.TrimSpace(key) == "" {
		k.p.UI().Abort("key is required")
	}
	key = normaliseKey(key)
	if length <= 0 {
		length = 32
	}
	k.p.UI().Start("Generating secret for %s", key)
	if _, err := store.Get(key); err == nil {
		k.p.UI().Abortf("keeper key %q already exists; use 'keeper set' or 'keeper delete' first", key)
	}
	secret, err := security.NewPassword().Generate(length)
	if err != nil {
		k.p.UI().Abort("generate secret: ", err)
	}
	if err := store.EnsureBucket(key); err != nil {
		k.p.UI().Abort("failed to prepare bucket: ", err)
	}
	if err := store.Set(key, []byte(secret)); err != nil {
		k.p.UI().Abort("store secret: ", err)
	}
	k.p.UI().Done("Secret stored in keeper")
	u := ui.New()
	u.Render(func() {
		u.SecretBox("Generated secret — "+key, secret)
		u.InfoLine("reference in agbero.hcl as:  ss://" + key)
		u.InfoLine("stored in keeper; copy this value to the other node with 'keeper set " + key + " <value>'")
	})
}

func (k *Keeper) Set(_ string, key, value string, asB64 bool, fromFile string) {
	store := k.requireStore()

	u := ui.New()
	rawKey := key
	key = normaliseKey(key)
	k.p.UI().Start("Storing %s", key)

	if err := store.EnsureBucket(key); err != nil {
		k.p.UI().Abort("failed to prepare bucket: ", err)
	}

	if err := k.cmds(store).Set(key, value, keepcmd.SetOptions{Base64: asB64, FromFile: fromFile}); err != nil {
		k.p.UI().Abort(err)
	}
	k.p.UI().Done("Secret stored in keeper")

	ref := rawKey
	if !strings.Contains(rawKey, "://") {
		ref = "ss://" + normaliseKey(rawKey)
	}
	u.Render(func() {
		u.InfoLine("reference in agbero.hcl as:  " + ref)
	})
}

func (k *Keeper) Delete(_ string, key string, force bool) {
	if key == "" {
		k.p.UI().Abort("key is required")
	}
	if !force {
		u := ui.New()
		confirm, err := u.Confirm(fmt.Sprintf("Delete %q from the keeper?", key), "This cannot be undone.")
		if err != nil || !confirm {
			fmt.Println("aborted")
			return
		}
	}
	store := k.requireStore()
	key = normaliseKey(key)
	k.p.UI().Start("Deleting %s", key)
	if err := k.cmds(store).Delete(key); err != nil {
		k.p.UI().Abort(err)
	}
	k.p.UI().Done("Secret deleted")
}

func (k *Keeper) Backup(_ string, dest string) {
	store := k.requireStore()
	if err := k.cmds(store).Backup(keepcmd.BackupOptions{Dest: dest}); err != nil {
		k.p.UI().Abort(err)
	}
}

// Check reports whether the keeper is locked without prompting for a
// passphrase or mutating the store.
func (k *Keeper) Check(configPath string) {
	u := ui.New()
	global, err := LoadGlobal(configPath)
	if err != nil {
		k.p.UI().Abort("load config: ", err)
	}
	if address := strings.TrimSpace(global.Admin.Address); address != "" {
		if locked, ok := keeperStatus(address); ok {
			u.Render(func() {
				if locked {
					u.WarnLine("keeper is locked (service)")
				} else {
					u.SuccessLine("keeper is unlocked (service)")
				}
			})
			return
		}
	}

	dataDir := global.Storage.DataDir
	if !dataDir.IsSet() {
		dataDir = setup.NewContext(k.p.Logger).Paths.DataDir
	}
	if _, err := secrets.ReadControlFile(dataDir); err == nil {
		u.Render(func() { u.WarnLine("keeper is locked (service waiting for unlock)") })
		return
	}

	dbPath := filepath.Join(dataDir.Path(), def.DefaultKeeperName)
	if _, err := os.Stat(dbPath); err != nil {
		u.Render(func() { u.WarnLine("keeper database is not initialized") })
		return
	}
	store, err := secrets.Open(secrets.Config{
		DataDir:         dataDir,
		Setting:         &global.Security.Keeper,
		Logger:          k.p.Logger,
		Interactive:     false,
		AllowLocked:     true,
		DisableAutoLock: true,
	})
	if err != nil {
		k.p.UI().Abort("open keeper: ", err)
	}
	defer store.Close()
	u.Render(func() {
		if store.IsLocked() {
			u.WarnLine("keeper is locked")
		} else {
			u.SuccessLine("keeper is unlocked")
		}
	})
}

func keeperStatus(address string) (bool, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return false, false
	}
	if strings.HasPrefix(address, ":") {
		address = "127.0.0.1" + address
	}
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(strings.TrimRight(address, "/") + "/status")
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false
	}
	var st struct {
		Locked bool `json:"locked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return false, false
	}
	return st.Locked, true
}

func (k *Keeper) Status(_ string) {
	store := k.requireStore()
	if err := k.cmds(store).Status(); err != nil {
		k.p.UI().Abort(err)
	}
}

func normaliseKey(key string) string {
	e := expect.NewRaw(key)
	if ref, err := e.SecretRef(); err == nil {
		return ref.WithoutScheme()
	}
	return key
}

func (k *Keeper) Rotate(_ string) {
	store := k.requireStore()

	u := ui.New()
	newResult, err := u.PasswordConfirm("New passphrase")
	if err != nil {
		k.p.UI().Abort("new passphrase required: ", err)
	}
	newPass := newResult.Bytes()
	defer newResult.Zero()

	if err := store.Rotate(newPass); err != nil {
		k.p.UI().Abort("rotation failed: ", err)
	}

	zero.Bytes(newPass)
	ui.New().SuccessLine("passphrase rotated — update the systemd credential, Vault entry, or environment source")
	ui.New().Blank()
}

func (k *Keeper) REPL(_ string) {
	store := k.requireStore()

	u := ui.New()
	u.Render(func() {
		u.Blank()
		u.InfoLine("Keeper REPL — type 'help' for commands, 'exit' to quit")
	})

	cmds := &keepcmd.Commands{
		Store:   func() (*keeperlib.Keeper, error) { return store, nil },
		Out:     &uiOutput{u: u},
		NoClose: true,
	}

	for {
		input := u.PromptInline("keeper")
		u.Flush()

		if input == "" {
			u.InfoLine("exiting REPL")
			return
		}

		parts := strings.Fields(input)
		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		u.Blank()
		switch cmd {
		case "exit", "quit":
			u.SuccessLine("bye")
			return

		case "help":
			k.replHelp()

		case "status":
			if err := cmds.Status(); err != nil {
				u.Render(func() { u.WarnLine(err.Error()) })
			}

		case "list", "ls":
			if err := cmds.List(); err != nil {
				u.Render(func() { u.WarnLine(err.Error()) })
			}

		case "get":
			if len(args) == 0 {
				u.Render(func() { u.WarnLine("usage: get <key>") })
				continue
			}
			if err := cmds.Get(normaliseKey(args[0])); err != nil {
				u.Render(func() { u.WarnLine(err.Error()) })
			}

		case "set":
			if len(args) < 1 {
				u.Render(func() { u.WarnLine("usage: set <key> <value>  |  set <key> --file <path>") })
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
					i = len(rest)
				}
			}
			if opts.FromFile == "" && value == "" {
				u.Render(func() { u.WarnLine("usage: set <key> <value>  |  set <key> --file <path>") })
				continue
			}
			key = normaliseKey(key)
			if err := store.EnsureBucket(key); err != nil {
				u.Render(func() { u.WarnLine("bucket error: " + err.Error()) })
				continue
			}
			if err := cmds.Set(key, value, opts); err != nil {
				u.Render(func() { u.WarnLine(err.Error()) })
			}

		case "delete", "del", "rm":
			if len(args) == 0 {
				u.Render(func() { u.WarnLine("usage: delete <key> [--force]") })
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
				u.Render(func() { u.WarnLine(err.Error()) })
			}

		default:
			u.WarnLine(fmt.Sprintf("unknown command %q — type 'help' for available commands", cmd))
		}
	}
}

func (k *Keeper) replHelp() {
	u := ui.New()
	u.Render(func() {
		u.Blank()
		u.InfoLine("Keeper REPL commands:")
		u.KeyValueBlock("", []ui.KV{
			{Label: "list", Value: "list all keys in the store"},
			{Label: "list <scheme>", Value: "list all keys in a specific scheme"},
			{Label: "list <scheme> <namespace>", Value: "list all keys in a specific bucket"},
			{Label: "get <key>", Value: "retrieve a secret value"},
			{Label: "set <key> <value>", Value: "store a plain-text secret"},
			{Label: "set <key> --file <path>", Value: "store a file's contents as a secret"},
			{Label: "delete <key>", Value: "delete a secret (prompts for confirmation)"},
			{Label: "delete <key> --force", Value: "delete without confirmation prompt"},
			{Label: "status", Value: "show whether the store is locked or unlocked"},
			{Label: "help", Value: "show this help"},
			{Label: "exit / quit", Value: "leave the REPL"},
		})
		u.InfoLine("Keys accept any scheme: ss://ns/key, vault://ns/key, or plain ns/key")

	})
}
