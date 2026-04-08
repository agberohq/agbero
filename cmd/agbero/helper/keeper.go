package helper

import (
	"fmt"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/ui"
	keeperlib "github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keepcmd"
	"github.com/olekukonko/zero"
)

type Keeper struct {
	p *Helper
}

type uiOutput struct{ u *ui.UI }

func (o *uiOutput) Table(headers []string, rows [][]string) { o.u.Table(headers, rows) }
func (o *uiOutput) KeyValue(label, value string)            { o.u.KeyValue(label, value) }
func (o *uiOutput) Success(msg string)                      { o.u.SuccessLine(msg) }
func (o *uiOutput) Info(msg string)                         { o.u.InfoLine(msg) }
func (o *uiOutput) Error(msg string)                        { o.u.WarnLine(msg) }

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
		k.p.Logger.Fatal("keeper store is not available — run 'agbero init' first or check AGBERO_PASSPHRASE")
	}
	return k.p.Store
}

func (k *Keeper) List(_ string) {
	store := k.requireStore()
	if err := k.cmds(store).List(); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Get(_ string, key string) {
	store := k.requireStore()
	key = normaliseKey(key)
	if err := k.cmds(store).Get(key); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Set(_ string, key, value string, asB64 bool, fromFile string) {
	store := k.requireStore()

	u := ui.New()

	rawKey := key
	key = normaliseKey(key)

	if err := store.EnsureBucket(key); err != nil {
		k.p.Logger.Fatal("failed to prepare bucket: ", err)
	}

	if err := k.cmds(store).Set(key, value, keepcmd.SetOptions{Base64: asB64, FromFile: fromFile}); err != nil {
		k.p.Logger.Fatal(err)
	}

	ref := rawKey
	if !strings.Contains(rawKey, "://") {
		ref = "ss://" + key
	}
	u.InfoLine("reference in agbero.hcl as:  " + ref)
}

func (k *Keeper) Delete(_ string, key string, force bool) {
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
	store := k.requireStore()
	key = normaliseKey(key)
	if err := k.cmds(store).Delete(key); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Backup(_ string, dest string) {
	store := k.requireStore()
	if err := k.cmds(store).Backup(keepcmd.BackupOptions{Dest: dest}); err != nil {
		k.p.Logger.Fatal(err)
	}
}

func (k *Keeper) Status(_ string) {
	store := k.requireStore()
	if err := k.cmds(store).Status(); err != nil {
		k.p.Logger.Fatal(err)
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
	// store.Rotate requires the store to be unlocked — do NOT call store.Lock()
	// before this. The store is already unlocked (injected from main).

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

func (k *Keeper) REPL(_ string) {
	store := k.requireStore()

	u := ui.New()
	u.Blank()
	u.InfoLine("Keeper REPL — type 'help' for commands, 'exit' to quit")
	u.Blank()

	cmds := &keepcmd.Commands{
		Store:   func() (*keeperlib.Keeper, error) { return store, nil },
		Out:     &uiOutput{u: u},
		NoClose: true,
	}

	for {
		input := u.PromptInline("keeper")
		if input == "" {
			u.InfoLine("exiting REPL")
			u.Blank()
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
					i = len(rest)
				}
			}
			if opts.FromFile == "" && value == "" {
				u.WarnLine("usage: set <key> <value>  |  set <key> --file <path>")
				continue
			}
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
	u.Blank()
}
