package alaye

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
)

func TestRedactGlobalHidesKeeperPassphraseFile(t *testing.T) {
	g := &Global{}
	g.Security.Keeper.PassphraseFile = "/etc/agbero/keeper.passphrase"

	r := RedactGlobal(g)
	if r.Security.Keeper.PassphraseFile != def.RedactedValue {
		t.Fatalf("passphrase_file = %q, want %q", r.Security.Keeper.PassphraseFile, def.RedactedValue)
	}
	if g.Security.Keeper.PassphraseFile != "/etc/agbero/keeper.passphrase" {
		t.Fatal("RedactGlobal mutated the input")
	}
}
