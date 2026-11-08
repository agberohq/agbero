package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
)

func TestControlUnlock(t *testing.T) {
	dataDir := expect.NewFolder(filepath.Join(t.TempDir(), "data"))
	store, err := Open(Config{
		DataDir: dataDir,
		Setting: &alaye.Keeper{Enabled: expect.Active, Passphrase: expect.Value("control-test-passphrase")},
		Logger:  ll.New("test").Disable(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Lock(); err != nil {
		t.Fatal(err)
	}
	ctl, err := StartControl(store, dataDir, ll.New("test").Disable())
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	if _, err := os.Stat(ControlPath(dataDir)); err != nil {
		t.Fatalf("control file missing: %v", err)
	}
	if err := UnlockControl(dataDir, []byte("control-test-passphrase")); err != nil {
		t.Fatal(err)
	}
	ctl.Wait()
	if store.IsLocked() {
		t.Fatal("store is still locked")
	}
	if _, err := os.Stat(ControlPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("control file was not removed: %v", err)
	}
}
