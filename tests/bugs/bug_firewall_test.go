package bugs

import (
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/middleware/firewall"
)

// Finding: Reload() closed the firewall bolt store while the old listeners were
// still serving (server.go:533-538 called CloseFirewall() before the replacement
// manager opened the same file, and the compensating block at :664-670 was
// commented out). Bans recorded by the draining engine in that window were
// silently dropped (firewall/store.go Add -> buffered channel with no consumer).
//
// The fix hands the open store to the replacement engine and reference-counts it.
// This test drives that handover through the public API: two engines share one
// store, the first one is closed (as Reload does), and a ban added afterwards by
// the second must still be persisted.
func TestBUG_FirewallBanLostDuringReload(t *testing.T) {
	dataDir := expect.NewFolder(filepath.Join(t.TempDir(), "data"))
	if err := dataDir.Init(expect.DirPerm); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	fw := &alaye.Firewall{Status: expect.Active, Mode: "active"}

	// Engine #1: normal start, owns the store (refs=1).
	oldEngine, err := firewall.New(firewall.Config{
		Firewall: fw,
		DataDir:  dataDir,
		Logger:   testLogger,
	})
	if err != nil {
		t.Fatalf("firewall.New (old): %v", err)
	}
	store := oldEngine.Store()
	if store == nil {
		t.Fatalf("setup: no store on the first engine")
	}

	// Engine #2: the replacement created by a config reload adopts the store.
	newEngine, err := firewall.New(firewall.Config{
		Firewall: fw,
		Logger:   testLogger,
		Store:    store,
	})
	if err != nil {
		t.Fatalf("firewall.New (adopting): %v", err)
	}

	// The old manager retires while the new one is live (Reload drains, then
	// closes the old traffic manager).
	if err := oldEngine.Close(); err != nil {
		t.Fatalf("old engine Close: %v", err)
	}

	// A ban recorded through the replacement engine — i.e. after the old engine
	// was closed — must survive.
	if err := store.Add(firewall.Rule{IP: "192.0.2.77", Reason: "during-drain"}); err != nil {
		t.Fatalf("Add after handover returned an error: %v", err)
	}
	if err := store.Sync(); err != nil {
		t.Fatalf("Sync after handover: %v", err)
	}

	// Retire the replacement engine (last reference) and reopen the file from
	// scratch: the ban must be on disk.
	if err := newEngine.Close(); err != nil {
		t.Fatalf("new engine Close: %v", err)
	}
	reopened, err := firewall.NewStore(dataDir, testLogger)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	rules, err := reopened.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	for _, r := range rules {
		if r.IP == "192.0.2.77" {
			return
		}
	}
	t.Fatalf("BUG CONFIRMED: a ban recorded after the reload handover was not persisted "+
		"(%d rule(s) on disk). Reload must hand the open store to the replacement engine "+
		"instead of closing it while the old listeners are still draining (server.go:533-538).",
		len(rules))
}
