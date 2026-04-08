package helper

import (
	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/hub/discovery"
)

type Run struct {
	p *Helper
}

// Start launches the agbero server.  The Keeper store must already be open
// and unlocked — it is injected via r.p.Store by main() before this is called.
// Run.Start never opens or closes the store itself; lifecycle is owned by main().
func (r *Run) Start(configPath string, devMode bool) error {
	global, err := loadGlobal(configPath)
	if err != nil {
		return err
	}

	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(r.p.Logger))

	if err := hm.Watch(); err != nil {
		return err
	}

	server := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(r.p.Logger),
		agbero.WithShutdownManager(r.p.Shutdown),
		agbero.WithKeeper(r.p.Store),
	)

	return server.Start(configPath)
}
