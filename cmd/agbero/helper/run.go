package helper

import (
	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/discovery"
)

type Run struct {
	p *Helper
}

// Start executes `agbero run` - runs the proxy in foreground
// Uses openStore (Interactive: true) because it can prompt for passphrase
func (r *Run) Start(configPath string, devMode bool) error {
	global, err := loadGlobal(configPath)
	if err != nil {
		return err
	}

	// openStore uses Interactive: true - will prompt if needed
	store := r.p.openStore(configPath)
	defer store.Close()

	hostFolder := global.Storage.HostsDir.Sub(woos.HostDir)
	hm := discovery.NewHost(hostFolder, discovery.WithLogger(r.p.Logger))

	if err := hm.Watch(); err != nil {
		return err
	}

	server := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(r.p.Logger),
		agbero.WithShutdownManager(r.p.Shutdown),
		agbero.WithKeeper(store),
	)

	return server.Start(configPath)
}
