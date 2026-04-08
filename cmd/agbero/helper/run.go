package helper

import (
	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/hub/discovery"
)

type Run struct {
	p *Helper
}

func (r *Run) Start(configPath string, devMode bool) error {
	global, err := loadGlobal(configPath)
	if err != nil {
		return err
	}

	store := r.p.openStore(configPath)
	defer store.Close()

	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(r.p.Logger))

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
