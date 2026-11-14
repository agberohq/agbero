package helper

import (
	"os"
	"path/filepath"

	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/hub/control"
	"github.com/agberohq/agbero/internal/hub/discovery"
)

type Run struct {
	p *Helper
}

func (r *Run) Start(configPath string, devMode bool) error {
	// Keep relative service paths (notably WAF rules) stable even if the
	// invoking shell's working directory was removed during an uninstall.
	if abs, err := filepath.Abs(configPath); err == nil {
		_ = os.Chdir(filepath.Dir(abs))
	}
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
		agbero.WithControlSocket(control.SocketPath(global.Storage.DataDir.Path())),
	)

	pidPath, err := writePIDFile(global.Storage.DataDir.Path())
	if err != nil {
		r.p.Logger.Warn("failed to write pid file; 'config reload' will not work", "err", err)
	} else {
		defer removePIDFile(pidPath)
	}

	stopReload := registerReload(server.Reload)
	defer stopReload()

	return server.Start(configPath)
}
