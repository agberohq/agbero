package agbero

import (
	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

type Option func(server *Server)

func WithHostManager(hm *discovery.Host) Option {
	return func(server *Server) {
		server.hostManager = hm
	}
}

func WithGlobalConfig(global *alaye.Global) Option {
	return func(server *Server) {
		server.global = global
	}
}

func WithLogger(logger *ll.Logger) Option {
	return func(server *Server) {
		server.logger = logger
	}
}

func WithShutdownManager(sm *jack.Shutdown) Option {
	return func(server *Server) {
		server.shutdown = sm
	}
}
