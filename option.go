package agbero

import (
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
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
