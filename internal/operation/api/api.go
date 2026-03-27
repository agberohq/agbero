package api

import (
	"sync/atomic"

	"github.com/agberohq/agbero/internal/cluster"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/middleware/firewall"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/telemetry"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

type ActiveState struct {
	Global   *alaye.Global
	Firewall *firewall.Engine
	TLSS     *tlss.Manager
}

type Shared struct {
	Logger    *ll.Logger
	Cluster   *cluster.Manager
	Store     *security.Store
	Discovery *discovery.Host
	PPK       *security.PPK
	Telemetry *telemetry.Store

	// monitor shared state
	state atomic.Value
}

func (s *Shared) State() *ActiveState {
	if v := s.state.Load(); v != nil {
		return v.(*ActiveState)
	}
	return &ActiveState{} // Fallback to avoid nil panics
}

// UpdateState is called by the main server to push a new copy of the state.
func (s *Shared) UpdateState(newState *ActiveState) {
	s.state.Store(newState)
}

// Handler registers all API routes under /api/v1 on the provided router.
// It sets up public endpoints (health, auth) and protected groups (cluster, host, etc.).
func Handler(shared *Shared, r chi.Router) {
	r.Route("/api/v1", func(r chi.Router) {
		if shared.Cluster != nil && shared.PPK != nil {
			ClusterHandler(shared, r)
		} else if shared.Cluster == nil {
			shared.Logger.Warn("admin api disabled: cluster ppk not active")
		} else if shared.PPK == nil {
			shared.Logger.Error("admin api disabled: security ppk (internal_auth_key) not configured")
		}

		if state := shared.State(); state.Global != nil &&
			state.Global.Admin.Telemetry.Enabled.Active() && shared.Telemetry != nil {
			shared.Logger.Info("telemetry history enabled")
			r.Mount("/telemetry", telemetry.Handler(shared.Telemetry))
		}

		CertsHandler(shared, r)
		RouterHandler(shared, r)
		KeeperHandler(shared, r)
		TOTPHandler(shared, r)
		FirewallHandler(shared, r)
		SecretsHandler(shared, r)
		HostHandler(shared, r)
		RouterHandler(shared, r)
	})

	r.Route("/auto/v1", func(r chi.Router) {
		CertsHandler(shared, r)
		RouterHandler(shared, r)
	})

}
