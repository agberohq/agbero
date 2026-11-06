package api

import (
	"net/http"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/cluster"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/middleware/firewall"
	"github.com/agberohq/agbero/internal/pkg/revoke"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/stash"
	"github.com/agberohq/agbero/internal/pkg/telemetry"
	"github.com/agberohq/keeper"
	"github.com/go-chi/chi/v5"
	"github.com/olekukonko/ll"
)

type ActiveState struct {
	Global   *alaye.Global
	Firewall *firewall.Engine
	TLSS     *tlss.Manager
}

type UpdateChecker interface {
	GetCurrent() string
	GetLatest() string
	IsAvailable() bool
}

type Shared struct {
	Logger        *ll.Logger
	Cluster       *cluster.Manager
	Keeper        *keeper.Keeper
	Discovery     *discovery.Host
	PPK           *security.PPK
	Telemetry     *telemetry.Store
	RevokeStore   *revoke.Store
	UpdateChecker UpdateChecker

	// CacheStore is the active cache backend, wired in from admin.go at startup.
	// Used by CacheHandler for purge-by-tag and clear-all operations.
	CacheStore stash.Store

	state atomic.Value
}

func (s *Shared) State() *ActiveState {
	if v := s.state.Load(); v != nil {
		return v.(*ActiveState)
	}
	return &ActiveState{}
}

func (s *Shared) UpdateState(newState *ActiveState) {
	s.state.Store(newState)
}

func AdminHandler(shared *Shared, r chi.Router) {
	r.Route("/api/v1", func(r chi.Router) {
		// host.go sets its own limit for a precise 413 on host writes; this
		// covers every other admin endpoint.
		r.Use(adminBodyLimit(def.HostConfigMaxBytes))

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

		SystemHandler(shared, r)
		CertsHandler(shared, r)
		RouterHandler(shared, r)
		KeeperHandler(shared, r)
		TOTPHandler(shared, r)
		FirewallHandler(shared, r)
		SecretsHandler(shared, r)
		HostHandler(shared, r)
		RevokeHandler(shared, r)
		KVHandler(shared, r)
		CacheHandler(shared, r) // CDN cache management
	})
}

func AutoHandler(shared *Shared, r chi.Router) {
	r.Route("/auto/v1", func(r chi.Router) {
		AutoRouteHandler(shared, r)
	})
}

// adminBodyLimit caps every admin request body. The Content-Length check gives
// a clean 413; MaxBytesReader covers chunked requests.
func adminBodyLimit(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > max {
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}
