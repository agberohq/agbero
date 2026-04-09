package xserverless

import (
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/middleware/nonce"
)

type serverless struct {
	mux         *http.ServeMux
	nonceStores map[string]*nonce.Store
}

// New creates a serverless handler. Existing call sites remain unchanged.
func New(cfg resource.Proxy, route *alaye.Route) http.Handler {
	return NewWithNonces(cfg, route, nil)
}

// NewWithNonces creates a serverless handler with pre-built nonce stores.
// nonceStores maps rest endpoint name → Store; nil when not needed.
func NewWithNonces(cfg resource.Proxy, route *alaye.Route, nonceStores map[string]*nonce.Store) http.Handler {
	s := &serverless{
		mux:         http.NewServeMux(),
		nonceStores: nonceStores,
	}

	globalEnv := make(map[string]expect.Value)
	cfg.Resource.Env.Global.Range(func(k string, v expect.Value) bool {
		globalEnv[k] = v
		return true
	})

	routeEnv := route.Env

	validRests := make(map[string]alaye.Replay)
	for _, rest := range route.Serverless.Replay {
		if !rest.Enabled.Active() {
			continue
		}
		if _, exists := validRests[rest.Name]; exists {
			cfg.Resource.Logger.Fields("name", rest.Name).Warn("serverless: duplicate REST name detected, overwriting previous registration")
		}
		validRests[rest.Name] = rest
	}

	for name, rest := range validRests {
		var nonceStore *nonce.Store
		if nonceStores != nil {
			nonceStore = nonceStores[name]
		}
		handler := NewReplay(ReplayConfig{
			Resource:   cfg.Resource,
			REST:       rest,
			GlobalEnv:  globalEnv,
			RouteEnv:   routeEnv,
			NonceStore: nonceStore,
		})
		s.mux.Handle("/"+name, handler)
	}

	validWorkers := make(map[string]alaye.Work)
	for _, worker := range route.Serverless.Workers {
		if _, exists := validWorkers[worker.Name]; exists {
			cfg.Resource.Logger.Fields("name", worker.Name).Warn("serverless: duplicate Worker name detected, overwriting previous registration")
		}
		validWorkers[worker.Name] = worker
	}

	for name, worker := range validWorkers {
		if _, exists := validRests[name]; exists {
			cfg.Resource.Logger.Fields("name", name).Warn("serverless: Worker name collides with REST name, skipping worker registration")
			continue
		}
		handler := NewWorker(WorkerConfig{
			Resource:  cfg.Resource,
			Route:     *route,
			Work:      worker,
			GlobalEnv: globalEnv,
			RouteEnv:  routeEnv,
			Orch:      cfg.Orch,
		})
		s.mux.Handle("/"+name, handler)
	}
	return s
}

func (s *serverless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
