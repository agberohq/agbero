// Package xserverless implements the entry point for serverless route handling.
// It dispatches traffic between REST proxies and ephemeral binary workers.
package xserverless

import (
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
)

type serverless struct {
	mux *http.ServeMux
}

// New creates a new serverless dispatcher that routes traffic to RESTs and Workers.
// It initializes sub-handlers for all configured serverless endpoints in the route.
func New(cfg resource.Proxy, route *alaye.Route) http.Handler {
	s := &serverless{
		mux: http.NewServeMux(),
	}

	globalEnv := make(map[string]alaye.Value)
	cfg.Resource.Env.Global.Range(func(k string, v alaye.Value) bool {
		globalEnv[k] = v
		return true
	})

	routeEnv := route.Env

	for _, rest := range route.Serverless.RESTs {
		if !rest.Enabled.Active() {
			continue
		}
		handler := NewRest(RestConfig{
			Resource:  cfg.Resource,
			REST:      rest,
			GlobalEnv: globalEnv,
			RouteEnv:  routeEnv,
		})
		s.mux.Handle("/rest/"+rest.Name, handler)
	}

	for _, worker := range route.Serverless.Workers {
		handler := NewWorker(WorkerConfig{
			Resource:  cfg.Resource,
			Work:      worker,
			GlobalEnv: globalEnv,
			RouteEnv:  routeEnv,
			Orch:      cfg.Orch,
		})
		s.mux.Handle("/work/"+worker.Name, handler)
	}

	return s
}

// ServeHTTP forwards the request to the internal ServeMux managing serverless functions.
// It provides the entry point for requests targeting /rest/* or /work/* endpoints.
func (s *serverless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
