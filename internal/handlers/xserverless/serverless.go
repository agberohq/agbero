package xserverless

import (
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
)

type serverless struct {
	mux *http.ServeMux
}

// Instantiates a new serverless handler router that multiplexes mapped REST and Worker execution endpoints
// Configures route-specific environments injected globally down to the handlers
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
		s.mux.Handle("/"+rest.Name, handler)
	}

	for _, worker := range route.Serverless.Workers {
		handler := NewWorker(WorkerConfig{
			Resource:  cfg.Resource,
			Route:     *route,
			Work:      worker,
			GlobalEnv: globalEnv,
			RouteEnv:  routeEnv,
			Orch:      cfg.Orch,
		})
		s.mux.Handle("/"+worker.Name, handler)
	}

	return s
}

// Proxies incoming serverless HTTP requests to the resolved multiplexer
// Uses the registered URI path rules to identify target functions
func (s *serverless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
