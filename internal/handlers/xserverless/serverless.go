package xserverless

import (
	"net/http"
	"path"
	"regexp"
	"strings"

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

	// Register replay endpoints
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
		cleanName, ok := cleanRouteName(name)
		if !ok {
			cfg.Resource.Logger.Fields("name", name).Error("serverless: invalid route name, skipping registration")
			continue
		}

		var nonceStore *nonce.Store
		if nonceStores != nil {
			nonceStore = nonceStores[name]
		}
		domainStr := ""
		if cfg.Host != nil && len(cfg.Host.Domains) > 0 {
			domainStr = cfg.Host.Domains[0]
		}
		handler := NewReplay(ReplayConfig{
			Resource:   cfg.Resource,
			Replay:     rest,
			GlobalEnv:  globalEnv,
			RouteEnv:   routeEnv,
			NonceStore: nonceStore,
			Domain:     domainStr,
			Route:      *route,
		})
		s.mux.Handle("/"+cleanName, handler)
	}

	validWorkers := make(map[string]alaye.Work)
	for _, worker := range route.Serverless.Workers {
		if !worker.Enabled.Active() {
			continue
		}

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

		cleanName, ok := cleanRouteName(name)
		if !ok {
			cfg.Resource.Logger.Fields("name", name).Error("serverless: invalid worker name, skipping registration")
			continue
		}

		domainStr2 := ""
		if cfg.Host != nil && len(cfg.Host.Domains) > 0 {
			domainStr2 = cfg.Host.Domains[0]
		}
		handler := NewWorker(WorkerConfig{
			Resource:  cfg.Resource,
			Route:     *route,
			Work:      worker,
			GlobalEnv: globalEnv,
			RouteEnv:  routeEnv,
			Orch:      cfg.Orch,
			Domain:    domainStr2,
		})
		s.mux.Handle("/"+cleanName, handler)
	}
	return s
}

func (s *serverless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

var routeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// cleanRouteName sanitizes and validates a route name to prevent path traversal
// and HTTP mux poisoning. Returns cleaned name + true if valid.
func cleanRouteName(name string) (string, bool) {
	clean := path.Clean("/" + name)[1:]
	if clean == "" || clean == "." || strings.Contains(clean, "/") || strings.Contains(clean, "..") {
		return "", false
	}
	// Strict allowlist: alphanumeric, dots, hyphens, underscores. Must start with alnum.
	if !routeNameRe.MatchString(clean) {
		return "", false
	}
	return clean, true
}
