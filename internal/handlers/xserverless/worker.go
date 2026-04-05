package xserverless

import (
	"net/http"
	"os"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	orchestrator2 "github.com/agberohq/agbero/internal/hub/orchestrator"
	"github.com/agberohq/agbero/internal/hub/resource"
)

type WorkerConfig struct {
	Resource  *resource.Resource
	Route     alaye.Route
	Work      alaye.Work
	GlobalEnv map[string]expect.Value
	RouteEnv  map[string]expect.Value
	Orch      *orchestrator2.Manager
}

type WorkerHandler struct {
	res       *resource.Resource
	route     alaye.Route
	cfg       alaye.Work
	globalEnv map[string]expect.Value
	routeEnv  map[string]expect.Value
	orch      *orchestrator2.Manager
}

// NewWorker initializes a new worker handler with the given configuration.
func NewWorker(cfg WorkerConfig) *WorkerHandler {
	return &WorkerHandler{
		res:       cfg.Resource,
		route:     cfg.Route,
		cfg:       cfg.Work,
		globalEnv: cfg.GlobalEnv,
		routeEnv:  cfg.RouteEnv,
		orch:      cfg.Orch,
	}
}

// ServeHTTP handles the incoming HTTP request by running the configured worker process.
// It resolves the execution directory and returns 503 if a git deployment is pending.
func (h *WorkerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = "default"
	}

	var dir string
	if h.orch != nil {
		dir = h.orch.ResolveDir(host, h.route, h.cfg)
	} else {
		dir = os.TempDir()
	}

	if dir == "" && h.route.Web.Git.Enabled.Active() {
		http.Error(w, "Deployment in progress...", http.StatusServiceUnavailable)
		return
	}

	env := expect.CompileEnv(h.globalEnv, h.routeEnv, h.cfg.Env)

	proc := &orchestrator2.Process{
		Config: h.cfg,
		Env:    env,
		Dir:    dir,
		Logger: h.res.Logger.Namespace("worker").Namespace(h.cfg.Name),
	}

	if err := proc.Run(r.Context(), r.Body, w); err != nil {
		h.res.Logger.Fields("worker", h.cfg.Name, "err", err).Error("serverless: ephemeral execution failed")
		http.Error(w, "Worker Execution Failed", http.StatusInternalServerError)
	}
}
