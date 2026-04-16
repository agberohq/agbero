package xserverless

import (
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/orchestrator"
	"github.com/agberohq/agbero/internal/hub/resource"
)

type WorkerConfig struct {
	Resource  *resource.Resource
	Route     alaye.Route
	Work      alaye.Work
	GlobalEnv map[string]expect.Value
	RouteEnv  map[string]expect.Value
	Orch      *orchestrator.Manager
	Domain    string
}

type Worker struct {
	res       *resource.Resource
	route     alaye.Route
	cfg       alaye.Work
	globalEnv map[string]expect.Value
	routeEnv  map[string]expect.Value
	orch      *orchestrator.Manager
	statsKey  alaye.BackendKey
}

func NewWorker(cfg WorkerConfig) *Worker {
	key := cfg.Route.WorkerBackendKey(cfg.Domain, cfg.Work.Name)
	cfg.Resource.Metrics.GetOrRegister(key)
	return &Worker{
		res:       cfg.Resource,
		route:     cfg.Route,
		cfg:       cfg.Work,
		globalEnv: cfg.GlobalEnv,
		routeEnv:  cfg.RouteEnv,
		orch:      cfg.Orch,
		statsKey:  key,
	}
}

func (h *Worker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	host := r.Host
	if host == "" {
		host = "default"
	}

	h.res.Logger.Fields("worker", h.cfg.Name, "method", r.Method, "remote", r.RemoteAddr).Info("serverless: worker request received")

	activity := h.res.Metrics.GetOrRegister(h.statsKey).Activity
	activity.StartRequest()
	failed := false
	defer func() {
		activity.EndRequest(time.Since(start).Microseconds(), failed)
	}()

	// orch is required — it owns the allowlist, privilege config, and
	// directory resolution. A nil orch means server misconfiguration;
	// refuse rather than execute without any security controls.
	if h.orch == nil {
		failed = true
		h.res.Logger.Fields("worker", h.cfg.Name).Error("serverless: no orchestrator configured, refusing execution")
		http.Error(w, "Worker Execution Failed", http.StatusInternalServerError)
		return
	}

	dir := h.orch.ResolveDir(host, h.route, h.cfg)

	// dir can only be empty if serverless.git is enabled but the cook
	// manager has not yet completed the initial clone.
	if dir == "" {
		h.res.Logger.Fields("worker", h.cfg.Name).Warn("serverless: git deployment pending, no checkout available")
		http.Error(w, "Deployment in progress...", http.StatusServiceUnavailable)
		return
	}

	env := expect.CompileEnv(h.globalEnv, h.routeEnv, h.cfg.Env)

	proc := h.orch.NewProcess(
		h.cfg,
		env,
		dir,
		h.res.Logger.Namespace("worker").Namespace(h.cfg.Name),
	)

	if err := proc.Run(r.Context(), r.Body, w); err != nil {
		failed = true
		h.res.Logger.Fields("worker", h.cfg.Name, "err", err, "duration", time.Since(start)).Error("serverless: ephemeral execution failed")
		http.Error(w, "Worker Execution Failed", http.StatusInternalServerError)
		return
	}
	h.res.Logger.Fields("worker", h.cfg.Name, "duration", time.Since(start)).Info("serverless: worker done")
}
