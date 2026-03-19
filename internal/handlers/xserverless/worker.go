// Package xserverless handles ephemeral binary execution as request handlers.
// Workers process incoming request bodies and write to the response stream.
package xserverless

import (
	"net/http"
	"os"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/pkg/orchestrator"
)

type WorkerConfig struct {
	Resource  *resource.Resource
	Work      alaye.Work
	GlobalEnv map[string]alaye.Value
	RouteEnv  map[string]alaye.Value
	Orch      *orchestrator.Manager
}

type WorkerHandler struct {
	res       *resource.Resource
	cfg       alaye.Work
	globalEnv map[string]alaye.Value
	routeEnv  map[string]alaye.Value
	orch      *orchestrator.Manager
}

// NewWorker constructs a handler for executing a background or interactive system process.
// It leverages the provided orchestrator to resolve working directories and execution context.
func NewWorker(cfg WorkerConfig) *WorkerHandler {
	return &WorkerHandler{
		res:       cfg.Resource,
		cfg:       cfg.Work,
		globalEnv: cfg.GlobalEnv,
		routeEnv:  cfg.RouteEnv,
		orch:      cfg.Orch,
	}
}

// ServeHTTP executes the system process associated with the worker for the current request.
// It pipes the HTTP request body to the process stdin and process stdout to the HTTP response.
func (h *WorkerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = "default"
	}

	var dir string
	if h.orch != nil {
		routeCfg := alaye.Route{
			Env: h.routeEnv,
			Serverless: alaye.Serverless{
				Workers: []alaye.Work{h.cfg},
			},
		}
		dir = h.orch.ResolveDir(host, routeCfg, h.cfg)
	} else {
		dir = os.TempDir()
	}

	env := alaye.CompileEnv(h.globalEnv, h.routeEnv, h.cfg.Env)

	proc := &orchestrator.Process{
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
