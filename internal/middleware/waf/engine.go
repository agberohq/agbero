package waf

import (
	"net/http"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	coraza "github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/olekukonko/ll"
)

// Engine wraps a Coraza WAF instance. A nil Engine is a safe no-op passthrough.
type Engine struct {
	waf    coraza.WAF
	mode   string
	logger *ll.Logger
}

// Config is used to construct an Engine from global Security.WAF config.
type Config struct {
	WAF    *alaye.WAF
	Logger *ll.Logger
}

// RouteConfig constructs a per-route Engine, merging global and route-level config.
type RouteConfig struct {
	Global *alaye.WAF
	Route  *alaye.WAFRoute
	Logger *ll.Logger
}

// New builds a WAF Engine from global config.
// Returns (nil, nil) when WAF is disabled or config is nil — callers must handle nil.
func New(cfg Config) (*Engine, error) {
	if cfg.WAF == nil || cfg.WAF.Status.Inactive() {
		return nil, nil
	}

	wafInst, err := buildWAF(cfg.WAF.Directives, cfg.WAF.RulesDir)
	if err != nil {
		return nil, err
	}

	return &Engine{
		waf:    wafInst,
		mode:   cfg.WAF.Mode,
		logger: cfg.Logger,
	}, nil
}

// NewForRoute builds a WAF Engine for a specific route.
// When route.IgnoreGlobal is true the global WAF is bypassed entirely.
// Route-level Directives are appended on top of the global ones.
func NewForRoute(cfg RouteConfig) (*Engine, error) {
	// No route override at all — fall back to global directly
	if cfg.Route == nil || cfg.Route.IsZero() {
		return New(Config{WAF: cfg.Global, Logger: cfg.Logger})
	}

	// Route explicitly disables WAF for this path
	if cfg.Route.Status.Inactive() {
		return nil, nil
	}

	// IgnoreGlobal — use only route directives (if any)
	if cfg.Route.IgnoreGlobal {
		if len(cfg.Route.Directives) == 0 {
			return nil, nil // no rules at all — passthrough
		}
		wafInst, err := buildWAF(cfg.Route.Directives, "")
		if err != nil {
			return nil, err
		}
		mode := cfg.Route.EffectiveMode(cfg.Global)
		return &Engine{waf: wafInst, mode: mode, logger: cfg.Logger}, nil
	}

	// Merge: global directives + route directives
	var directives []string
	rulesDir := ""
	if cfg.Global != nil {
		directives = append(directives, cfg.Global.Directives...)
		rulesDir = cfg.Global.RulesDir
	}
	directives = append(directives, cfg.Route.Directives...)

	wafInst, err := buildWAF(directives, rulesDir)
	if err != nil {
		return nil, err
	}

	mode := cfg.Route.EffectiveMode(cfg.Global)
	return &Engine{waf: wafInst, mode: mode, logger: cfg.Logger}, nil
}

// Middleware wraps next with WAF inspection. A nil Engine returns next unchanged.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	if e == nil {
		return next
	}
	if e.mode == "monitor" {
		return txhttp.WrapHandler(e.waf, monitorHandler(next, e.logger))
	}
	return txhttp.WrapHandler(e.waf, next)
}

// monitorHandler wraps next so that WAF interruptions are logged but not enforced.
func monitorHandler(next http.Handler, log *ll.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mw := &monitorWriter{ResponseWriter: w}
		next.ServeHTTP(mw, r)
		if mw.blocked {
			if log != nil {
				log.Fields("path", r.URL.Path, "method", r.Method).
					Warn("waf: monitor mode — would have blocked request")
			}
			mw.unblock()
		}
	})
}

type monitorWriter struct {
	http.ResponseWriter
	blocked bool
	status  int
}

func (mw *monitorWriter) WriteHeader(code int) {
	if code == http.StatusForbidden || code == http.StatusBadRequest {
		mw.blocked = true
		mw.status = code
		return
	}
	mw.ResponseWriter.WriteHeader(code)
}

func (mw *monitorWriter) unblock() {
	mw.ResponseWriter.WriteHeader(http.StatusOK)
}

// buildWAF creates a Coraza WAF from directives and an optional rules directory.
// rulesDir is opened as an os.DirFS and passed to WithRootFS so that
// "Include @path/to/rules/*.conf" directives resolve correctly.
func buildWAF(directives []string, rulesDir string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig()

	if rulesDir != "" {
		cfg = cfg.WithRootFS(os.DirFS(rulesDir))
	}

	combined := strings.Join(directives, "\n")
	if combined != "" {
		cfg = cfg.WithDirectives(combined)
	}

	return coraza.NewWAF(cfg)
}
