package waf

import (
	"net/http"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	coraza "github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
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

	wafInst, err := buildWAF(cfg.WAF.Directives, cfg.WAF.RulesDir, cfg.WAF.Mode, cfg.Logger)
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
	if cfg.Route == nil || cfg.Route.IsZero() {
		return New(Config{WAF: cfg.Global, Logger: cfg.Logger})
	}

	if cfg.Route.Status.Inactive() {
		return nil, nil
	}

	mode := cfg.Route.EffectiveMode(cfg.Global)

	if cfg.Route.IgnoreGlobal {
		if len(cfg.Route.Directives) == 0 {
			return nil, nil
		}
		wafInst, err := buildWAF(cfg.Route.Directives, "", mode, cfg.Logger)
		if err != nil {
			return nil, err
		}
		return &Engine{waf: wafInst, mode: mode, logger: cfg.Logger}, nil
	}

	var directives []string
	rulesDir := ""
	if cfg.Global != nil {
		directives = append(directives, cfg.Global.Directives...)
		rulesDir = cfg.Global.RulesDir
	}
	directives = append(directives, cfg.Route.Directives...)

	wafInst, err := buildWAF(directives, rulesDir, mode, cfg.Logger)
	if err != nil {
		return nil, err
	}

	return &Engine{waf: wafInst, mode: mode, logger: cfg.Logger}, nil
}

func (e *Engine) Middleware(next http.Handler) http.Handler {
	if e == nil {
		return next
	}
	// Let Coraza natively handle detection/blocking based on SecRuleEngine
	return txhttp.WrapHandler(e.waf, next)
}

// buildWAF creates a Coraza WAF from directives and an optional rules directory.
// rulesDir is opened as an os.DirFS and passed to WithRootFS so that
// "Include @path/to/rules/*.conf" directives resolve correctly.
func buildWAF(directives []string, rulesDir string, mode string, logger *ll.Logger) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig()

	if rulesDir != "" {
		cfg = cfg.WithRootFS(os.DirFS(rulesDir))
	}

	// Route Coraza's internal error/warning logs to our structured logger
	if logger != nil {
		cfg = cfg.WithErrorCallback(func(mr types.MatchedRule) {
			logger.Fields(
				"rule_id", mr.Rule().ID(),
				"msg", mr.Message(),
				"data", mr.Data(),
				"severity", mr.Rule().Severity().String(),
			).Warn("waf: rule matched")
		})
	}

	combined := strings.Join(directives, "\n")

	// Use native Coraza configurations to enable Monitor (DetectionOnly) mode
	if mode == "monitor" {
		combined = "SecRuleEngine DetectionOnly\n" + combined
	} else {
		combined = "SecRuleEngine On\n" + combined
	}

	if combined != "" {
		cfg = cfg.WithDirectives(combined)
	}

	return coraza.NewWAF(cfg)
}
