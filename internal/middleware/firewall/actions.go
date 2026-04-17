package firewall

import (
	"fmt"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func (e *Engine) handleAction(w http.ResponseWriter, r *http.Request, rule alaye.Rule, ruleName, reason string) {
	var actionDef alaye.FirewallAction
	actionName := "ban"
	if rule.Action != "" {
		actionName = rule.Action
	} else if e.cfg.Defaults.Dynamic.Action != "" {
		actionName = e.cfg.Defaults.Dynamic.Action
	}

	for _, a := range e.cfg.Actions {
		if a.Name == actionName {
			actionDef = a
			break
		}
	}

	if actionDef.Name == "" {
		actionDef = alaye.FirewallAction{
			Mitigation: "add",
			Response:   alaye.Response{StatusCode: 403},
		}
	}

	if e.cfg.Mode == "verbose" || e.cfg.Mode == "monitor" {
		e.logger.Fields("mode", "monitor", "rule", ruleName, "ip", e.ipMgr.ClientIP(r)).Warn("simulated block")
		return
	}

	if actionDef.Mitigation == "add" || actionDef.Mitigation == "ban" {
		duration := 24 * time.Hour
		if rule.Duration > 0 {
			duration = rule.Duration.StdDuration()
		}

		ip := e.ipMgr.ClientIP(r)
		banRule := Rule{
			IP:        ip,
			Type:      BlockTypeSingle,
			Reason:    fmt.Sprintf("%s: %s", ruleName, reason),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(duration),
		}
		_ = e.store.Add(banRule)
		e.logger.Fields("ip", ip, "rule", ruleName).Warn("ban added")
	}

	e.sendResponse(w, actionDef.Response, ruleName)
}

func (e *Engine) blockRequest(w http.ResponseWriter, r *http.Request, ruleName, reason string) {
	e.handleAction(w, r, alaye.Rule{}, ruleName, reason)
}

func (e *Engine) sendResponse(w http.ResponseWriter, resp alaye.Response, ruleName string) {
	if resp.Status.Inactive() {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	if resp.ContentType != "" {
		w.Header().Set("Content-Type", resp.ContentType)
	}
	w.WriteHeader(resp.StatusCode)

	if resp.Template != nil {
		data := map[string]any{"RuleName": ruleName, "Timestamp": time.Now().Unix()}
		if err := resp.Template.Execute(w, data); err != nil {
			e.logger.Error("template execution failed", "err", err, "rule", ruleName)
		}
	} else if resp.BodyTemplate != "" {
		w.Write([]byte(resp.BodyTemplate))
	}
}
