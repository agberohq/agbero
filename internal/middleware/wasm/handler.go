package wasm

import (
	"context"
	"net/http"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type contextKey string

const (
	wResponseWriter contextKey = "w"
	wRequest        contextKey = "req"
	wRequestContext contextKey = "rc"
)

type Instance struct {
	m   *Manager
	c   wazero.ModuleConfig
	mod api.Module
}

func (m *Manager) Handler(next http.Handler) http.Handler {
	if m == nil || !m.config.Enabled.Active() {
		return next
	}

	m.ExportHostFunctions()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := &RequestContext{W: w, R: r, Next: true}

		ctx := context.WithValue(r.Context(), wResponseWriter, w)
		ctx = context.WithValue(ctx, wRequest, r)
		ctx = context.WithValue(ctx, wRequestContext, rc)

		inst, err := m.GetInstance(ctx)
		if err != nil {
			m.logger.Fields("err", err).Error("wasm: failed to instantiate")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer m.CloseInstance(ctx, inst)

		handleFunc := inst.mod.ExportedFunction("handle_request")
		if handleFunc == nil {
			handleFunc = inst.mod.ExportedFunction("_start")
		}

		if handleFunc == nil {
			m.logger.Error("wasm: module must export 'handle_request'")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		_, err = handleFunc.Call(ctx)
		if err != nil {
			m.logger.Fields("err", err).Error("wasm: execution failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if rc.Next {
			next.ServeHTTP(w, r)
		}
	})
}
