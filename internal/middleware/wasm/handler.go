package wasm

import (
	"context"
	"net/http"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type Instance struct {
	m   *Manager
	c   wazero.ModuleConfig
	mod api.Module
}

func (m *Manager) Handler(next http.Handler) http.Handler {
	// Ensure host functions are available
	m.ExportHostFunctions()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Setup Context
		// We pass W and R via context so Host Functions can access them
		rc := &RequestContext{W: w, R: r, Next: true}

		ctx := context.WithValue(r.Context(), "w", w)
		ctx = context.WithValue(ctx, "req", r)
		ctx = context.WithValue(ctx, "rc", rc)

		// 2. Get Instance
		inst, err := m.GetInstance(ctx)
		if err != nil {
			m.logger.Fields("err", err).Error("wasm: failed to instantiate")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer m.PutInstance(ctx, inst)

		// 3. Call the Guest's entrypoint (e.g., "handle_request")
		// The guest must export a function named "handle_request"
		handleFunc := inst.mod.ExportedFunction("handle_request")
		if handleFunc == nil {
			// Fallback: try "_start" if it's a simple main()
			handleFunc = inst.mod.ExportedFunction("_start")
		}

		if handleFunc == nil {
			m.logger.Error("wasm: module must export 'handle_request'")
			return // Fail open or closed? Currently fail open (next)
		}

		// 4. Run WASM
		// No arguments passed directly; Guest calls host functions to get data
		_, err = handleFunc.Call(ctx)
		if err != nil {
			m.logger.Fields("err", err).Error("wasm: execution failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// 5. Check if WASM signaled to stop (e.g. auth failure)
		if rc.Next {
			next.ServeHTTP(w, r)
		}
	})
}
