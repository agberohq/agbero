package wasm

import (
	"context"
	"net/http"

	"github.com/tetratelabs/wazero/api"
)

// RequestContext holds the state for a single HTTP request
type RequestContext struct {
	W    http.ResponseWriter
	R    *http.Request
	Next bool // Should we proceed?
}

// ExportHostFunctions registers Agbero's API into the WASM runtime
func (m *Manager) ExportHostFunctions() {
	builder := m.runtime.NewHostModuleBuilder("env")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			// FIX: Get RequestContext, then extract *http.Request from it
			rcRaw := ctx.Value(CtxKeyRequest)
			if rcRaw == nil {
				stack[0] = 0
				return
			}
			rc, ok := rcRaw.(*RequestContext)
			if !ok || rc == nil || rc.R == nil {
				stack[0] = 0
				return
			}
			req := rc.R

			// Permission check
			if !m.config.HasAccess("headers") {
				stack[0] = 0
				return
			}

			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			bufPtr := uint32(stack[2])
			bufLen := uint32(stack[3])

			// Bounds check for key read
			keyBytes, ok := mod.Memory().Read(keyPtr, keyLen)
			if !ok {
				stack[0] = 0
				return
			}

			val := req.Header.Get(string(keyBytes))
			valBytes := []byte(val)
			totalLen := uint64(len(valBytes))

			writeLen := min(uint32(totalLen), bufLen)

			if writeLen > 0 {
				// Bounds check for value write
				if !mod.Memory().Write(bufPtr, valBytes[:writeLen]) {
					stack[0] = 0
					return
				}
			}

			stack[0] = totalLen
		}),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		Export("agbero_get_header")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			// FIX: Use typed context key CtxKeyResponseWriter
			wRaw := ctx.Value(CtxKeyResponseWriter)
			if wRaw == nil {
				return
			}
			w, ok := wRaw.(http.ResponseWriter)
			if !ok {
				return
			}

			if !m.config.HasAccess("headers") {
				return
			}

			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			valPtr := uint32(stack[2])
			valLen := uint32(stack[3])

			keyBytes, ok := mod.Memory().Read(keyPtr, keyLen)
			if !ok {
				return
			}
			valBytes, ok := mod.Memory().Read(valPtr, valLen)
			if !ok {
				return
			}

			w.Header().Set(string(keyBytes), string(valBytes))
		}),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{}).
		Export("agbero_set_header")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			bufPtr := uint32(stack[0])
			bufLen := uint32(stack[1])
			totalLen := uint64(len(m.configJSON))

			writeLen := min(uint32(totalLen), bufLen)

			if writeLen > 0 {
				if !mod.Memory().Write(bufPtr, m.configJSON[:writeLen]) {
					stack[0] = 0
					return
				}
			}

			stack[0] = totalLen
		}),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		Export("agbero_get_config")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			status := uint32(stack[0])
			// FIX: Use typed context key CtxKeyRequest
			rcRaw := ctx.Value(CtxKeyRequest)
			if rcRaw == nil {
				return
			}
			rc, ok := rcRaw.(*RequestContext)
			if !ok || rc == nil {
				return
			}

			if status != 0 {
				rc.W.WriteHeader(int(status))
				rc.Next = false
			} else {
				rc.Next = true
			}
		}),
			[]api.ValueType{api.ValueTypeI32},
			[]api.ValueType{}).
		Export("agbero_done")

	_, _ = builder.Instantiate(context.Background())
}
