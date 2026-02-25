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
			req := ctx.Value("req").(*http.Request)

			if !m.config.HasAccess("headers") {
				stack[0] = 0
				return
			}

			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			bufPtr := uint32(stack[2])
			bufLen := uint32(stack[3])

			keyBytes, _ := mod.Memory().Read(keyPtr, keyLen)
			val := req.Header.Get(string(keyBytes))
			valBytes := []byte(val)
			totalLen := uint64(len(valBytes))

			writeLen := min(uint32(totalLen), bufLen)

			if writeLen > 0 {
				mod.Memory().Write(bufPtr, valBytes[:writeLen])
			}

			stack[0] = totalLen
		}),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		Export("agbero_get_header")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			w := ctx.Value("w").(http.ResponseWriter)

			if !m.config.HasAccess("headers") {
				return
			}

			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			valPtr := uint32(stack[2])
			valLen := uint32(stack[3])

			keyBytes, _ := mod.Memory().Read(keyPtr, keyLen)
			valBytes, _ := mod.Memory().Read(valPtr, valLen)

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
				mod.Memory().Write(bufPtr, m.configJSON[:writeLen])
			}

			stack[0] = totalLen
		}),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		Export("agbero_get_config")

	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			status := uint32(stack[0])
			rc := ctx.Value("rc").(*RequestContext)

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
