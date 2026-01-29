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
	// We create a "env" module which is the standard for C/Rust/TinyGo
	builder := m.runtime.NewHostModuleBuilder("env")

	// 1. Get Header: agbero_get_header(key_ptr, key_len, val_ptr, max_len) -> val_len
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			// Logic to read header from ctx and write to WASM memory
			req := ctx.Value("req").(*http.Request)

			// If "headers" not in access list, return 0
			if !m.config.HasAccess("headers") {
				stack[0] = 0
				return
			}

			// Read arguments from stack
			keyPtr := uint32(stack[0])
			keyLen := uint32(stack[1])
			bufPtr := uint32(stack[2])
			bufLen := uint32(stack[3])

			// Read key from WASM memory
			keyBytes, _ := mod.Memory().Read(keyPtr, keyLen)
			val := req.Header.Get(string(keyBytes))

			// Write value back
			valBytes := []byte(val)
			if uint32(len(valBytes)) > bufLen {
				valBytes = valBytes[:bufLen] // Truncate if buffer too small
			}
			mod.Memory().Write(bufPtr, valBytes)

			stack[0] = uint64(len(valBytes))
		}),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		Export("agbero_get_header")

	// 2. Set Header: agbero_set_header(key_ptr, key_len, val_ptr, val_len)
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			w := ctx.Value("w").(http.ResponseWriter)

			// Security check
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

	// 3. Get Config: agbero_get_config(buf_ptr, buf_len) -> actual_len
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
			bufPtr := uint32(stack[0])
			bufLen := uint32(stack[1])

			if uint32(len(m.configJSON)) > bufLen {
				// Buffer too small, just return needed size
				stack[0] = uint64(len(m.configJSON))
				return
			}

			mod.Memory().Write(bufPtr, m.configJSON)
			stack[0] = uint64(len(m.configJSON))
		}),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI32}).
		Export("agbero_get_config")

	// 4. Block/Allow: agbero_done(status_code)
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
