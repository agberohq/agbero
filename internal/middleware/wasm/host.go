package wasm

import (
	"context"
	"net/http"

	"github.com/tetratelabs/wazero/api"
)

const (
	maxHeaderKeySize = 1024
	maxHeaderValSize = 4096
	emptyReturnVal   = 0
)

type RequestContext struct {
	W    http.ResponseWriter
	R    *http.Request
	Next bool
}

// ExportHostFunctions registers internal proxy API hooks into the WASM runtime.
// It is idempotent: the sync.Once guard ensures the "env" host module is
// compiled and instantiated exactly once per Manager lifetime. Calling it more
// than once would cause wazero to return "module env has already been
// instantiated" and waste CPU compiling modules that are immediately discarded.
func (m *Manager) ExportHostFunctions() {
	m.hostOnce.Do(func() {
		builder := m.runtime.NewHostModuleBuilder("env")

		builder.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
				rcRaw := ctx.Value(CtxKeyRequest)
				if rcRaw == nil {
					stack[0] = emptyReturnVal
					return
				}
				rc, ok := rcRaw.(*RequestContext)
				if !ok || rc == nil || rc.R == nil {
					stack[0] = emptyReturnVal
					return
				}
				req := rc.R

				if !m.config.HasAccess("headers") {
					stack[0] = emptyReturnVal
					return
				}

				keyPtr := uint32(stack[0])
				keyLen := uint32(stack[1])
				bufPtr := uint32(stack[2])
				bufLen := uint32(stack[3])

				if keyLen > maxHeaderKeySize {
					stack[0] = emptyReturnVal
					return
				}

				keyBytes, ok := mod.Memory().Read(keyPtr, keyLen)
				if !ok {
					stack[0] = emptyReturnVal
					return
				}

				val := req.Header.Get(string(keyBytes))
				valBytes := []byte(val)
				totalLen := uint64(len(valBytes))

				writeLen := min(uint32(totalLen), bufLen)

				if writeLen > 0 {
					if !mod.Memory().Write(bufPtr, valBytes[:writeLen]) {
						stack[0] = emptyReturnVal
						return
					}
				}

				stack[0] = totalLen
			}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
			Export("agbero_get_header")

		builder.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
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

				if keyLen > maxHeaderKeySize || valLen > maxHeaderValSize {
					return
				}

				keyBytes, ok := mod.Memory().Read(keyPtr, keyLen)
				if !ok {
					return
				}
				valBytes, ok := mod.Memory().Read(valPtr, valLen)
				if !ok {
					return
				}

				w.Header().Set(string(keyBytes), string(valBytes))
			}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{}).
			Export("agbero_set_header")

		builder.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
				bufPtr := uint32(stack[0])
				bufLen := uint32(stack[1])
				totalLen := uint64(len(m.configJSON))

				writeLen := min(uint32(totalLen), bufLen)

				if writeLen > 0 {
					if !mod.Memory().Write(bufPtr, m.configJSON[:writeLen]) {
						stack[0] = emptyReturnVal
						return
					}
				}

				stack[0] = totalLen
			}), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
			Export("agbero_get_config")

		builder.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
				status := uint32(stack[0])
				rcRaw := ctx.Value(CtxKeyRequest)
				if rcRaw == nil {
					return
				}
				rc, ok := rcRaw.(*RequestContext)
				if !ok || rc == nil {
					return
				}

				if status != emptyReturnVal {
					rc.W.WriteHeader(int(status))
					rc.Next = false
				} else {
					rc.Next = true
				}
			}), []api.ValueType{api.ValueTypeI32}, []api.ValueType{}).
			Export("agbero_done")

		_, _ = builder.Instantiate(context.Background())
	})
}
