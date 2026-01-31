package wasm

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type Manager struct {
	logger     *ll.Logger
	runtime    wazero.Runtime
	compiled   wazero.CompiledModule
	config     *alaye.Wasm
	configJSON []byte

	pool sync.Pool
}

func NewManager(ctx context.Context, logger *ll.Logger, cfg *alaye.Wasm) (*Manager, error) {
	// 1. Read the WASM binary
	code, err := os.ReadFile(cfg.Module)
	if err != nil {
		return nil, err
	}

	// Explicitly isolate the config map to ensure no parent struct leakage.
	// We create a new map to be absolutely sure we strictly serialize key-values.
	safeConfig := make(map[string]string)
	if cfg.Config != nil {
		for k, v := range cfg.Config {
			safeConfig[k] = v
		}
	}

	// 2. Serialize user config to JSON once
	cfgJSON, err := json.Marshal(safeConfig)
	if err != nil {
		return nil, err
	}

	// 3. Create Runtime
	r := wazero.NewRuntime(ctx)

	// 4. Instantiate WASI (standard system calls like print)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	// 5. Compile the module (this optimizes it)
	compiled, err := r.CompileModule(ctx, code)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		logger:     logger,
		runtime:    r,
		compiled:   compiled,
		config:     cfg,
		configJSON: cfgJSON,
	}

	// 6. Setup the Instance Pool
	m.pool.New = func() any {
		// Create a new instance attached to our host functions
		// We define the host functions in a separate file (host.go)
		modConfig := wazero.NewModuleConfig().
			WithStdout(os.Stdout).
			WithStderr(os.Stderr)

		// Create a transient host module just for this instance context
		// Note: In a real advanced impl, we'd reuse the host module definition
		return &Instance{
			m: m,
			c: modConfig,
		}
	}

	return m, nil
}

func (m *Manager) Close(ctx context.Context) {
	m.runtime.Close(ctx)
}

func (m *Manager) GetInstance(ctx context.Context) (*Instance, error) {
	inst := m.pool.Get().(*Instance)

	// We instantiate the module for this specific request
	// This ensures clean memory for every request
	// wazero optimizes this to be very fast
	mod, err := m.runtime.InstantiateModule(ctx, m.compiled, inst.c)
	if err != nil {
		return nil, err
	}
	inst.mod = mod
	return inst, nil
}

func (m *Manager) PutInstance(ctx context.Context, i *Instance) {
	// Close the instance to free memory/reset state
	if i.mod != nil {
		i.mod.Close(ctx)
	}
	m.pool.Put(i)
}
