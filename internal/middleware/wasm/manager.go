package wasm

import (
	"context"
	"encoding/json"
	"os"

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
}

func NewManager(ctx context.Context, logger *ll.Logger, cfg *alaye.Wasm) (*Manager, error) {
	code, err := os.ReadFile(cfg.Module)
	if err != nil {
		return nil, err
	}

	safeConfig := make(map[string]string)
	if cfg.Config != nil {
		for k, v := range cfg.Config {
			safeConfig[k] = v
		}
	}

	cfgJSON, err := json.Marshal(safeConfig)
	if err != nil {
		return nil, err
	}

	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	compiled, err := r.CompileModule(ctx, code)
	if err != nil {
		return nil, err
	}

	return &Manager{
		logger:     logger,
		runtime:    r,
		compiled:   compiled,
		config:     cfg,
		configJSON: cfgJSON,
	}, nil
}

func (m *Manager) Close(ctx context.Context) {
	m.runtime.Close(ctx)
}

func (m *Manager) GetInstance(ctx context.Context) (*Instance, error) {
	// Create a new module instance per request for total isolation
	modConfig := wazero.NewModuleConfig().
		WithStdout(os.Stdout).
		WithStderr(os.Stderr)

	mod, err := m.runtime.InstantiateModule(ctx, m.compiled, modConfig)
	if err != nil {
		return nil, err
	}

	return &Instance{
		m:   m,
		c:   modConfig,
		mod: mod,
	}, nil
}

// CloseInstance must be called via defer to free WASM memory
func (m *Manager) CloseInstance(ctx context.Context, i *Instance) {
	if i != nil && i.mod != nil {
		_ = i.mod.Close(ctx)
	}
}
