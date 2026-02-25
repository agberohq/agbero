package wasm

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Manager manages WASM module and instance pooling
type Manager struct {
	logger     *ll.Logger
	runtime    wazero.Runtime
	compiled   wazero.CompiledModule
	config     *alaye.Wasm
	configJSON []byte

	pool sync.Pool // Pool of reusable instances
}

// NewManager initializes the WASM runtime and precompiled module
func NewManager(ctx context.Context, logger *ll.Logger, cfg *alaye.Wasm) (*Manager, error) {
	code, err := os.ReadFile(cfg.Module)
	if err != nil {
		return nil, err
	}

	// Safe copy of config
	safeConfig := make(map[string]string)
	if cfg.Config != nil {
		maps.Copy(safeConfig, cfg.Config)
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

	m := &Manager{
		logger:     logger.Namespace("wasm"),
		runtime:    r,
		compiled:   compiled,
		config:     cfg,
		configJSON: cfgJSON,
	}

	// Initialize sync.Pool for module instances
	m.pool.New = func() any {
		modConfig := wazero.NewModuleConfig().
			WithStdout(os.Stdout).
			WithStderr(os.Stderr)
		mod, err := m.runtime.InstantiateModule(ctx, m.compiled, modConfig)
		if err != nil {
			m.logger.Error("failed to instantiate wasm module for pool: %v", err)
			return nil
		}
		return &Instance{
			m:   m,
			c:   modConfig,
			mod: mod,
		}
	}

	return m, nil
}

// Close shuts down the WASM runtime
func (m *Manager) Close(ctx context.Context) {
	m.runtime.Close(ctx)
}

// GetInstance returns a pooled WASM instance
func (m *Manager) GetInstance(ctx context.Context) (*Instance, error) {
	obj := m.pool.Get()
	if obj == nil {
		// Pool.New failed, instantiate manually
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
	inst := obj.(*Instance)
	return inst, nil
}

// CloseInstance returns the WASM instance to the pool
func (m *Manager) CloseInstance(ctx context.Context, i *Instance) {
	if i == nil || i.mod == nil {
		return
	}
	m.pool.Put(i)
}
