package tunnel

import (
	"fmt"
	"net"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/tunnel/virtual"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

type Mode int

const (
	ModeNone Mode = iota
	ModeClient
	ModeGateway
)

// Manager handles the lifecycle of FRP Clients and Servers.
type Manager struct {
	logger *ll.Logger
	mu     sync.RWMutex

	// Clients: Map of HostID -> Local Listener Port
	// Used in Sidecar Mode: Traffic from FRP Tunnel -> Local Port -> Agbero
	activePorts map[string]int

	// Gateway: The virtual listener for hijacking /_connect requests
	virtualListeners map[string]*virtual.Listener
}

func NewManager(logger *ll.Logger) *Manager {
	return &Manager{
		logger:           logger.Namespace("tunnel"),
		activePorts:      make(map[string]int),
		virtualListeners: make(map[string]*virtual.Listener),
	}
}

// GetIngressPort returns the local loopback port assigned to a specific host
// for receiving tunnel traffic.
func (m *Manager) GetIngressPort(hostID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activePorts[hostID]
}

// RegisterHost analyzes a host config and sets up necessary tunnel infrastructure.
// Returns the allocated local port if the host is a Tunnel Client.
func (m *Manager) RegisterHost(hostID string, cfg *alaye.Host) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cleanup existing if reloading
	if port, exists := m.activePorts[hostID]; exists {
		// In a real implementation, we would stop the running frpc instance here
		delete(m.activePorts, hostID)
		m.logger.Fields("host", hostID, "old_port", port).Debug("tunnel: re-registering host")
	}

	if cfg.Tunnel == nil {
		return 0, nil
	}

	// Mode A: Tunnel Client (Sidecar)
	if cfg.Tunnel.Client != nil && cfg.Tunnel.Client.Enabled {
		port, err := getFreePort()
		if err != nil {
			return 0, fmt.Errorf("tunnel: failed to allocate local ingress port: %w", err)
		}

		m.activePorts[hostID] = port
		m.logger.Fields("host", hostID, "local_port", port, "remote", cfg.Tunnel.Client.ServerAddr).
			Info("tunnel: client enabled, allocated local ingress")

		// TODO: Phase 3 - Start frpc instance here pointing to 127.0.0.1:port
		return port, nil
	}

	// Mode B: Gateway
	if cfg.Tunnel.Gateway != nil && cfg.Tunnel.Gateway.Enabled {
		// Ensure we have a virtual listener for hijacking
		if _, exists := m.virtualListeners[hostID]; !exists {
			vl := virtual.NewListener(nil) // Addr doesn't matter for virtual
			m.virtualListeners[hostID] = vl
			m.logger.Fields("host", hostID).Info("tunnel: gateway enabled")

			// TODO: Phase 3 - Start frps instance here using vl as listener
		}
	}

	return 0, nil
}

// GetVirtualListener returns the listener for connection hijacking (Gateway Mode).
func (m *Manager) GetVirtualListener(hostID string) *virtual.Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.virtualListeners[hostID]
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, l := range m.virtualListeners {
		l.Close()
	}
	// TODO: Stop all frpc/frps instances
	return nil
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
