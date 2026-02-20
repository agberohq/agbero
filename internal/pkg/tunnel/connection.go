package tunnel

import (
	"net"
	"sync"
)

// ConnectionPool manages active tunnel connections to ensure clean shutdown
type ConnectionPool struct {
	mu          sync.Mutex
	connections map[net.Conn]bool
}

func NewConnectionPool() *ConnectionPool {
	return &ConnectionPool{
		connections: make(map[net.Conn]bool),
	}
}

func (p *ConnectionPool) Add(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connections[conn] = true
}

func (p *ConnectionPool) Remove(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.connections, conn)
}

func (p *ConnectionPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for conn := range p.connections {
		_ = conn.Close()
	}
	// Re-initialize map to prevent using closed connections if object is reused
	p.connections = make(map[net.Conn]bool)
}

func (p *ConnectionPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.connections)
}
