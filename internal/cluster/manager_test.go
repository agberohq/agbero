package cluster

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/olekukonko/ll"
)

// mockHandler captures updates for assertions
type mockHandler struct {
	updates map[string]string
}

func (m *mockHandler) OnClusterChange(key string, value []byte, deleted bool) {
	if m.updates == nil {
		m.updates = make(map[string]string)
	}
	if deleted {
		delete(m.updates, key)
	} else {
		m.updates[key] = string(value)
	}
}

func getFreePort() int {
	addr, _ := net.ResolveTCPAddr("tcp", "localhost:0")
	l, _ := net.ListenTCP("tcp", addr)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestClusterReplication(t *testing.T) {
	logger := ll.New("test").Enable()

	port1 := getFreePort()
	port2 := getFreePort()

	h1 := &mockHandler{}
	node1, err := NewManager(Config{
		Name:     "node1",
		BindAddr: "127.0.0.1",
		BindPort: port1,
	}, h1, logger)
	if err != nil {
		t.Fatalf("failed to start node1: %v", err)
	}
	defer node1.Shutdown()

	h2 := &mockHandler{}
	node2, err := NewManager(Config{
		Name:     "node2",
		BindAddr: "127.0.0.1",
		BindPort: port2,
		Seeds:    []string{fmt.Sprintf("127.0.0.1:%d", port1)},
	}, h2, logger)
	if err != nil {
		t.Fatalf("failed to start node2: %v", err)
	}
	defer node2.Shutdown()

	// Wait for join
	time.Sleep(2 * time.Second)
	if len(node1.Members()) != 2 {
		t.Fatalf("cluster failed to join, members: %v", node1.Members())
	}

	// Test 1: Node 1 sets data -> Node 2 receives
	key := "route:test"
	val := []byte("payload")
	node1.Set(key, val)

	time.Sleep(500 * time.Millisecond) // Allow gossip propagation

	got, ok := node2.Get(key)
	if !ok || string(got) != string(val) {
		t.Errorf("Node2 failed to receive update. Got %q, want %q", got, val)
	}

	// Test 2: Handler invocation check
	if h2.updates[key] != string(val) {
		t.Errorf("Node2 handler not triggered correctly. Map: %v", h2.updates)
	}

	// Test 3: Node 2 updates data (LWW) -> Node 1 receives
	newVal := []byte("payload_updated")
	node2.Set(key, newVal)

	time.Sleep(500 * time.Millisecond)

	got1, ok1 := node1.Get(key)
	if !ok1 || string(got1) != string(newVal) {
		t.Errorf("Node1 failed to receive update from Node2. Got %q, want %q", got1, newVal)
	}

	// Test 4: Deletion
	node1.Delete(key)
	time.Sleep(500 * time.Millisecond)

	if _, ok := node2.Get(key); ok {
		t.Error("Node2 still has key after deletion")
	}
}
