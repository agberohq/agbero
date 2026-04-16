package cluster

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/olekukonko/ll"
)

type mockHandler struct {
	mu         sync.RWMutex
	updates    map[string]string
	certs      map[string]bool
	challenges map[string]string
}

func (m *mockHandler) OnClusterChange(key string, value []byte, deleted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updates == nil {
		m.updates = make(map[string]string)
	}
	if deleted {
		delete(m.updates, key)
	} else {
		m.updates[key] = string(append([]byte(nil), value...))
	}
}

func (m *mockHandler) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.certs == nil {
		m.certs = make(map[string]bool)
	}
	m.certs[domain] = true
	return nil
}

func (m *mockHandler) OnClusterChallenge(token, keyAuth string, deleted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.challenges == nil {
		m.challenges = make(map[string]string)
	}
	if deleted {
		delete(m.challenges, token)
	} else {
		m.challenges[token] = keyAuth
	}
}

func (m *mockHandler) get(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.updates[key]
	return v, ok
}

func (m *mockHandler) has(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.updates[key]
	return ok
}

func TestClusterReplication(t *testing.T) {
	logger := ll.New("test").Disable()

	port1 := zulu.PortFree()
	port2 := zulu.PortFree()

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

	time.Sleep(2 * time.Second)
	if len(node1.Members()) != 2 {
		t.Fatalf("cluster failed to join, members: %v", node1.Members())
	}

	key := "route:test"
	val := []byte("payload")
	node1.Set(key, val)

	time.Sleep(500 * time.Millisecond)

	got, ok := node2.Get(key)
	if !ok || string(got) != string(val) {
		t.Errorf("Node2 failed to receive update. Got %q, want %q", got, val)
	}

	if got, ok := h2.get(key); !ok || got != string(val) {
		t.Errorf("Node2 handler not triggered correctly")
	}

	newVal := []byte("payload_updated")
	node2.Set(key, newVal)

	time.Sleep(500 * time.Millisecond)

	got1, ok1 := node1.Get(key)
	if !ok1 || string(got1) != string(newVal) {
		t.Errorf("Node1 failed to receive update from Node2. Got %q, want %q", got1, newVal)
	}

	node1.Delete(key)
	time.Sleep(500 * time.Millisecond)

	if _, ok := node2.Get(key); ok {
		t.Error("Node2 still has key after deletion")
	}
}

type testHandler struct {
	mu         sync.RWMutex
	data       map[string][]byte
	certs      map[string]bool
	challenges map[string]string
}

func (h *testHandler) OnClusterChange(key string, value []byte, deleted bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.data == nil {
		h.data = make(map[string][]byte)
	}
	if deleted {
		delete(h.data, key)
	} else {
		h.data[key] = append([]byte(nil), value...)
	}
}

func (h *testHandler) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.certs == nil {
		h.certs = make(map[string]bool)
	}
	h.certs[domain] = true
	return nil
}

func (h *testHandler) OnClusterChallenge(token, keyAuth string, deleted bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.challenges == nil {
		h.challenges = make(map[string]string)
	}
	if deleted {
		delete(h.challenges, token)
	} else {
		h.challenges[token] = keyAuth
	}
}

func (h *testHandler) get(key string) ([]byte, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	v, ok := h.data[key]
	if ok {
		return append([]byte(nil), v...), true
	}
	return nil, false
}

func (h *testHandler) has(key string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.data[key]
	return ok
}

func TestClusterSync(t *testing.T) {
	logger := ll.New("test").Disable()

	h1 := &testHandler{data: make(map[string][]byte)}
	c1, err := NewManager(Config{
		BindAddr: "127.0.0.1",
		BindPort: 0,
		Name:     "node1",
	}, h1, logger)
	if err != nil {
		t.Fatalf("node1 init failed: %v", err)
	}
	defer c1.Shutdown()

	port1 := c1.list.LocalNode().Port

	h2 := &testHandler{data: make(map[string][]byte)}
	c2, err := NewManager(Config{
		BindAddr: "127.0.0.1",
		BindPort: 0,
		Name:     "node2",
		Seeds:    []string{fmt.Sprintf("127.0.0.1:%d", port1)},
	}, h2, logger)
	if err != nil {
		t.Fatalf("node2 init failed: %v", err)
	}
	defer c2.Shutdown()

	time.Sleep(2 * time.Second)
	if c1.list.NumMembers() != 2 || c2.list.NumMembers() != 2 {
		t.Fatalf("nodes failed to join: n1=%d n2=%d", c1.list.NumMembers(), c2.list.NumMembers())
	}

	key := "test-key"
	val := []byte("hello-world")
	c1.Set(key, val)

	time.Sleep(1 * time.Second)

	if got, ok := h2.get(key); !ok || string(got) != string(val) {
		t.Fatalf("node2 did not receive update. got %v, want %v", string(got), string(val))
	}

	c2.Delete(key)
	time.Sleep(1 * time.Second)

	if h1.has(key) {
		t.Fatal("node1 did not receive deletion")
	}
	if h2.has(key) {
		t.Fatal("node2 failed to delete local key")
	}
}

func TestDelegate_LWW_and_Tombstones(t *testing.T) {
	logger := ll.New("test").Disable()
	metrics := &RealMetrics{}
	cipher, _ := security.NewCipher("test-secret-key-1234567890123456")
	configMgr := NewDistributor(logger, "")
	del := newDelegate(Config{}, nil, logger, metrics, cipher, configMgr)

	ts1 := time.Now().UnixNano()
	env1 := Envelope{Key: "foo", Op: OpSet, Value: []byte("v1"), Timestamp: ts1}
	del.apply(env1, true)

	val, ok := del.get("foo")
	if !ok || string(val) != "v1" {
		t.Fatalf("expected v1, got %v", string(val))
	}

	envOld := Envelope{Key: "foo", Op: OpSet, Value: []byte("v0"), Timestamp: ts1 - 1000}
	del.apply(envOld, false)

	val, ok = del.get("foo")
	if !ok || string(val) != "v1" {
		t.Fatalf("LWW failed: expected v1 to persist over v0")
	}

	ts2 := ts1 + 1000
	env2 := Envelope{Key: "foo", Op: OpSet, Value: []byte("v2"), Timestamp: ts2}
	del.apply(env2, false)

	val, ok = del.get("foo")
	if !ok || string(val) != "v2" {
		t.Fatalf("LWW failed: expected v2 to overwrite v1")
	}

	ts3 := ts2 + 1000
	envDel := Envelope{Key: "foo", Op: OpDel, Timestamp: ts3}
	del.apply(envDel, false)

	_, ok = del.get("foo")
	if ok {
		t.Fatalf("expected key to be deleted")
	}

	del.mu.RLock()
	internalEnv, exists := del.store["foo"]
	del.mu.RUnlock()

	if !exists {
		t.Fatalf("tombstone missing from internal store")
	}
	if internalEnv.Op != OpDel {
		t.Fatalf("tombstone Op mismatch")
	}
	if internalEnv.Value != nil {
		t.Fatalf("tombstone value should be nil")
	}

	envStale := Envelope{Key: "foo", Op: OpSet, Value: []byte("v2"), Timestamp: ts2}
	del.apply(envStale, false)

	_, ok = del.get("foo")
	if ok {
		t.Fatalf("stale update revived deleted key")
	}
}

func TestConfigManager_ChecksumEchoPrevention(t *testing.T) {
	logger := ll.New("test").Disable()
	tmpDir := t.TempDir()
	cm := NewDistributor(logger, expect.NewFolder(tmpDir))

	domain := "test"
	content := []byte("route / { backend { address \"http://localhost:8080\" } }")

	if !cm.ShouldBroadcast(domain, content) {
		t.Error("ShouldBroadcast should return true for genuinely new content")
	}

	_, _ = cm.PreparePayload(domain, content, false, "node1")

	if cm.ShouldBroadcast(domain, content) {
		t.Error("ShouldBroadcast should return false for identical content to prevent echo loops")
	}

	different := []byte("route /different { backend { address \"http://localhost:9090\" } }")
	if !cm.ShouldBroadcast(domain, different) {
		t.Error("ShouldBroadcast should return true for different content")
	}
}

func TestConfigManager_ValidationRejectsBadHCL(t *testing.T) {
	logger := ll.New("test").Disable()
	tmpDir := t.TempDir()
	cm := NewDistributor(logger, expect.NewFolder(tmpDir))

	badHCL := []byte("invalid {{{ hcl syntax")
	if err := cm.validateHCL(tmpDir+"/test.hcl", badHCL); err == nil {
		t.Error("validateHCL should reject invalid HCL")
	} else {
		t.Logf("Bad HCL correctly rejected: %v", err)
	}

	// Valid host HCL with required fields (domains and route with backend)
	goodHCL := []byte(`domains = ["test.com"]

route "/" {
  backend {
    server {
      address = "http://localhost:8080"
    }
  }
}`)
	if err := cm.validateHCL(tmpDir+"/test.hcl", goodHCL); err != nil {
		t.Errorf("validateHCL should accept valid HCL: %v", err)
	}
}

func TestConfigManager_DeletionHandling(t *testing.T) {
	logger := ll.New("test").Disable()
	tmpDir := t.TempDir()
	cm := NewDistributor(logger, expect.NewFolder(tmpDir))

	domain := "delete-test"
	configPath := tmpDir + "/" + domain + ".hcl"

	if err := cm.writeAtomic(configPath, []byte("test")); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	payload := ConfigPayload{
		Domain:    domain,
		Deleted:   true,
		Checksum:  cm.calculateChecksum(nil),
		Timestamp: time.Now().UnixNano(),
		NodeID:    "test-node",
	}
	cm.Apply(payload)

	if _, err := os.Stat(configPath); err == nil {
		t.Error("file should be deleted after Apply with Deleted=true")
	}
}

func TestConfigManager_CompressionRoundTrip(t *testing.T) {
	logger := ll.New("test").Disable()
	cm := NewDistributor(logger, "")

	original := []byte(`route "/" { backend { address "http://localhost:8080" } }`)

	compressed, err := cm.compress(original)
	if err != nil {
		t.Fatalf("compress failed: %v", err)
	}

	decompressed, err := cm.decompress(compressed)
	if err != nil {
		t.Fatalf("decompress failed: %v", err)
	}

	if string(decompressed) != string(original) {
		t.Errorf("round-trip mismatch: got %q, want %q", decompressed, original)
	}
}

func TestManager_FullSyncUsesExportedAPI(t *testing.T) {
	logger := ll.New("test").Disable()

	port1 := zulu.PortFree()
	port2 := zulu.PortFree()

	h1 := &mockHandler{}
	m1, err := NewManager(Config{
		Name:     "sync-node1",
		BindAddr: "127.0.0.1",
		BindPort: port1,
	}, h1, logger)
	if err != nil {
		t.Fatalf("failed to start m1: %v", err)
	}
	defer m1.Shutdown()

	h2 := &mockHandler{}
	m2, err := NewManager(Config{
		Name:     "sync-node2",
		BindAddr: "127.0.0.1",
		BindPort: port2,
		Seeds:    []string{fmt.Sprintf("127.0.0.1:%d", port1)},
	}, h2, logger)
	if err != nil {
		t.Fatalf("failed to start m2: %v", err)
	}
	defer m2.Shutdown()

	time.Sleep(2 * time.Second)

	key := "sync:test"
	val := []byte("sync-payload")
	m1.Set(key, val)

	time.Sleep(1 * time.Second)

	if got, ok := h2.get(key); !ok || got != string(val) {
		t.Errorf("sync failed: node2 got %q, want %q", got, val)
	}
}
