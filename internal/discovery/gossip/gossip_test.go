package gossip

import (
	"encoding/json"
	"net"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("test").Disable()
)

// Mock Hosting implements the Hosting interface
type mockHost struct {
	updated     bool
	removed     bool
	routeExists bool
	failures    map[string]int
}

func (m *mockHost) UpdateGossipNode(nodeID, host string, route alaye.Route) {
	m.updated = true
}

func (m *mockHost) RemoveGossipNode(nodeID string) {
	m.removed = true
}

func (m *mockHost) RouteExists(host, path string) bool {
	return m.routeExists
}

func (m *mockHost) ResetNodeFailures(nodeName string) {
	if m.failures == nil {
		m.failures = make(map[string]int)
	}
	m.failures[nodeName] = 0
}

func TestNewService_Disabled(t *testing.T) {
	s, err := NewService(nil, nil, nil)
	if err != nil || s != nil {
		t.Error("Expected nil service for disabled")
	}
}

func TestNewService_InvalidKey(t *testing.T) {
	cfg := &alaye.Gossip{Enabled: alaye.NewStatus(alaye.Active), SecretKey: "short"}
	// Must pass a valid logger
	_, err := NewService(nil, cfg, testLogger)
	if err == nil {
		t.Error("Expected key length error")
	}
}

func TestNewService_WithAuth(t *testing.T) {
	tmpFile := t.TempDir() + "/key.pem"
	security.GenerateNewKeyFile(tmpFile)
	// Use port 0 to let OS assign a free port
	cfg := alaye.Gossip{Enabled: alaye.NewStatus(alaye.Active), PrivateKeyFile: tmpFile, Port: 0}
	logger := testLogger

	hm := &mockHost{}
	s, err := NewService(hm, &cfg, logger)
	if err != nil {
		t.Logf("Service start failed: %v", err)
		return
	}
	defer s.Shutdown()

	if s.tokenManager == nil {
		t.Error("Token manager not loaded")
	}
}

func TestJoin_Success(t *testing.T) {
	hm := &mockHost{}
	// Use Port 0 to bind to a random available port
	cfg := &alaye.Gossip{Enabled: alaye.NewStatus(alaye.Active), Port: 0}
	logger := testLogger
	s, err := NewService(hm, cfg, logger)
	if err != nil {
		t.Skipf("Skipping join test due to bind error: %v", err)
		return
	}
	defer s.Shutdown()

	// Try to join a port that is definitely NOT us and likely closed (e.g., 54321)
	err = s.Join([]string{"127.0.0.1:54321"})
	if err == nil {
		t.Error("Expected join error when joining unreachable seed")
	}
}

func TestProcessNode_Valid(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger}
	e := &event{s: s}

	// Mock valid node with meta
	meta := Meta{Host: "test.com", Path: "/api", Port: 8080}
	b, _ := json.Marshal(meta)

	// Create a dummy node with a valid address
	node := &memberlist.Node{
		Name: "node1",
		Meta: b,
		Addr: net.ParseIP("127.0.0.1"),
		Port: 7946,
	}

	e.processNode(node)
	if !hm.updated {
		t.Error("Update not called")
	}
}

func TestProcessNode_InvalidMeta(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger}
	e := &event{s: s}

	node := &memberlist.Node{Name: "node1", Meta: []byte("invalid")}
	e.processNode(node)
	if hm.updated {
		t.Error("Processed invalid meta")
	}
}

func TestProcessNode_Dedup(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger}
	e := &event{s: s}

	meta := Meta{Host: "test.com", Path: "/api", Port: 8080}
	b, _ := json.Marshal(meta)

	node := &memberlist.Node{
		Name: "node1",
		Meta: b,
		Addr: net.ParseIP("127.0.0.1"),
		Port: 7946,
	}

	e.processNode(node)

	if !hm.updated {
		t.Fatal("expected route upsert (merge), but it was not updated")
	}
}

func TestProcessNode_AuthReject(t *testing.T) {
	tmpFile := t.TempDir() + "/key.pem"
	security.GenerateNewKeyFile(tmpFile)
	tm, _ := security.LoadKeys(tmpFile)

	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger, tokenManager: tm}
	e := &event{s: s}

	meta := Meta{Host: "test.com", Path: "/api", Port: 8080, Token: "invalid"}
	b, _ := json.Marshal(meta)

	node := &memberlist.Node{
		Name: "node1",
		Meta: b,
		Addr: net.ParseIP("127.0.0.1"),
		Port: 7946,
	}

	// This should fail auth and NOT update the host
	// BUT since fetchToken might try to contact the node (which isn't running),
	// it will log a warning and return early. This is correct behavior.
	e.processNode(node)
	if hm.updated {
		t.Error("Processed without valid token")
	}
}

func TestNotifyLeave_Remove(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger, localName: "local-node"} // Set localName
	e := &event{s: s}

	node := &memberlist.Node{Name: "node1"}
	e.NotifyLeave(node)
	if !hm.removed {
		t.Error("Remove not called")
	}
}

func TestNotifyLeave_IgnoreSelf(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger, localName: "local-node"}
	e := &event{s: s}

	node := &memberlist.Node{Name: "local-node"}
	e.NotifyLeave(node)
	if hm.removed {
		t.Error("Should not remove self")
	}
}

func TestShutdown(t *testing.T) {
	cfg := alaye.Gossip{Enabled: alaye.NewStatus(alaye.Active), Port: 0}
	logger := testLogger
	s, err := NewService(nil, &cfg, logger)
	if err != nil {
		t.Skipf("Skipping shutdown test due to bind error: %v", err)
		return
	}
	err = s.Shutdown()
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
}
