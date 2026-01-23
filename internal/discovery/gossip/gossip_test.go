package gossip

import (
	"encoding/json"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/security"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/hashicorp/memberlist"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("test").Enable()
)

// Mock HostManager
type mockHost struct {
	updated     bool
	removed     bool
	routeExists bool
	failures    map[string]int
}

func (m *mockHost) UpdateGossipNode(nodeID, host string, route woos.Route) {
	m.updated = true
}

func (m *mockHost) RemoveGossipNode(nodeID string) {
	m.removed = true
}

func (m *mockHost) RouteExists(host, path string) bool {
	return m.routeExists
}

func (m *mockHost) ResetNodeFailures(nodeName string) {
	m.failures[nodeName] = 0
}

func TestNewService_Disabled(t *testing.T) {
	s, err := NewService(nil, nil, nil)
	if err != nil || s != nil {
		t.Error("Expected nil service for disabled")
	}
}

func TestNewService_InvalidKey(t *testing.T) {
	cfg := &woos.GossipConfig{Enabled: true, SecretKey: "short"}
	_, err := NewService(nil, cfg, nil)
	if err == nil {
		t.Error("Expected key length error")
	}
}

func TestNewService_WithAuth(t *testing.T) {
	tmpFile := t.TempDir() + "/key.pem"
	security.GenerateNewKeyFile(tmpFile)
	cfg := &woos.GossipConfig{Enabled: true, PrivateKeyFile: tmpFile}
	logger := testLogger
	s, err := NewService(nil, cfg, logger)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if s.tokenManager == nil {
		t.Error("Token manager not loaded")
	}
	s.Shutdown()
}

func TestJoin_Success(t *testing.T) {
	hm := &mockHost{}
	cfg := &woos.GossipConfig{Enabled: true}
	logger := testLogger
	s, _ := NewService(hm, cfg, logger)
	defer s.Shutdown()

	// Mock seeds (won't connect, but test call)
	err := s.Join([]string{"127.0.0.1:7946"})
	if err == nil { // Expect error since no real cluster
		t.Error("Expected join error in test")
	}
}

func TestProcessNode_Valid(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger}
	e := &eventDelegate{s: s}

	meta := AppMeta{Host: "test.com", Path: "/api", Port: 8080}
	b, _ := json.Marshal(meta)
	node := &memberlist.Node{Name: "node1", Meta: b}

	e.processNode(node)
	if !hm.updated {
		t.Error("Update not called")
	}
}

func TestProcessNode_InvalidMeta(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger}
	e := &eventDelegate{s: s}

	node := &memberlist.Node{Name: "node1", Meta: []byte("invalid")}
	e.processNode(node)
	if hm.updated {
		t.Error("Processed invalid meta")
	}
}

func TestProcessNode_Dedup(t *testing.T) {
	hm := &mockHost{routeExists: true}
	s := &Service{hm: hm, logger: testLogger}
	e := &eventDelegate{s: s}

	meta := AppMeta{Host: "test.com", Path: "/api", Port: 8080}
	b, _ := json.Marshal(meta)
	node := &memberlist.Node{Name: "node1", Meta: b}

	e.processNode(node)
	if hm.updated {
		t.Error("Processed duplicate route")
	}
}

func TestProcessNode_AuthReject(t *testing.T) {
	tmpFile := t.TempDir() + "/key.pem"
	security.GenerateNewKeyFile(tmpFile)
	tm, _ := security.LoadKeys(tmpFile)

	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger, tokenManager: tm}
	e := &eventDelegate{s: s}

	meta := AppMeta{Host: "test.com", Path: "/api", Port: 8080, Token: "invalid"}
	b, _ := json.Marshal(meta)
	node := &memberlist.Node{Name: "node1", Meta: b}

	e.processNode(node)
	if hm.updated {
		t.Error("Processed without valid token")
	}
}

func TestNotifyAlive_ResetFailures(t *testing.T) {
	hm := &mockHost{failures: map[string]int{"node1": 5}}
	s := &Service{hm: hm, logger: testLogger}
	e := &eventDelegate{s: s}

	node := &memberlist.Node{Name: "node1"}
	e.NotifyAlive(node)

	if hm.failures["node1"] != 0 {
		t.Error("Failures not reset")
	}
}

func TestNotifyLeave_Remove(t *testing.T) {
	hm := &mockHost{}
	s := &Service{hm: hm, logger: testLogger}
	e := &eventDelegate{s: s}

	node := &memberlist.Node{Name: "node1"}
	e.NotifyLeave(node)
	if !hm.removed {
		t.Error("Remove not called")
	}
}

func TestShutdown(t *testing.T) {
	cfg := &woos.GossipConfig{Enabled: true}
	logger := testLogger
	s, _ := NewService(nil, cfg, logger)
	err := s.Shutdown()
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
}
