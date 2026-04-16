package cluster

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/olekukonko/ll"
)

var (
	testLoogerCluster = ll.New("test").Disable()
)

type MockHandler struct {
	Changes    map[string][]byte
	Certs      map[string]bool
	Challenges map[string]string
	Deleted    map[string]bool
}

func NewMockHandler() *MockHandler {
	return &MockHandler{
		Changes:    make(map[string][]byte),
		Certs:      make(map[string]bool),
		Challenges: make(map[string]string),
		Deleted:    make(map[string]bool),
	}
}

func (m *MockHandler) OnClusterChange(key string, value []byte, deleted bool) {
	if deleted {
		m.Deleted[key] = true
		delete(m.Changes, key)
	} else {
		m.Changes[key] = value
	}
}

func (m *MockHandler) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	m.Certs[domain] = true
	return nil
}

func (m *MockHandler) OnClusterChallenge(token, keyAuth string, deleted bool) {
	if deleted {
		delete(m.Challenges, token)
	} else {
		m.Challenges[token] = keyAuth
	}
}

func TestDelegate_Apply_LWW(t *testing.T) {
	h := NewMockHandler()
	configMgr := NewDistributor(testLoogerCluster, "")
	d := newDelegate(Config{}, h, ll.New("test").Disable(), nil, nil, configMgr)

	now := time.Now().UnixNano()

	d.apply(Envelope{Op: OpSet, Key: "foo", Value: []byte("old"), Timestamp: now}, true)
	if string(h.Changes["foo"]) != "old" {
		t.Error("Failed to apply initial")
	}

	d.apply(Envelope{Op: OpSet, Key: "foo", Value: []byte("new"), Timestamp: now + 1}, false)
	if string(h.Changes["foo"]) != "new" {
		t.Error("Failed to apply newer")
	}

	d.apply(Envelope{Op: OpSet, Key: "foo", Value: []byte("ancient"), Timestamp: now - 1}, false)
	if string(h.Changes["foo"]) != "new" {
		t.Error("Applied older timestamp update")
	}
}

func TestDelegate_CertEncryption(t *testing.T) {
	secret := "cluster-secret-key-1234567890123"
	cipher, _ := security.NewCipher(secret)
	h := NewMockHandler()
	configMgr := NewDistributor(testLoogerCluster, "")
	d := newDelegate(Config{}, h, ll.New("test").Disable(), nil, cipher, configMgr)

	domain := "test.com"
	keyData := []byte("private-key-data")

	encKey, _ := cipher.Encrypt(keyData)

	payload := CertPayload{
		Domain:  domain,
		CertPEM: []byte("cert-data"),
		KeyPEM:  encKey,
	}
	payloadBytes, _ := json.Marshal(payload)

	d.apply(Envelope{Op: OpCert, Key: "cert:test.com", Value: payloadBytes, Timestamp: time.Now().UnixNano()}, false)

	if !h.Certs[domain] {
		t.Error("Cert update not propagated to handler")
	}
}

func TestManager_BroadcastCert(t *testing.T) {
	secret := []byte("cluster-secret-key-1234567890123")
	h := NewMockHandler()
	cipher, _ := security.NewCipher(string(secret))
	configMgr := NewDistributor(testLoogerCluster, "")
	del := newDelegate(Config{}, h, ll.New("test").Disable(), nil, cipher, configMgr)

	m := &Manager{
		delegate: del,
		cipher:   cipher,
		nodeName: "test-node", // Required for env.Owner and self-filtering
		// list intentionally nil for unit test isolation
	}

	err := m.BroadcastCert("secure.com", []byte("cert"), []byte("key"))
	if err != nil {
		t.Fatalf("BroadcastCert failed: %v", err)
	}

	env, ok := del.store["cert:secure.com"]
	if !ok {
		t.Fatal("Cert not in store")
	}

	var p CertPayload
	json.Unmarshal(env.Value, &p)
	if string(p.KeyPEM) == "key" {
		t.Error("Private key was stored in plaintext!")
	}
	if !h.Certs["secure.com"] {
		t.Error("Handler did not receive decrypted cert")
	}
}
