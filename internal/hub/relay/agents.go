package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/agberohq/oshodi"
)

const (
	agentsBucket = "relay_agents"
	claimsBucket = "relay_claims"
)

var (
	errAuth      = errors.New("authentication failed")
	errRevoked   = errors.New("agent revoked")
	errMaxAgents = errors.New("max agents reached")
)

type agentRecord struct {
	ID             string             `json:"id"`
	CredentialHash string             `json:"credential_hash"`
	Status         string             `json:"status"`
	CreatedAt      time.Time          `json:"created_at"`
	LastSeen       time.Time          `json:"last_seen"`
	Exposures      []registeredExpose `json:"exposures"`
}

type agentStore struct {
	mu      sync.Mutex
	db      *oshodi.DB
	agents  *oshodi.Bucket
	claims  *oshodi.Bucket
	records map[string]*agentRecord
	owners  map[string]string
}

func newAgentStore(db *oshodi.DB) *agentStore {
	s := &agentStore{
		db:      db,
		records: make(map[string]*agentRecord),
		owners:  make(map[string]string),
	}
	if db == nil {
		return s
	}
	if agents, err := db.Bucket(agentsBucket); err == nil {
		s.agents = agents
	}
	if claims, err := db.Bucket(claimsBucket); err == nil {
		s.claims = claims
	}
	if s.agents != nil {
		_ = s.agents.Scan(func(k, v []byte) bool {
			var rec agentRecord
			if json.Unmarshal(v, &rec) == nil && rec.ID != "" {
				s.records[rec.ID] = &rec
			}
			return true
		})
	}
	if s.claims != nil {
		_ = s.claims.Scan(func(k, v []byte) bool {
			s.owners[string(k)] = string(v)
			return true
		})
	}
	return s
}

func (s *agentStore) get(id string) (*agentRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[id]
	if !ok {
		return nil, false
	}
	cp := *rec
	return &cp, true
}

func (s *agentStore) put(rec *agentRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.ID] = rec
	if s.agents != nil {
		if data, err := json.Marshal(rec); err == nil {
			_ = s.agents.Set([]byte(rec.ID), data)
		}
	}
}

func (s *agentStore) activeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rec := range s.records {
		if rec.Status == "active" {
			n++
		}
	}
	return n
}

func (s *agentStore) verifyCredential(id, credential string) bool {
	rec, ok := s.get(id)
	if !ok || rec.Status != "active" || credential == "" {
		return false
	}
	sum := sha256.Sum256([]byte(credential))
	got := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(rec.CredentialHash)) == 1
}

func (s *agentStore) enroll(id, enrollToken, expectedToken string, maxAgents int) (string, error) {
	if subtle.ConstantTimeCompare([]byte(enrollToken), []byte(expectedToken)) != 1 {
		return "", errAuth
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.records[id]
	if rec != nil && rec.Status == "revoked" {
		return "", errRevoked
	}
	if rec == nil {
		active := 0
		for _, r := range s.records {
			if r.Status == "active" {
				active++
			}
		}
		if maxAgents > 0 && active >= maxAgents {
			return "", errMaxAgents
		}
		rec = &agentRecord{ID: id, Status: "active", CreatedAt: time.Now().UTC()}
		s.records[id] = rec
	}
	credential, err := newCredential()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(credential))
	rec.CredentialHash = hex.EncodeToString(sum[:])
	rec.Status = "active"
	rec.LastSeen = time.Now().UTC()
	if s.agents != nil {
		if data, err := json.Marshal(rec); err == nil {
			_ = s.agents.Set([]byte(id), data)
		}
	}
	return credential, nil
}

func (s *agentStore) setExposures(id string, exposures []registeredExpose) {
	rec, ok := s.get(id)
	if !ok {
		return
	}
	rec.Exposures = exposures
	rec.LastSeen = time.Now().UTC()
	s.put(rec)
}

func (s *agentStore) claim(owner string, keys []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		if current, exists := s.owners[key]; exists && current != owner {
			return false
		}
	}
	for _, key := range keys {
		if _, exists := s.owners[key]; exists {
			continue
		}
		s.owners[key] = owner
		if s.claims != nil {
			_ = s.claims.Set([]byte(key), []byte(owner))
		}
	}
	return true
}

func newCredential() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
