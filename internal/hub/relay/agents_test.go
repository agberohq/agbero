package relay

import "testing"

func TestAgentStoreEnrollmentAndClaims(t *testing.T) {
	s := newAgentStore(nil)

	cred, err := s.enroll("alice", "enroll", "enroll", 1)
	if err != nil {
		t.Fatal(err)
	}
	if cred == "" {
		t.Fatal("empty credential")
	}
	if !s.verifyCredential("alice", cred) {
		t.Fatal("issued credential did not verify")
	}
	if s.verifyCredential("alice", "wrong") {
		t.Fatal("wrong credential verified")
	}
	if _, err := s.enroll("bob", "enroll", "enroll", 1); err == nil {
		t.Fatal("max_agents was not enforced")
	}
	if !s.claim("alice", []string{"path:/hello", "tcp:15432"}) {
		t.Fatal("first claim rejected")
	}
	if s.claim("bob", []string{"path:/hello"}) {
		t.Fatal("conflicting claim accepted")
	}
	if !s.claim("alice", []string{"path:/hello"}) {
		t.Fatal("idempotent claim rejected")
	}
}
