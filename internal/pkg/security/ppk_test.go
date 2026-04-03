package security

import (
	"os"
	"testing"
	"time"
)

func TestTokenLifecycle(t *testing.T) {
	tmpFile := "test_key.pem"
	defer os.Remove(tmpFile)

	// Generate Key
	if err := NewPPK(tmpFile); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Load Key
	tm, err := PPKLoad(tmpFile)
	if err != nil {
		t.Fatalf("failed to load keys: %v", err)
	}

	// Mint Token
	service := VerifiedToken{Service: "test-service"}
	ttl := 5 * time.Second
	token, err := tm.Mint(service.Service, ttl)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Verify Token
	gotService, err := tm.Verify(token)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if gotService.Service != service.Service {
		t.Errorf("expected service %q, got %q", service.Service, gotService.Service)
	}
}
