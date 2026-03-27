package security

import (
	"os"
	"testing"
	"time"
)

func TestTokenLifecycle(t *testing.T) {
	tmpFile := "test_key.pem"
	defer os.Remove(tmpFile)

	// 1. Generate Key
	if err := NewPPK(tmpFile); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 2. Load Key
	tm, err := PPKLoad(tmpFile)
	if err != nil {
		t.Fatalf("failed to load keys: %v", err)
	}

	// 3. Mint Token
	service := "my-service"
	ttl := 5 * time.Second
	token, err := tm.Mint(service, ttl)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// 4. Verify Token
	gotService, err := tm.Verify(token)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}

	if gotService != service {
		t.Errorf("expected service %q, got %q", service, gotService)
	}
}
