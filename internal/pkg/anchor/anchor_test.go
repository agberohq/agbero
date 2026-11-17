package anchor

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func echoHandler(method string, params json.RawMessage) (any, error) {
	var s string
	_ = json.Unmarshal(params, &s)
	return method + ":" + s, nil
}

func TestAnchorOwnerAttachAndRelease(t *testing.T) {
	dir := t.TempDir()
	a := New("keeper", dir)
	ctx := context.Background()

	owner, release, isOwner, err := a.Open(ctx, Options{Role: RoleService, Exclusive: true}, HandlerFunc(echoHandler))
	if err != nil {
		t.Fatal(err)
	}
	if !isOwner {
		t.Fatal("first opener should own")
	}

	client, closeClient, isOwner, err := a.Open(ctx, Options{Role: RoleCLI}, HandlerFunc(echoHandler))
	if err != nil {
		t.Fatal(err)
	}
	if isOwner {
		t.Fatal("second opener should attach")
	}
	var out string
	if err := client.Call(ctx, "get", "hello", &out); err != nil {
		t.Fatal(err)
	}
	if out != "get:hello" {
		t.Fatalf("out = %q", out)
	}
	closeClient()
	release()

	if err := owner.Call(ctx, "get", "after-close", &out); err == nil {
		t.Fatal("owner client survived release")
	}
}

func TestAnchorExclusiveServiceRefusesServiceOwner(t *testing.T) {
	dir := t.TempDir()
	a := New("keeper", dir)
	ctx := context.Background()
	_, release, _, err := a.Open(ctx, Options{Role: RoleService, Exclusive: true}, HandlerFunc(echoHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, _, _, err := a.Open(ctx, Options{Role: RoleService, Exclusive: true}, HandlerFunc(echoHandler)); err == nil {
		t.Fatal("second exclusive service owner accepted")
	}
}

func TestAnchorExclusiveServiceWaitsForCLI(t *testing.T) {
	dir := t.TempDir()
	a := New("keeper", dir)
	ctx := context.Background()
	_, releaseCLI, _, err := a.Open(ctx, Options{Role: RoleCLI}, HandlerFunc(echoHandler))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		releaseCLI()
	}()
	_, release, owner, err := a.Open(ctx, Options{Role: RoleService, Exclusive: true, Wait: 2 * time.Second}, HandlerFunc(echoHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if !owner {
		t.Fatal("service did not become owner after CLI released")
	}
}
