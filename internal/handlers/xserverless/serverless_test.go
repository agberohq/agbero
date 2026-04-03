package xserverless

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	resource2 "github.com/agberohq/agbero/internal/hub/resource"
)

// TestServerless_New_NoPanicOnCollision verifies that duplicate registrations do not cause a ServeMux panic.
// It ensures that REST and Worker name collisions are handled gracefully based on priority rules.
func TestServerless_New_NoPanicOnCollision(t *testing.T) {
	res := resource2.New()
	defer res.Close()

	route := alaye.Route{
		Env: map[string]expect.Value{},
		Serverless: alaye.Serverless{
			Enabled: alaye.Active,
			RESTs: []alaye.REST{
				{Name: "duplicate", Enabled: alaye.Active, URL: "http://first"},
				{Name: "duplicate", Enabled: alaye.Active, URL: "http://second"},
				{Name: "conflict", Enabled: alaye.Active, URL: "http://rest-wins"},
			},
			Workers: []alaye.Work{
				{Name: "worker-dup", Command: []string{"echo", "1"}},
				{Name: "worker-dup", Command: []string{"echo", "2"}},
				{Name: "conflict", Command: []string{"echo", "worker-loses"}},
			},
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New panicked due to collision: %v", r)
		}
	}()

	handler := New(resource2.Proxy{Resource: res}, &route)
	if handler == nil {
		t.Fatal("expected handler, got nil")
	}
}
