package alaye

import (
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestRouteProtocolValidation(t *testing.T) {
	r := Route{Path: "/mcp", Protocol: "smtp", Enabled: expect.Active}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("Validate() error = %v, want protocol error", err)
	}
	r.Protocol = def.RouteProtocolMCP
	if err := r.Validate(); err != nil {
		// It may fail for engine/backend reasons; protocol itself must pass.
		if strings.Contains(err.Error(), "protocol") {
			t.Fatalf("mcp protocol rejected: %v", err)
		}
	}
}
