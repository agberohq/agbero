package alaye

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
)

func TestRouteInlineTunnelValidation(t *testing.T) {
	base := func(tunnel string) Route {
		return Route{
			Path: "/",
			Backends: Backend{
				Enabled: expect.Active,
				Servers: []Server{{Address: "http://127.0.0.1:9000"}},
				Tunnel:  tunnel,
			},
		}
	}
	r := base("   ")
	if err := r.Validate(); err != nil {
		t.Fatalf("whitespace tunnel should be treated as unset: %v", err)
	}
	r = base("socks5://127.0.0.1:9050")
	if err := r.Validate(); err != nil {
		t.Fatalf("valid socks5 tunnel rejected: %v", err)
	}
	r = base("http://127.0.0.1:9050")
	if err := r.Validate(); err == nil {
		t.Fatal("non-socks5 tunnel accepted")
	}
}

func TestRouteTunnelCanStandAlone(t *testing.T) {
	r := Route{
		Path: "/",
		Backends: Backend{
			Enabled: expect.Active,
			Tunnel:  "socks5://127.0.0.1:9050",
		},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("tunnel-only route rejected: %v", err)
	}
	r.Backends.Tunnel = "   "
	if err := r.Validate(); err == nil {
		t.Fatal("backend-less route without a tunnel was accepted")
	}
}
