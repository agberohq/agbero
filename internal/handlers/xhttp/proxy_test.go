package xhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/metrics"
)

func TestProxy_Pick_ReturnsCorrectType(t *testing.T) {
	backends := []*Backend{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		Path: "/",
		Backends: alaye.Backend{
			Enabled: alaye.Active,
			Servers: alaye.NewServers(server.URL),
		},
	}

	cfg := ConfigBackend{
		Route:    route,
		Domains:  []string{"example.com"},
		Logger:   testLogger,
		Registry: metrics.NewRegistry(),
	}

	b1, err := NewBackend(alaye.NewServer(server.URL), cfg)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b1.Stop()

	backends = append(backends, b1)

	proxyCfg := ConfigProxy{
		Strategy: "round_robin",
		Timeout:  30 * time.Second,
	}

	proxy := NewProxy(proxyCfg, backends, zulu.NewIPManager(nil))

	req := httptest.NewRequest("GET", "/", nil)
	picked := proxy.Pick(req)

	if picked == nil {
		t.Error("Pick should return a backend")
	}

	if picked != b1 {
		t.Error("Pick should return the correct backend instance")
	}
}
