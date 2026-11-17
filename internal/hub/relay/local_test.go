package relay

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func TestResolveLocal(t *testing.T) {
	h := &alaye.Host{
		Domains: []string{"show.localhost"},
		Bind:    []string{":80", ":443"},
		TLS:     alaye.TLS{Mode: "local"},
	}
	local, sni, insecure := ResolveLocal(h, alaye.Agent{})
	if local != "https://127.0.0.1:443" {
		t.Fatalf("local = %q", local)
	}
	if sni != "show.localhost" {
		t.Fatalf("sni = %q", sni)
	}
	if !insecure {
		t.Fatal("loopback HTTPS should default to insecure")
	}

	h.Bind = []string{":80"}
	local, _, _ = ResolveLocal(h, alaye.Agent{})
	if local != "http://127.0.0.1:80" {
		t.Fatalf("http local = %q", local)
	}

	local, sni, insecure = ResolveLocal(h, alaye.Agent{
		Local:         "https://10.0.0.5:8443",
		LocalSNI:      "internal.example",
		LocalInsecure: false,
	})
	if local != "https://10.0.0.5:8443" || sni != "internal.example" || insecure {
		t.Fatalf("explicit local = %q sni=%q insecure=%v", local, sni, insecure)
	}
}
