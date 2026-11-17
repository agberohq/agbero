package bugs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

// Guard for BUG-L14 — RedactRoute must blank credentials that are plain
// strings (or maps/slices) and therefore are not redacted by the JSON
// marshaller: cache Redis passwords, replay headers/URLs, worker caches.
//
// The input host is constructed directly; RedactHost must return a copy and
// must never mutate the live config.
func TestBUG_HostRedactionCoversCacheReplayAndWorkers(t *testing.T) {
	host := &alaye.Host{
		Domains: []string{"app.example.com"},
		Routes: []alaye.Route{{
			Path:    "/",
			Enabled: expect.Active,
			Cache: alaye.Cache{
				Enabled: expect.Active,
				Driver:  "redis",
				Redis: &alaye.RedisCache{
					Host:     "redis.internal",
					Port:     6379,
					Password: "cache-secret",
				},
			},
			Serverless: alaye.Serverless{
				Enabled: expect.Active,
				Replay: []alaye.Replay{{
					Name:    "hook",
					Enabled: expect.Active,
					URL:     "https://replay-user:replay-pass@replay.example.com/hook",
					Headers: map[string]string{
						"Authorization": "Bearer replay-header-secret",
						"Content-Type":  "application/json",
					},
					Auth: alaye.RestAuth{
						Enabled: expect.Active,
						Secret:  expect.NewValue("replay-auth-secret"),
					},
				}},
				Workers: []alaye.Work{{
					Name:    "worker",
					Command: []string{"node"},
					Cache: alaye.Cache{
						Enabled: expect.Active,
						Driver:  "redis",
						Redis:   &alaye.RedisCache{Password: "worker-cache-secret"},
					},
				}},
			},
		}},
	}

	red := alaye.RedactHost(host)
	if red == nil {
		t.Fatal("RedactHost returned nil")
	}
	body, err := json.Marshal(red)
	if err != nil {
		t.Fatalf("marshal redacted host: %v", err)
	}
	out := string(body)

	for _, secret := range []string{
		"cache-secret",
		"replay-pass",
		"replay-header-secret",
		"worker-cache-secret",
	} {
		if strings.Contains(out, secret) {
			t.Fatalf("BUG: redacted host still contains %q\n%s", secret, out)
		}
	}

	// The live config must not be mutated.
	if got := host.Routes[0].Cache.Redis.Password; got != "cache-secret" {
		t.Fatalf("RedactHost mutated the live cache password: got %q", got)
	}
	if got := host.Routes[0].Serverless.Replay[0].Headers["Authorization"]; got != "Bearer replay-header-secret" {
		t.Fatalf("RedactHost mutated the live replay header: got %q", got)
	}
	if got := host.Routes[0].Serverless.Workers[0].Cache.Redis.Password; got != "worker-cache-secret" {
		t.Fatalf("RedactHost mutated the live worker cache password: got %q", got)
	}
}
