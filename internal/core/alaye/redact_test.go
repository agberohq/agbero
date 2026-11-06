package alaye

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
)

func TestRedactGlobalHidesKeeperPassphraseFile(t *testing.T) {
	g := &Global{}
	g.Security.Keeper.PassphraseFile = "/etc/agbero/keeper.passphrase"

	r := RedactGlobal(g)
	if r.Security.Keeper.PassphraseFile != def.RedactedValue {
		t.Fatalf("passphrase_file = %q, want %q", r.Security.Keeper.PassphraseFile, def.RedactedValue)
	}
	if g.Security.Keeper.PassphraseFile != "/etc/agbero/keeper.passphrase" {
		t.Fatal("RedactGlobal mutated the input")
	}
}

func TestRedactHostCoversCacheReplayAndWorkers(t *testing.T) {
	h := &Host{
		Routes: []Route{{
			Path: "/",
			Cache: Cache{
				Redis: &RedisCache{Password: "cache-secret"},
			},
			Serverless: Serverless{
				Replay: []Replay{{
					URL:     "https://replay-user:replay-pass@replay.example.com/hook",
					Headers: map[string]string{"Authorization": "Bearer replay-header-secret"},
				}},
				Workers: []Work{{
					Cache: Cache{Redis: &RedisCache{Password: "worker-cache-secret"}},
				}},
			},
		}},
	}

	body, err := json.Marshal(RedactHost(h))
	if err != nil {
		t.Fatalf("marshal redacted host: %v", err)
	}
	for _, secret := range []string{"cache-secret", "replay-pass", "replay-header-secret", "worker-cache-secret"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("redacted host still contains %q: %s", secret, body)
		}
	}

	if h.Routes[0].Cache.Redis.Password != "cache-secret" {
		t.Fatal("RedactHost mutated the live cache password")
	}
	if h.Routes[0].Serverless.Replay[0].Headers["Authorization"] != "Bearer replay-header-secret" {
		t.Fatal("RedactHost mutated the live replay header")
	}
	if h.Routes[0].Serverless.Workers[0].Cache.Redis.Password != "worker-cache-secret" {
		t.Fatal("RedactHost mutated the live worker cache password")
	}
}
