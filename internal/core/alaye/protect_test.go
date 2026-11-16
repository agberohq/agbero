package alaye

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
)

func TestProtectValidate(t *testing.T) {
	valid := Protect{Enabled: expect.Active, Users: []string{"alice:$2y$10$abcdefghijklmnopqrstuv"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := map[string]Protect{
		"empty users":     {Enabled: expect.Active},
		"malformed user":  {Enabled: expect.Active, Users: []string{"alice"}},
		"empty username":  {Enabled: expect.Active, Users: []string{":hash"}},
		"empty secret":    {Enabled: expect.Active, Users: []string{"alice:"}},
		"negative ttl":    {Enabled: expect.Active, Users: []string{"alice:hash"}, SessionTTL: -1},
		"bad cookie name": {Enabled: expect.Active, Users: []string{"alice:hash"}, CookieName: "bad cookie"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestRouteRejectsMultiplePrimaryAuthModes(t *testing.T) {
	r := Route{
		Path: "/",
		Backends: Backend{
			Enabled: expect.Active,
			Servers: []Server{{Address: "http://127.0.0.1:9000"}},
		},
		BasicAuth:  BasicAuth{Enabled: expect.Active, Users: []string{"a:b"}},
		Protect: Protect{Enabled: expect.Active, Users: []string{"a:b"}},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("route accepted both basic_auth and protect")
	}
}
