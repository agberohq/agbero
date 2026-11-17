package scan

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestBroadCIDR(t *testing.T) {
	for _, v := range []string{"0.0.0.0/0", "::/0"} {
		if !broadCIDR([]string{v}) {
			t.Errorf("%s not broad", v)
		}
	}
	if broadCIDR([]string{"192.168.0.0/16"}) {
		t.Fatal("LAN CIDR flagged as broad")
	}
}

func TestPrivateAddress(t *testing.T) {
	for _, v := range []string{"http://127.0.0.1:3000", "10.0.0.5:80", "http://[::1]:8080"} {
		if !isPrivateAddress(v) {
			t.Errorf("%s should be private", v)
		}
	}
	if isPrivateAddress("https://example.com") {
		t.Fatal("public host flagged private")
	}
}

func TestRunFindsServerlessGit(t *testing.T) {
	g := &alaye.Global{
		Security: alaye.Security{Allow: alaye.Allow{ServerlessGit: expect.Active}},
		Admin:    alaye.Admin{Enabled: expect.Active, Address: "127.0.0.1:9090"},
	}
	r := Run(g, nil, Paths{})
	found := false
	for _, f := range r.Findings {
		if f.Code == "security.serverless_git" {
			found = true
			if f.Severity != High {
				t.Fatalf("severity = %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("findings = %+v", r.Findings)
	}
}
