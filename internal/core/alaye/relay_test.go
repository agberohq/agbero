package alaye

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

func validRelayConfig() Relay {
	return Relay{
		Name: "agents",
		Listen: RelayListen{
			Address:  "0.0.0.0",
			Port:     8443,
			Protocol: "https",
		},
		Auth: RelayAuth{Method: "enrollment", Token: "enroll-token"},
		Policy: RelayPolicy{
			AllowHTTP:      true,
			AllowSubdomain: true,
			AllowTCPPorts:  []string{"20000-20100"},
		},
	}
}

func validAgentConfig() Agent {
	return Agent{
		Name:   "default",
		Relay:  "https://relay.example.com:8443",
		Enroll: "enroll-token",
		Local:  "http://127.0.0.1:8080",
		Pool:   8,
	}
}

func TestRelay_Validate(t *testing.T) {
	r := validRelayConfig()
	if err := r.Validate(); err != nil {
		t.Fatalf("valid relay rejected: %v", err)
	}
	if r.Policy.MaxAgents != 100 || r.Policy.MaxStreams != 1000 {
		t.Fatalf("policy defaults = %+v", r.Policy)
	}

	bad := validRelayConfig()
	bad.Policy.AllowHTTP = false
	bad.Policy.AllowSubdomain = false
	bad.Policy.AllowTCPPorts = nil
	if err := bad.Validate(); err == nil {
		t.Fatal("relay without exposure modes accepted")
	}

	bad = validRelayConfig()
	bad.Policy.AllowTCPPorts = []string{"nope"}
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid tcp port range accepted")
	}

	bad = validRelayConfig()
	bad.Policy.Namespace = "agent"
	if err := bad.Validate(); err == nil {
		t.Fatal("unimplemented namespace accepted")
	}
}

func TestAgent_Validate(t *testing.T) {
	a := validAgentConfig()
	if err := a.Validate(); err != nil {
		t.Fatalf("valid agent rejected: %v", err)
	}
	a.Relay = "ftp://relay.example.com:8443"
	if err := a.Validate(); err == nil {
		t.Fatal("non-https relay accepted")
	}
	a = validAgentConfig()
	a.Enroll = ""
	a.Token = ""
	if err := a.Validate(); err == nil {
		t.Fatal("agent without enrollment or token accepted")
	}
	a = validAgentConfig()
	a.Enroll = ""
	a.Token = "preprovisioned"
	if err := a.Validate(); err != nil {
		t.Fatalf("pre-provisioned agent rejected: %v", err)
	}
}

func TestExpose_Validate(t *testing.T) {
	valid := Expose{ID: "hello", Via: "default", Path: true}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid expose rejected: %v", err)
	}

	for _, ex := range []Expose{
		{ID: "Hello", Via: "default", Path: true},
		{ID: "admin", Via: "default", Path: true},
		{ID: "hello", Path: true},
		{ID: "hello", Via: "default"},
	} {
		if err := ex.Validate(); err == nil {
			t.Fatalf("invalid expose %+v accepted", ex)
		}
	}

	tcp := Expose{ID: "postgres", Via: "default", TCP: &RelayTarget{PublicPort: 15432, Local: "127.0.0.1:5432"}}
	if err := tcp.Validate(); err != nil {
		t.Fatalf("valid tcp expose rejected: %v", err)
	}
}

func TestHost_ValidateRelayAgentReferences(t *testing.T) {
	h := Host{
		Domains: []string{"local.example.com"},
		Relays:  []Relay{validRelayConfig()},
		Agents:  []Agent{validAgentConfig()},
		Routes: []Route{{
			Path: "/",
			Web:  Web{Enabled: expect.Active, Root: "/var/www/example"},
			Exposes: []Expose{{
				ID:   "hello",
				Via:  "default",
				Path: true,
			}},
		}},
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("valid host rejected: %v", err)
	}

	h.Routes[0].Exposes[0].Via = "missing"
	if err := h.Validate(); err == nil {
		t.Fatal("expose with unknown agent accepted")
	}
}

func TestRedactHost_RelayAndAgentTokens(t *testing.T) {
	h := &Host{
		Domains: []string{"relay.example.com"},
		Relays:  []Relay{validRelayConfig()},
		Agents:  []Agent{validAgentConfig()},
	}
	red := RedactHost(h)
	if red.Relays[0].Auth.Token != def.RedactedValue {
		t.Fatalf("relay token was not redacted: %q", red.Relays[0].Auth.Token)
	}
	if red.Agents[0].Enroll != def.RedactedValue {
		t.Fatalf("agent enroll token was not redacted: %q", red.Agents[0].Enroll)
	}
	if h.Agents[0].Enroll != "enroll-token" {
		t.Fatal("redaction mutated the live host")
	}
}
