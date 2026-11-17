package api

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestMergeRedactedSecrets_RelayAndAgentTokens(t *testing.T) {
	existing := &alaye.Host{
		Relays: []alaye.Relay{{
			Name: "agents",
			Auth: alaye.RelayAuth{Token: "relay-token"},
		}},
		Agents: []alaye.Agent{{
			Name:   "default",
			Token:  "agent-token",
			Enroll: "enroll-token",
		}},
	}
	incoming := &alaye.Host{
		Relays: []alaye.Relay{{
			Name: "agents",
			Auth: alaye.RelayAuth{Token: expect.Value("[REDACTED]")},
		}},
		Agents: []alaye.Agent{{
			Name:   "default",
			Token:  expect.Value("[REDACTED]"),
			Enroll: expect.Value("[REDACTED]"),
		}},
	}

	mergeRedactedSecrets(existing, incoming)

	if got := incoming.Relays[0].Auth.Token.String(); got != "relay-token" {
		t.Fatalf("relay token = %q, want relay-token", got)
	}
	if got := incoming.Agents[0].Token.String(); got != "agent-token" {
		t.Fatalf("agent token = %q, want agent-token", got)
	}
	if got := incoming.Agents[0].Enroll.String(); got != "enroll-token" {
		t.Fatalf("agent enroll = %q, want enroll-token", got)
	}
}
