package bugs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

// BUG-06 — secret reference NAMES leak through the redacted admin config.
//
// alaye.RedactGlobal (redact.go) clears secret VALUES, and expect.Value's
// MarshalJSON redacts plain values — but any value that IS a secret-store
// reference is returned verbatim:
//
//	func (v Value) MarshalJSON() ([]byte, error) {
//	    if v.IsSecretStoreRef() { return []byte(`"` + string(v) + `"`), nil }
//	    return []byte(`"[REDACTED]"`), nil
//	}
//
// So GET /config (handleConfigDump → sanitizeGlobalConfig) and GET
// /api/v1/discovery both disclose the map of every secret a deployment keeps
// (e.g. "ss://vault/prod-totp-admin"). This is reconnaissance, not direct
// credential theft — severity is LOW/MEDIUM, and exposing reference names may
// even be a deliberate choice so the admin UI can render them. The test
// documents the current behaviour; if the team decides reference names are
// sensitive, flip it to require redaction.
func TestBUG_ConfigDumpsSecretReferenceNames(t *testing.T) {
	g := &alaye.Global{
		Env: map[string]expect.Value{
			"PROD_API_KEY":  expect.NewValue("ss://vault/prod-totp-admin"),
			"DB_PASSWORD":   expect.NewValue("ss://vault/prod-db-password"),
			"PLAIN_LITERAL": expect.NewValue("not-a-secret-recognition-string"),
		},
	}

	red := alaye.RedactGlobal(g)
	out, err := json.Marshal(red)
	if err != nil {
		t.Fatalf("marshal redacted global: %v", err)
	}
	body := string(out)

	if !strings.Contains(body, "ss://vault/prod-totp-admin") ||
		!strings.Contains(body, "ss://vault/prod-db-password") {
		t.Fatalf("BUG FIXED: secret reference names are now redacted — flip this " +
			"test to require redaction of ss:// references in RedactGlobal")
	}

	if strings.Contains(body, "not-a-secret-recognition-string") {
		t.Fatalf("regression: plain env literal must stay [REDACTED]")
	}
	t.Logf("BUG CONFIRMED: GET /config discloses every secret-store reference " +
		"name used by this deployment (values are still redacted)")
}
