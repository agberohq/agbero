package api

import (
	"strings"
	"testing"
)

const authHCLSample = `# host-level comment
domains = ["auth.example.com"]

route "/admin" {
  # keep this route comment
  enabled  = "on"
  protocol = "http"

  basic_auth {
    # basic settings
    enabled = "on"
    realm   = "Admin"
    users   = [
      "alice:$2y$10$abcdefghijklmnopqrstuv",
    ]
  }

  protect {
    enabled     = "off"
    title       = "Old title"
    users       = ["carol:$2y$10$abcdefghijklmnopqrstuv"]
    session_ttl = "1h"
  }

  backend {
    # upstream comment
    server { address = "http://127.0.0.1:8080" }
  }
}
`

func TestMutateAuthSettingsPreservesComments(t *testing.T) {
	out, err := mutateAuthSettings([]byte(authHCLSample), "/admin", authModeProtect, authConfigRequest{
		Enabled:    boolPtr(true),
		Title:      strPtr("Cockroach Admin"),
		SessionTTL: strPtr("8h"),
		CookieName: strPtr("admin_sess"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"# host-level comment",
		"# keep this route comment",
		"# basic settings",
		"# upstream comment",
		`title       = "Cockroach Admin"`,
		`session_ttl = "8h"`,
		`cookie_name = "admin_sess"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("mutated HCL missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, `users       = ["carol:$2y$10$abcdefghijklmnopqrstuv"]`) &&
		!strings.Contains(got, `"carol:$2y$10$abcdefghijklmnopqrstuv"`) {
		t.Errorf("settings save dropped the users list:\n%s", got)
	}
	if strings.Contains(got, `title       = "Old title"`) {
		t.Errorf("title was not updated:\n%s", got)
	}
}

func TestMutateAuthUsersReplacesOnlyTargetBlock(t *testing.T) {
	out, err := mutateAuthUsers([]byte(authHCLSample), "/admin", authModeProtect, []string{
		"carol:$2y$10$abcdefghijklmnopqrstuv",
		"dave:ss://auth/auth.example.com/admin/protect/dave",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, `"dave:ss://auth/auth.example.com/admin/protect/dave"`) {
		t.Fatalf("new user missing:\n%s", got)
	}
	if !strings.Contains(got, `"alice:$2y$10$abcdefghijklmnopqrstuv"`) {
		t.Fatalf("basic_auth users were modified:\n%s", got)
	}
	if _, err := parseHostBytes(out); err != nil {
		t.Fatalf("append produced invalid HCL: %v\n%s", err, got)
	}
	for _, want := range []string{"# host-level comment", "# keep this route comment", "# upstream comment"} {
		if !strings.Contains(got, want) {
			t.Errorf("comment %q was lost:\n%s", want, got)
		}
	}
}

func TestMutateAuthCreatesMissingBlock(t *testing.T) {
	src := `route "/admin" {
  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`
	out, err := mutateAuthSettings([]byte(src), "/admin", authModeProtect, authConfigRequest{
		Enabled: boolPtr(true),
		Title:   strPtr("Login"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "protect {") {
		t.Fatalf("missing protect block:\n%s", got)
	}
	if !strings.Contains(got, `enabled = "on"`) {
		t.Fatalf("enabled attribute missing:\n%s", got)
	}
}

func TestMutateAuthUnknownRouteFails(t *testing.T) {
	if _, err := mutateAuthSettings([]byte(authHCLSample), "/missing", authModeBasic, authConfigRequest{}); err == nil {
		t.Fatal("expected an error for an unknown route")
	}
}

func TestMutateAuthInvalidHCLFails(t *testing.T) {
	if _, err := mutateAuthSettings([]byte("route \"/admin\" {"), "/admin", authModeBasic, authConfigRequest{}); err == nil {
		t.Fatal("expected an error for invalid HCL")
	}
}

func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }

const authHCLCommentedUsers = `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled = "on"
    users = [
      # alice label
      "alice:$2y$10$abcdefghijklmnopqrstuv", # alice trailing
      # carol label
      "carol:$2y$10$abcdefghijklmnopqrstuv",
    ]
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`

func TestMutateAuthUsersPreservesCommentsOnAdd(t *testing.T) {
	out, err := mutateAuthUsers([]byte(authHCLCommentedUsers), "/admin", authModeProtect, []string{
		"alice:$2y$10$abcdefghijklmnopqrstuv",
		"carol:$2y$10$abcdefghijklmnopqrstuv",
		"dave:ss://auth/auth.example.com/admin/protect/dave",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"# alice label", "# alice trailing", "# carol label", "dave:ss://"} {
		if !strings.Contains(got, want) {
			t.Errorf("append lost %q:\n%s", want, got)
		}
	}
	if _, err := parseHostBytes(out); err != nil {
		t.Fatalf("append produced invalid HCL: %v\n%s", err, got)
	}
}

func TestMutateAuthUsersPreservesCommentsOnReset(t *testing.T) {
	out, err := mutateAuthUsers([]byte(authHCLCommentedUsers), "/admin", authModeProtect, []string{
		"alice:$2y$10$abcdefghijklmnopqrstuv",
		"carol:$2y$10$zzzzzzzzzzzzzzzzzzzzzz",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"# alice label", "# alice trailing", "# carol label", "$2y$10$zzzzzzzzzzzzzzzzzzzzzz"} {
		if !strings.Contains(got, want) {
			t.Errorf("reset lost %q:\n%s", want, got)
		}
	}
	if _, err := parseHostBytes(out); err != nil {
		t.Fatalf("reset produced invalid HCL: %v\n%s", err, got)
	}
}

func TestMutateAuthUsersPreservesCommentsOnDelete(t *testing.T) {
	out, err := mutateAuthUsers([]byte(authHCLCommentedUsers), "/admin", authModeProtect, []string{
		"alice:$2y$10$abcdefghijklmnopqrstuv",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "carol") || strings.Contains(got, "# carol label") {
		t.Errorf("delete left the removed user or its label behind:\n%s", got)
	}
	for _, want := range []string{"# alice label", "# alice trailing", "\"alice:$2y$10$abcdefghijklmnopqrstuv\""} {
		if !strings.Contains(got, want) {
			t.Errorf("delete lost %q:\n%s", want, got)
		}
	}
	if _, err := parseHostBytes(out); err != nil {
		t.Fatalf("delete produced invalid HCL: %v\n%s", err, got)
	}
}
