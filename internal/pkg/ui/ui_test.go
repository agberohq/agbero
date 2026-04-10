package ui

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"charm.land/lipgloss/v2/compat"
)

// Helpers

func newBuf() (*UI, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	u := New(WithWriter(buf))
	return u, buf
}

func out(buf *bytes.Buffer) string {
	return stripped(buf.String())
}

func stripped(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	// Also handle the case where there are control characters like \r
	result := b.String()
	// Remove any remaining control characters except newline
	var clean strings.Builder
	for _, r := range result {
		if r >= 32 || r == '\n' {
			clean.WriteRune(r)
		}
	}
	return clean.String()
}

// Core functionality

func TestFlush_writesAndResets(t *testing.T) {
	u, buf := newBuf()
	u.line("hello")
	u.Flush()
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("expected 'hello' in output, got %q", buf.String())
	}
	if u.buf.Len() != 0 {
		t.Error("internal buffer should be reset after Flush")
	}
}

func TestKeyValueBlock_containsLabelsAndValues(t *testing.T) {
	u, buf := newBuf()
	u.KeyValueBlock("", []KV{
		{Label: "Config file", Value: "/etc/agbero.hcl"},
		{Label: "Admin user", Value: "admin"},
	})
	u.Flush()
	out := out(buf)

	// Check for labels and values (they might have spaces around them)
	expected := []string{"Config file", "/etc/agbero.hcl", "Admin user", "admin"}
	for _, want := range expected {
		if !strings.Contains(out, want) {
			t.Errorf("KeyValueBlock output missing %q. Got output:\n%s", want, out)
		}
	}
}

func TestSecretBox_containsLabelAndValue(t *testing.T) {
	u, buf := newBuf()
	u.SecretBox("Cluster key", "b64.abc123XYZ==")
	u.Flush()
	out := out(buf)

	if !strings.Contains(out, "Cluster key") {
		t.Errorf("SecretBox missing label %q. Got output:\n%s", "Cluster key", out)
	}
	if !strings.Contains(out, "b64.abc123XYZ==") {
		t.Errorf("SecretBox missing value %q. Got output:\n%s", "b64.abc123XYZ==", out)
	}
}

func TestStatusBadge_knownStatuses(t *testing.T) {
	statuses := []string{"running", "stopped", "error"}
	for _, status := range statuses {
		u, buf := newBuf()
		u.StatusBadge(status)
		u.Flush()
		out := out(buf)
		// StatusBadge renders the status text, not necessarily the exact input

		lowerStatus := strings.ToLower(status)
		if !strings.Contains(out, lowerStatus) {
			t.Errorf("StatusBadge(%q) output missing status text %q. Got output:\n%s",
				status, lowerStatus, out)
		}
	}
}

func TestSuccessLine(t *testing.T) {
	u, buf := newBuf()
	u.SuccessLine("CA installed")
	u.Flush()
	out := out(buf)
	if !strings.Contains(out, "✓") {
		t.Errorf("SuccessLine missing checkmark. Got output:\n%s", out)
	}
	if !strings.Contains(out, "CA installed") {
		t.Errorf("SuccessLine missing message. Got output:\n%s", out)
	}
}

func TestErrorHint_withHint(t *testing.T) {
	u, buf := newBuf()
	u.ErrorHint("config not found", "run agbero init")
	u.Flush()
	out := out(buf)

	expected := []string{"✗", "config not found", "→", "run agbero init"}
	for _, want := range expected {
		if !strings.Contains(out, want) {
			t.Errorf("ErrorHint output missing %q. Got output:\n%s", want, out)
		}
	}
}

func TestStep_allStates(t *testing.T) {
	cases := []struct {
		state string
		icon  string
	}{
		{"ok", "✓"},
		{"fail", "✗"},
		{"", "•"},
	}
	for _, tc := range cases {
		u, buf := newBuf()
		u.Step(tc.state, "doing something")
		u.Flush()
		out := out(buf)
		if !strings.Contains(out, tc.icon) {
			t.Errorf("Step(%q) missing icon %q. Got output:\n%s", tc.state, tc.icon, out)
		}
		if !strings.Contains(out, "doing something") {
			t.Errorf("Step(%q) missing message. Got output:\n%s", tc.state, out)
		}
	}
}

func TestHelpScreen_containsSectionTitlesAndCommands(t *testing.T) {
	u, buf := newBuf()
	u.HelpScreen([]HelpSection{
		{
			Title: "Scaffolding",
			Commands: []HelpCmd{
				{Cmd: "agbero init", Desc: "scaffold config"},
			},
		},
	})
	u.Flush()
	out := out(buf)

	// Title is converted to uppercase
	if !strings.Contains(out, "SCAFFOLDING") {
		t.Errorf("HelpScreen missing section title. Got output:\n%s", out)
	}
	if !strings.Contains(out, "agbero init") {
		t.Errorf("HelpScreen missing command. Got output:\n%s", out)
	}
}

func TestInitSuccess_containsRequiredFields(t *testing.T) {
	u, buf := newBuf()
	u.InitSuccess("/etc/agbero.hcl", "admin", "s3cr3t!", []ListItem{{Text: "agbero service start"}})
	u.Flush()
	out := out(buf)

	expected := []string{"/etc/agbero.hcl", "admin", "s3cr3t!", "agbero service start"}
	for _, want := range expected {
		if !strings.Contains(out, want) {
			t.Errorf("InitSuccess missing %q. Got output:\n%s", want, out)
		}
	}
}

func TestTable_containsHeadersAndData(t *testing.T) {
	u, buf := newBuf()
	u.Table(
		[]string{"Name", "Size"},
		[][]string{{"ca.pem", "1.2 KB"}},
	)
	u.Flush()
	out := out(buf)

	if !strings.Contains(out, "Name") {
		t.Errorf("Table missing header 'Name'. Got output:\n%s", out)
	}
	if !strings.Contains(out, "ca.pem") {
		t.Errorf("Table missing data 'ca.pem'. Got output:\n%s", out)
	}
}

// Edge cases

func TestKeyValueBlock_emptyNoOutput(t *testing.T) {
	u, buf := newBuf()
	u.KeyValueBlock("title", []KV{})
	u.Flush()
	if buf.Len() != 0 {
		t.Errorf("KeyValueBlock with empty pairs should produce no output, got %q", buf.String())
	}
}

func TestKeyValueBlock_multibyteLabelAlignment(t *testing.T) {
	u, buf := newBuf()
	u.KeyValueBlock("", []KV{
		{Label: "日本語", Value: "japanese"},
		{Label: "English", Value: "english"},
	})
	u.Flush()
	out := out(buf)

	// Look for the separator character (pipe) or spaces that indicate alignment
	// The separator might be '│' or '|' depending on the rendering
	separatorCount := strings.Count(out, "│") + strings.Count(out, "|")
	if separatorCount < 2 {
		t.Errorf("expected at least 2 separator chars for 2 rows, got %d in output:\n%s",
			separatorCount, out)
	}
}

func TestDefaultTheme_allFieldsSet(t *testing.T) {
	empty := compat.AdaptiveColor{}
	th := DefaultTheme
	fields := []compat.AdaptiveColor{th.Primary, th.Secondary, th.Faint, th.Accent,
		th.Success, th.Warn, th.Danger, th.Value, th.Border}
	for i, c := range fields {
		if c == empty {
			t.Errorf("DefaultTheme field %d is zero value", i)
		}
	}
}

func TestComposition_multipleCallsAccumulate(t *testing.T) {
	u, _ := newBuf()
	u.line("first")
	u.line("second")
	internal := u.String()
	if !strings.Contains(internal, "first") || !strings.Contains(internal, "second") {
		t.Errorf("multiple line() calls did not accumulate: %q", internal)
	}
	if !utf8.ValidString(internal) {
		t.Error("buffer contains invalid UTF-8")
	}
}

// Additional test to verify that indentation doesn't hide content
func TestIndentation_preservesContent(t *testing.T) {
	u, buf := newBuf()
	u.indented("test content")
	u.Flush()
	out := out(buf)

	if !strings.Contains(out, "test content") {
		t.Errorf("Indented content missing. Got output: %q", out)
	}
}
