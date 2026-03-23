package ui

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"charm.land/lipgloss/v2/compat"
)

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

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
	return b.String()
}

// ─────────────────────────────────────────────
//  Core functionality
// ─────────────────────────────────────────────

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
	out := out(buf)
	for _, want := range []string{"Config file", "/etc/agbero.hcl", "Admin user", "admin"} {
		if !strings.Contains(out, want) {
			t.Errorf("KeyValueBlock output missing %q: %q", want, out)
		}
	}
}

func TestSecretBox_containsLabelAndValue(t *testing.T) {
	u, buf := newBuf()
	u.SecretBox("Cluster key", "b64.abc123XYZ==")
	out := out(buf)
	if !strings.Contains(out, "Cluster key") {
		t.Errorf("SecretBox missing label: %q", out)
	}
	if !strings.Contains(out, "b64.abc123XYZ==") {
		t.Errorf("SecretBox missing value: %q", out)
	}
}

func TestStatusBadge_knownStatuses(t *testing.T) {
	statuses := []string{"running", "stopped", "error"}
	for _, status := range statuses {
		u, buf := newBuf()
		u.StatusBadge(status)
		out := out(buf)
		if !strings.Contains(out, status) {
			t.Errorf("StatusBadge(%q) output missing status text: %q", status, out)
		}
	}
}

func TestSuccessLine(t *testing.T) {
	u, buf := newBuf()
	u.SuccessLine("CA installed")
	out := out(buf)
	if !strings.Contains(out, "✓") || !strings.Contains(out, "CA installed") {
		t.Errorf("SuccessLine output: %q", out)
	}
}

func TestErrorHint_withHint(t *testing.T) {
	u, buf := newBuf()
	u.ErrorHint("config not found", "run agbero init")
	out := out(buf)
	for _, want := range []string{"✗", "config not found", "→", "run agbero init"} {
		if !strings.Contains(out, want) {
			t.Errorf("ErrorHint output missing %q: %q", want, out)
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
		out := out(buf)
		if !strings.Contains(out, tc.icon) || !strings.Contains(out, "doing something") {
			t.Errorf("Step(%q) output: %q", tc.state, out)
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
	out := out(buf)
	if !strings.Contains(out, "SCAFFOLDING") || !strings.Contains(out, "agbero init") {
		t.Errorf("HelpScreen output: %q", out)
	}
}

func TestInitSuccess_containsRequiredFields(t *testing.T) {
	u, buf := newBuf()
	u.InitSuccess("/etc/agbero.hcl", "admin", "s3cr3t!", []string{"agbero service start"})
	out := out(buf)
	for _, want := range []string{"/etc/agbero.hcl", "admin", "s3cr3t!", "agbero service start"} {
		if !strings.Contains(out, want) {
			t.Errorf("InitSuccess missing %q", want)
		}
	}
}

func TestTable_containsHeadersAndData(t *testing.T) {
	u, buf := newBuf()
	u.Table(
		[]string{"Name", "Size"},
		[][]string{{"ca.pem", "1.2 KB"}},
	)
	out := out(buf)
	if !strings.Contains(out, "Name") || !strings.Contains(out, "ca.pem") {
		t.Errorf("Table output: %q", out)
	}
}

// ─────────────────────────────────────────────
//  Edge cases
// ─────────────────────────────────────────────

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
	out := out(buf)
	count := strings.Count(out, "│")
	if count < 2 {
		t.Errorf("expected at least 2 separator chars for 2 rows, got %d in %q", count, out)
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
