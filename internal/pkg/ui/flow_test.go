package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestFlowFeedback(t *testing.T) {
	var buf bytes.Buffer
	f := NewFlow(WithWriter(&buf), WithIndent(0))
	f.Start("doing work").Done("work complete").Info("details")
	out := buf.String()
	for _, want := range []string{"doing work", "work complete", "details"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}
}
