package alaye

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDuration_UnmarshalText_goDurationString(t *testing.T) {
	cases := []struct {
		input    string
		expected time.Duration
	}{
		{"30s", 30 * time.Second},
		{"1m", time.Minute},
		{"1m30s", 90 * time.Second},
		{"100ms", 100 * time.Millisecond},
		{"1h", time.Hour},
		{"0s", 0},
		{"0", 0},
	}
	for _, c := range cases {
		var d Duration
		if err := d.UnmarshalText([]byte(c.input)); err != nil {
			t.Errorf("input %q: unexpected error: %v", c.input, err)
			continue
		}
		if d.StdDuration() != c.expected {
			t.Errorf("input %q: got %v, want %v", c.input, d.StdDuration(), c.expected)
		}
	}
}

func TestDuration_UnmarshalText_bareInteger(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("30")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.StdDuration() != 30*time.Second {
		t.Errorf("got %v, want 30s", d.StdDuration())
	}
}

func TestDuration_UnmarshalText_emptyString(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 0 {
		t.Errorf("got %v, want 0", d)
	}
}

func TestDuration_UnmarshalText_whitespace(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("  30s  ")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.StdDuration() != 30*time.Second {
		t.Errorf("got %v, want 30s", d.StdDuration())
	}
}

func TestDuration_UnmarshalText_invalid(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("not-a-duration")); err == nil {
		t.Error("expected error for invalid input, got nil")
	}
}

func TestDuration_MarshalText_roundTrip(t *testing.T) {
	cases := []string{"30s", "1m0s", "1h0m0s", "100ms", "0s"}
	for _, input := range cases {
		var d Duration
		if err := d.UnmarshalText([]byte(input)); err != nil {
			t.Errorf("UnmarshalText(%q): %v", input, err)
			continue
		}
		out, err := d.MarshalText()
		if err != nil {
			t.Errorf("MarshalText(%q): %v", input, err)
			continue
		}
		var d2 Duration
		if err := d2.UnmarshalText(out); err != nil {
			t.Errorf("second UnmarshalText(%q): %v", string(out), err)
			continue
		}
		if d != d2 {
			t.Errorf("round-trip mismatch for %q: got %v", input, d2)
		}
	}
}

func TestDuration_StdDuration(t *testing.T) {
	d := Duration(45 * time.Second)
	if d.StdDuration() != 45*time.Second {
		t.Errorf("StdDuration: got %v, want 45s", d.StdDuration())
	}
}

func TestDuration_Seconds(t *testing.T) {
	d := Duration(90 * time.Second)
	if d.Seconds() != 90.0 {
		t.Errorf("Seconds: got %v, want 90.0", d.Seconds())
	}
}

func TestDuration_String(t *testing.T) {
	d := Duration(2 * time.Minute)
	if d.String() != "2m0s" {
		t.Errorf("String: got %q, want %q", d.String(), "2m0s")
	}
}

func TestDuration_MarshalJSON_string(t *testing.T) {
	d := Duration(30 * time.Second)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(b) != `"30s"` {
		t.Errorf("MarshalJSON: got %s, want %q", b, "30s")
	}
}

func TestDuration_UnmarshalJSON_string(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"1m30s"`), &d); err != nil {
		t.Fatalf("UnmarshalJSON string: %v", err)
	}
	if d.StdDuration() != 90*time.Second {
		t.Errorf("got %v, want 90s", d.StdDuration())
	}
}

func TestDuration_UnmarshalJSON_number(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`60`), &d); err != nil {
		t.Fatalf("UnmarshalJSON number: %v", err)
	}
	if d.StdDuration() != 60*time.Second {
		t.Errorf("got %v, want 60s", d.StdDuration())
	}
}

func TestDuration_UnmarshalJSON_invalid(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`true`), &d); err == nil {
		t.Error("expected error for bool JSON value, got nil")
	}
}

func TestDuration_interfaceCompliance(t *testing.T) {
	var d Duration
	_ = interface{ UnmarshalText([]byte) error }(&d)
	_ = interface{ MarshalText() ([]byte, error) }(d)
	_ = interface{ UnmarshalJSON([]byte) error }(&d)
	_ = interface{ MarshalJSON() ([]byte, error) }(d)
}
