package alaye

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	baseTen      = 10
	bitSize64    = 64
	emptySeconds = 0
)

var (
	_ encoding.TextUnmarshaler = (*Duration)(nil)
	_ encoding.TextMarshaler   = (*Duration)(nil)
	_ json.Unmarshaler         = (*Duration)(nil)
	_ json.Marshaler           = (*Duration)(nil)
)

type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler for HCL2 and other text-based decoders.
// Accepts Go duration strings ("30s", "1m"), bare integers treated as seconds, and empty strings as zero.
func (d *Duration) UnmarshalText(text []byte) error {
	str := strings.TrimSpace(string(text))
	if str == "" {
		*d = emptySeconds
		return nil
	}

	if parsed, err := time.ParseDuration(str); err == nil {
		*d = Duration(parsed)
		return nil
	}

	if val, err := strconv.ParseInt(str, baseTen, bitSize64); err == nil {
		*d = Duration(time.Duration(val) * time.Second)
		return nil
	}

	return fmt.Errorf("invalid duration format: %s", str)
}

// MarshalText implements encoding.TextMarshaler for hclwrite round-trip serialisation.
// Encodes the duration as a standard Go duration string such as "30s" or "1m30s".
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// String returns the formatted string representation of the duration.
// Delegates to the underlying time.Duration for standard Go formatting.
func (d Duration) String() string {
	return time.Duration(d).String()
}

// StdDuration returns the underlying time.Duration value.
// Use at stdlib assignment sites such as http.Server fields to avoid scattered casts.
func (d Duration) StdDuration() time.Duration {
	return time.Duration(d)
}

// Seconds returns the duration as a floating-point number of seconds.
// Proxies time.Duration.Seconds so callers do not need a cast after field type changes.
func (d Duration) Seconds() float64 {
	return time.Duration(d).Seconds()
}

// MarshalJSON implements json.Marshaler.
// Encodes the duration as a string for JSON serialisation.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements json.Unmarshaler.
// Supports both string ("30s") and numeric (30 treated as seconds) JSON values.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value) * time.Second)
		return nil
	case string:
		return d.UnmarshalText([]byte(value))
	default:
		return fmt.Errorf("invalid duration json type")
	}
}
