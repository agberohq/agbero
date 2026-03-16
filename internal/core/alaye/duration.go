package alaye

import (
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

type Duration time.Duration

// UnmarshalText implements the encoding.TextUnmarshaler interface
// Parses human-readable time strings or raw integers into standard durations
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

// String returns the formatted string representation of the duration
// Formats the underlying time value into a standard Go duration string
func (d Duration) String() string {
	return time.Duration(d).String()
}

// MarshalJSON implements the json.Marshaler interface
// Encodes the duration as a standard string for JSON serialization
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface
// Supports parsing both string and integer types from JSON payloads
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
