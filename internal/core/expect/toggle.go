package expect

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Toggle int

const (
	Active   Toggle = 1
	Inactive Toggle = -1
	Unknown  Toggle = 0
)

var (
	_ encoding.TextUnmarshaler = (*Toggle)(nil)
	_ encoding.TextMarshaler   = (*Toggle)(nil)
	_ json.Unmarshaler         = (*Toggle)(nil)
	_ json.Marshaler           = (*Toggle)(nil)
)

func NewEnabled(v any) Toggle {
	var s Toggle
	_ = s.Set(v)
	return s
}

func (s *Toggle) Set(v any) error {
	switch val := v.(type) {
	case Toggle:
		*s = val
	case int:
		*s = Toggle(val)
	case bool:
		if val {
			*s = Active
		} else {
			*s = Inactive
		}
	case string:
		return s.UnmarshalText([]byte(val))
	default:
		*s = Unknown
	}
	return nil
}

func (s Toggle) Active() bool    { return s == Active }
func (s Toggle) Inactive() bool  { return s == Inactive }
func (s Toggle) NotActive() bool { return s != Active }

func (s Toggle) Default() bool { return s == Unknown }
func (s Toggle) Int() int      { return int(s) }
func (s Toggle) Bool() bool    { return s == Active }
func (s Toggle) IsZero() bool  { return s == Unknown }

func (s Toggle) Toggle() Toggle {
	if s.Inactive() {
		return Active
	}
	return Inactive
}

func (s Toggle) String() string {
	switch s {
	case Active:
		return "on"
	case Inactive:
		return "off"
	default:
		return "unknown"
	}
}

func (s *Toggle) UnmarshalText(text []byte) error {
	raw := strings.ToLower(strings.TrimSpace(string(text)))

	switch raw {
	case "on", "true", "enabled", "enable", "yes":
		*s = Active
		return nil
	case "off", "false", "disabled", "disable", "no":
		*s = Inactive
		return nil
	case "unknown", "default", "":
		*s = Unknown
		return nil
	}

	if i, err := strconv.Atoi(raw); err == nil {
		*s = Toggle(i)
		return nil
	}

	return fmt.Errorf("invalid status value: %s", raw)
}

func (s Toggle) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s Toggle) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Toggle) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		return s.UnmarshalText([]byte(str))
	}

	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		*s = Toggle(i)
		return nil
	}

	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if b {
			*s = Active
		} else {
			*s = Inactive
		}
		return nil
	}

	return fmt.Errorf("invalid JSON status: %s", string(data))
}

func (s *Toggle) Ensure(def Toggle) {
	if *s == Unknown {
		*s = def
	}
}
