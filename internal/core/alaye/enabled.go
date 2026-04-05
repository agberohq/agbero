package alaye

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Enabled int

const (
	Active   Enabled = 1
	Inactive Enabled = -1
	Unknown  Enabled = 0
)

var (
	_ encoding.TextUnmarshaler = (*Enabled)(nil)
	_ encoding.TextMarshaler   = (*Enabled)(nil)
	_ json.Unmarshaler         = (*Enabled)(nil)
	_ json.Marshaler           = (*Enabled)(nil)
)

func NewStatus(v any) Enabled {
	var s Enabled
	_ = s.Set(v)
	return s
}

func (s *Enabled) Set(v any) error {
	switch val := v.(type) {
	case Enabled:
		*s = val
	case int:
		*s = Enabled(val)
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

func (s Enabled) Active() bool    { return s == Active }
func (s Enabled) Inactive() bool  { return s == Inactive }
func (s Enabled) NotActive() bool { return s != Active }

func (s Enabled) Default() bool { return s == Unknown }
func (s Enabled) Int() int      { return int(s) }
func (s Enabled) Bool() bool    { return s == Active }

func (s Enabled) Toggle() Enabled {
	if s.Inactive() {
		return Active
	}
	return Inactive
}

func (s Enabled) String() string {
	switch s {
	case Active:
		return "on"
	case Inactive:
		return "off"
	default:
		return "unknown"
	}
}

func (s *Enabled) UnmarshalText(text []byte) error {
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
		*s = Enabled(i)
		return nil
	}

	return fmt.Errorf("invalid status value: %s", raw)
}

func (s Enabled) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s Enabled) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Enabled) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		return s.UnmarshalText([]byte(str))
	}

	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		*s = Enabled(i)
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

func (s *Enabled) Ensure(def Enabled) {
	if *s == Unknown {
		*s = def
	}
}
