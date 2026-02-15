package alaye

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Status int

const (
	Success Status = 1
	Fail    Status = -1
	Unknown Status = 0
)

var (
	_ encoding.TextUnmarshaler = (*Status)(nil)
	_ encoding.TextMarshaler   = (*Status)(nil)
	_ json.Unmarshaler         = (*Status)(nil)
	_ json.Marshaler           = (*Status)(nil)
)

func NewStatus(v interface{}) Status {
	var s Status
	_ = s.Set(v)
	return s
}

func (s *Status) Set(v interface{}) error {
	switch val := v.(type) {
	case Status:
		*s = val
	case int:
		*s = Status(val)
	case bool:
		if val {
			*s = Success
		} else {
			*s = Fail
		}
	case string:
		return s.UnmarshalText([]byte(val))
	default:
		*s = Unknown
	}
	return nil
}

func (s Status) Enabled() bool  { return s == Success }
func (s Status) Disabled() bool { return s == Fail }
func (s Status) Default() bool  { return s == Unknown }
func (s Status) Int() int       { return int(s) }
func (s Status) Bool() bool     { return s == Success }

func (s Status) Toggle() Status {
	if s.Disabled() {
		return Success
	}
	return Fail
}

func (s Status) String() string {
	switch s {
	case Success:
		return "on"
	case Fail:
		return "off"
	default:
		return "unknown"
	}
}

func (s *Status) UnmarshalText(text []byte) error {
	raw := strings.ToLower(strings.TrimSpace(string(text)))

	switch raw {
	case "on", "true", "enabled", "enable", "yes":
		*s = Success
		return nil
	case "off", "false", "disabled", "disable", "no":
		*s = Fail
		return nil
	case "unknown", "default", "":
		*s = Unknown
		return nil
	}

	if i, err := strconv.Atoi(raw); err == nil {
		*s = Status(i)
		return nil
	}

	return fmt.Errorf("invalid status value: %s", raw)
}

func (s Status) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		return s.UnmarshalText([]byte(str))
	}

	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		*s = Status(i)
		return nil
	}

	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if b {
			*s = Success
		} else {
			*s = Fail
		}
		return nil
	}

	return fmt.Errorf("invalid JSON status: %s", string(data))
}
