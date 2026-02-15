package firewall

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

type Inspector struct {
	Req    *http.Request
	Body   []byte
	IP     string
	Logger *ll.Logger
}

func (e *Engine) evaluateRules(rules []*alaye.Rule, in *Inspector) (bool, *alaye.Rule) {
	for _, rule := range rules {
		if rule.Match == nil {
			continue
		}

		if e.checkMatch(rule.Match, in) {
			if rule.Type == "dynamic" && rule.Match.Threshold != nil {
				triggered := e.checkThreshold(rule, in)
				if !triggered {
					continue
				}
			}
			return true, rule
		}
	}
	return false, nil
}

func (e *Engine) checkMatch(m *alaye.Match, in *Inspector) bool {
	// 1. High-level Checks
	if len(m.IP) > 0 {
		found := false
		inIP := net.ParseIP(in.IP)
		for _, ipStr := range m.IP {
			if strings.Contains(ipStr, "/") {
				_, netCIDR, _ := net.ParseCIDR(ipStr)
				if netCIDR != nil && inIP != nil && netCIDR.Contains(inIP) {
					found = true
					break
				}
			} else {
				if ipStr == in.IP {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	if len(m.Methods) > 0 {
		found := false
		for _, method := range m.Methods {
			if strings.EqualFold(method, in.Req.Method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(m.Path) > 0 {
		found := false
		for _, p := range m.Path {
			if strings.HasPrefix(in.Req.URL.Path, p) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// 2. Logic Blocks
	if len(m.Any) > 0 {
		matchAny := false
		for _, c := range m.Any {
			if e.checkCondition(c, in) {
				matchAny = true
				break
			}
		}
		if !matchAny {
			return false
		}
	}

	if len(m.All) > 0 {
		for _, c := range m.All {
			if !e.checkCondition(c, in) {
				return false
			}
		}
	}

	if len(m.None) > 0 {
		for _, c := range m.None {
			if e.checkCondition(c, in) {
				return false
			}
		}
	}

	return true
}

func (e *Engine) checkCondition(c *alaye.Condition, in *Inspector) bool {
	var val string
	switch c.Location {
	case "ip":
		val = in.IP
	case "path", "uri":
		val = in.Req.URL.Path
	case "method":
		val = in.Req.Method
	case "header", "headers":
		val = in.Req.Header.Get(c.Key)
	case "query":
		val = in.Req.URL.Query().Get(c.Key)
	case "body":
		if len(in.Body) > 0 {
			val = string(in.Body)
		}
	}

	if c.IgnoreCase {
		val = strings.ToLower(val)
	}

	match := false

	// Regex Matching
	if c.Compiled != nil {
		match = c.Compiled.MatchString(val)
	} else if c.Pattern != "" {
		// Fallback if compiled not set (shouldn't happen in prod, but safe for tests)
		match, _ = regexp.MatchString(c.Pattern, val)
	} else {
		// String Operator Matching
		target := c.Value
		if c.IgnoreCase {
			target = strings.ToLower(target)
		}

		switch c.Operator {
		case "contains":
			match = strings.Contains(val, target)
		case "prefix":
			match = strings.HasPrefix(val, target)
		case "suffix":
			match = strings.HasSuffix(val, target)
		case "empty":
			match = val == ""
		case "missing":
			match = val == ""
		default:
			// Exact match default.
			// Only match empty string if target is explicitly empty.
			match = val == target
		}
	}

	if c.Negate {
		return !match
	}
	return match
}

func (e *Engine) checkThreshold(rule *alaye.Rule, in *Inspector) bool {
	t := rule.Match.Threshold
	if t == nil {
		return true
	}

	key := in.IP
	if strings.HasPrefix(t.TrackBy, "header:") {
		h := strings.TrimPrefix(t.TrackBy, "header:")
		key = in.Req.Header.Get(h)
	} else if strings.HasPrefix(t.TrackBy, "cookie:") {
		c := strings.TrimPrefix(t.TrackBy, "cookie:")
		if cookie, err := in.Req.Cookie(c); err == nil {
			key = cookie.Value
		}
	}

	if rule.Match.Extract != nil && rule.Match.Extract.Regex != nil {
		var src string
		switch rule.Match.Extract.From {
		case "body":
			src = string(in.Body)
		case "query":
			src = in.Req.URL.RawQuery
		}
		matches := rule.Match.Extract.Regex.FindStringSubmatch(src)
		if len(matches) > 1 {
			key = key + "|" + matches[1]
		}
	}

	if key == "" {
		return false
	}

	count := e.counters.Increment(rule.Name, key, t.Window.TimeDuration())
	return count >= int64(t.Count)
}
