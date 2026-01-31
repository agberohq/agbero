package backend

import (
	"net"
	"net/http"
	"net/textproto"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
)

type ipRule struct {
	ip   net.IP
	cidr *net.IPNet
}

type Conditions struct {
	hasRules bool
	ips      []ipRule
	headers  map[string]string // canonical header key -> expected value
}

func NewConditions(c *alaye.Conditions) (*Conditions, error) {
	if c == nil {
		return nil, nil
	}

	out := &Conditions{
		headers: make(map[string]string),
	}

	// IP/CIDR rules
	for _, s := range c.SourceIPs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		if strings.Contains(s, woos.Slash) {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, errors.Newf("%w: %s", woos.ErrInvalidSrcCond, s)
			}
			out.ips = append(out.ips, ipRule{cidr: n})
			out.hasRules = true
			continue
		}

		ip := net.ParseIP(s)
		if ip == nil {
			return nil, errors.Newf("%w: %s", woos.ErrInvalidSrcCond, s)
		}
		out.ips = append(out.ips, ipRule{ip: ip})
		out.hasRules = true
	}

	// Headers exact match (AND)
	for k, v := range c.Headers {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out.headers[textproto.CanonicalMIMEHeaderKey(k)] = v
		out.hasRules = true
	}

	// Empty block => treat as no conditions.
	if !out.hasRules {
		return nil, nil
	}

	return out, nil
}

func (c *Conditions) HasRules() bool {
	return c != nil && c.hasRules
}

func (c *Conditions) Match(r *http.Request) bool {
	if c == nil || !c.hasRules {
		return true
	}

	// IP/CIDR check
	if len(c.ips) > 0 {
		ipStr := clientip.ClientIP(r)
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}

		ok := false
		for _, rule := range c.ips {
			if rule.cidr != nil {
				if rule.cidr.Contains(ip) {
					ok = true
					break
				}
				continue
			}
			if rule.ip != nil && rule.ip.Equal(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	// Header checks
	if len(c.headers) > 0 {
		for k, want := range c.headers {
			if r.Header.Get(k) != want {
				return false
			}
		}
	}

	return true
}
