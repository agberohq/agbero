package firewall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/yl2chen/cidranger"
)

type Inspector struct {
	Req      *http.Request
	Body     []byte
	IP       string
	ParsedIP net.IP
	Logger   *ll.Logger
}

type Engine struct {
	cfg      *alaye.Firewall
	store    *Store
	counters *Counters
	logger   *ll.Logger

	whitelistRanger cidranger.Ranger
	blacklistRanger cidranger.Ranger

	bufPool sync.Pool
}

func New(cfg *alaye.Firewall, dataDir woos.Folder, logger *ll.Logger) (*Engine, error) {
	if cfg == nil || cfg.Status.No() {
		return nil, nil
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	store, err := NewStore(dataDir, logger)
	if err != nil {
		return nil, fmt.Errorf("firewall store init: %w", err)
	}

	e := &Engine{
		cfg:             cfg,
		store:           store,
		counters:        NewCounters(),
		logger:          logger.Namespace("firewall"),
		whitelistRanger: cidranger.NewPCTrieRanger(),
		blacklistRanger: cidranger.NewPCTrieRanger(),
		bufPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, cfg.MaxInspectBytes))
			},
		},
	}

	if err := e.loadStaticRules(); err != nil {
		store.Close()
		return nil, err
	}

	return e, nil
}

func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.counters.Stop()
	return e.store.Close()
}

// Handler is the middleware.
// contextRoute is optional (pass nil for global/chain usage).
func (e *Engine) Handler(next http.Handler, contextRoute *alaye.FirewallRoute) http.Handler {
	if e == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientip.ClientIP(r)

		// 1. Check dynamic bans
		if ban, err := e.store.GetBan(ip); err == nil && !ban.IsExpired() {
			e.blockRequest(w, r, "banned_ip", ban.Reason)
			return
		}

		// 2. Check Static Whitelist
		if e.checkRanger(e.whitelistRanger, ip) {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Check Static Blacklist
		if e.checkRanger(e.blacklistRanger, ip) {
			e.handleAction(w, r, alaye.Rule{}, "static_blacklist", "blocked_ip")
			return
		}

		// 4. Inspect Body if configured
		var bodySample []byte
		if e.shouldInspectBody(r) {
			var err error
			bodySample, err = e.peekBody(r)
			if err != nil {
				e.logger.Debug("failed to peek body", "err", err)
			}
		}

		parsedIP := net.ParseIP(ip)
		inspector := &Inspector{
			Req:      r,
			Body:     bodySample,
			IP:       ip,
			ParsedIP: parsedIP,
			Logger:   e.logger,
		}

		// 5. Evaluate Global Rules
		runGlobal := true
		if contextRoute != nil && contextRoute.IgnoreGlobal {
			runGlobal = false
		}

		if runGlobal && e.cfg.Rules != nil {
			if matched, rule := e.evaluateRules(e.cfg.Rules, inspector); matched {
				e.handleAction(w, r, rule, rule.Name, "global_rule_match")
				return
			}
		}

		// 6. Evaluate Route-Specific Rules
		if contextRoute != nil && contextRoute.Status.Yes() && contextRoute.Rules != nil {
			if matched, rule := e.evaluateRules(contextRoute.Rules, inspector); matched {
				e.handleAction(w, r, rule, rule.Name, "route_rule_match")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (e *Engine) shouldInspectBody(r *http.Request) bool {
	if !e.cfg.InspectBody {
		return false
	}
	if r.ContentLength == 0 {
		return false
	}

	ct := r.Header.Get("Content-Type")
	if ct == "" && len(e.cfg.InspectContentTypes) > 0 {
		return false
	}

	for _, allowed := range e.cfg.InspectContentTypes {
		if strings.Contains(ct, allowed) {
			return true
		}
	}
	return false
}

func (e *Engine) peekBody(r *http.Request) ([]byte, error) {
	buf := e.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer e.bufPool.Put(buf)

	limitReader := io.LimitReader(r.Body, e.cfg.MaxInspectBytes)
	n, err := buf.ReadFrom(limitReader)
	if err != nil && err != io.EOF {
		return nil, err
	}

	sample := make([]byte, n)
	copy(sample, buf.Bytes())

	r.Body = &readCloserWrapper{
		Reader: io.MultiReader(bytes.NewReader(sample), r.Body),
		Closer: r.Body,
	}

	return sample, nil
}

type readCloserWrapper struct {
	io.Reader
	io.Closer
}

func (e *Engine) loadStaticRules() error {
	for _, r := range e.cfg.Rules {
		if r.Type != "static" && r.Type != "whitelist" {
			continue
		}
		if len(r.Match.IP) > 0 {
			target := e.blacklistRanger
			if r.Type == "whitelist" {
				target = e.whitelistRanger
			}
			for _, ipCidr := range r.Match.IP {
				if !strings.Contains(ipCidr, "/") {
					ipCidr += "/32"
				}
				_, network, err := net.ParseCIDR(ipCidr)
				if err == nil {
					_ = target.Insert(cidranger.NewBasicRangerEntry(*network))
				}
			}
		}
	}
	return nil
}

func (e *Engine) checkRanger(ranger cidranger.Ranger, ip string) bool {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}
	contains, _ := ranger.Contains(netIP)
	return contains
}

func (e *Engine) Unblock(ip string) error { return e.store.Remove(ip) }
func (e *Engine) Block(ip, reason string, duration time.Duration) error {
	return e.store.Add(Rule{
		IP:        ip,
		Type:      BlockTypeSingle,
		Reason:    reason,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
	})
}

func (e *Engine) evaluateRules(rules []alaye.Rule, in *Inspector) (bool, alaye.Rule) {
	for _, rule := range rules {

		if e.checkMatch(rule.Match, in) {
			if rule.Type == "dynamic" && rule.Match.Threshold.Enabled.Yes() {
				triggered := e.checkThreshold(rule, in)
				if !triggered {
					continue
				}
			}
			return true, rule
		}
	}
	return false, alaye.Rule{}
}

func (e *Engine) checkMatch(m alaye.Match, in *Inspector) bool {
	if len(m.IP) > 0 {
		found := false
		for _, ipStr := range m.IP {
			if strings.Contains(ipStr, "/") {
				_, netCIDR, _ := net.ParseCIDR(ipStr)
				if netCIDR != nil && in.ParsedIP != nil && netCIDR.Contains(in.ParsedIP) {
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

func (e *Engine) checkCondition(c alaye.Condition, in *Inspector) bool {
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

	if c.Compiled != nil {
		match = c.Compiled.MatchString(val)
	} else if c.Pattern != "" {
		match, _ = regexp.MatchString(c.Pattern, val)
	} else {
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
			match = val == target
		}
	}

	if c.Negate {
		return !match
	}
	return match
}

func (e *Engine) checkThreshold(rule alaye.Rule, in *Inspector) bool {
	t := rule.Match.Threshold
	if t.Enabled.No() {
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

	if rule.Match.Extract.Enabled.Yes() && rule.Match.Extract.Regex != nil {
		var src string
		switch rule.Match.Extract.From {
		case "body":
			src = string(in.Body)
		case "query":
			src = in.Req.URL.RawQuery
		}
		matches := rule.Match.Extract.Regex.FindStringSubmatch(src)
		if len(matches) > 1 {
			hash := sha256.Sum256([]byte(matches[1]))
			key = key + ":" + hex.EncodeToString(hash[:8])
		}
	}

	if key == "" {
		return false
	}

	count := e.counters.Increment(rule.Name, key, t.Window)
	return count >= int64(t.Count)
}

func (e *Engine) List() ([]Rule, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.LoadAll()
}
