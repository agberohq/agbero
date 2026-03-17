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
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/bot"
	"github.com/olekukonko/ll"
	"github.com/yl2chen/cidranger"
)

type Inspector struct {
	Req      *http.Request
	Body     []byte
	IP       string
	ParsedIP net.IP
	IsBot    bool
	Logger   *ll.Logger
}

type readCloserWrapper struct {
	io.Reader
	io.Closer
}

type Config struct {
	Firewall    *alaye.Firewall
	DataDir     woos.Folder
	Logger      *ll.Logger
	IPMgr       *zulu.IPManager
	SharedState woos.SharedState
	BotChecker  *bot.Checker
}

type Engine struct {
	cfg             *alaye.Firewall
	store           *Store
	counters        *Counters
	logger          *ll.Logger
	whitelistRanger cidranger.Ranger
	blacklistRanger cidranger.Ranger
	ipMgr           *zulu.IPManager
	sharedState     woos.SharedState
	botChecker      *bot.Checker
}

// New establishes deep packet inspection rules for perimeter security.
// It orchestrates whitelists, persistent local bans, and distributed dynamic thresholds.
func New(cfg Config) (*Engine, error) {
	if cfg.Firewall == nil || cfg.Firewall.Status.Inactive() {
		return nil, nil
	}
	if err := cfg.Firewall.Validate(); err != nil {
		return nil, err
	}
	if !cfg.DataDir.IsSet() {
		return nil, woos.ErrDataDirNotSet
	}
	store, err := NewStore(cfg.DataDir, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("firewall store init: %w", err)
	}
	ipMgr := cfg.IPMgr
	if ipMgr == nil {
		ipMgr = zulu.IP
	}
	botChecker := cfg.BotChecker
	if botChecker == nil {
		botChecker = bot.NewChecker()
	}
	e := &Engine{
		cfg:             cfg.Firewall,
		store:           store,
		counters:        NewCounters(),
		logger:          cfg.Logger.Namespace("firewall"),
		whitelistRanger: cidranger.NewPCTrieRanger(),
		blacklistRanger: cidranger.NewPCTrieRanger(),
		ipMgr:           ipMgr,
		sharedState:     cfg.SharedState,
		botChecker:      botChecker,
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

// Handler actively checks every packet traversing the mesh configuration boundaries.
// Applies immediate dropping or payload capturing dependent on rule expressions.
func (e *Engine) Handler(next http.Handler, contextRoute *alaye.FirewallRoute) http.Handler {
	if e == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := e.ipMgr.ClientIP(r)
		if ban, err := e.store.GetBan(ip); err == nil && !ban.IsExpired() {
			e.blockRequest(w, r, "banned_ip", ban.Reason)
			return
		}
		if e.checkRanger(e.whitelistRanger, ip) {
			next.ServeHTTP(w, r)
			return
		}
		if e.checkRanger(e.blacklistRanger, ip) {
			e.handleAction(w, r, alaye.Rule{}, "static_blacklist", "blocked_ip")
			return
		}
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
			IsBot:    e.botChecker.IsBot(r.UserAgent()),
			Logger:   e.logger,
		}
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
		if contextRoute != nil && contextRoute.Status.Active() && contextRoute.Rules != nil {
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
	limit := e.cfg.MaxInspectBytes
	if r.ContentLength > 0 && r.ContentLength < limit {
		limit = r.ContentLength
	}
	sample := make([]byte, limit)
	n, err := io.ReadFull(r.Body, sample)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	sample = sample[:n]
	r.Body = &readCloserWrapper{
		Reader: io.MultiReader(bytes.NewReader(sample), r.Body),
		Closer: r.Body,
	}
	return sample, nil
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

// Unblock removes an IP from the persistent ban store.
func (e *Engine) Unblock(ip string) error { return e.store.Remove(ip) }

// Block adds an IP to the persistent ban store with a reason and expiry duration.
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
		if !rule.Match.Enabled.Active() {
			continue
		}
		if e.checkMatch(rule.Match, in) {
			if rule.Type == "dynamic" && rule.Match.Threshold != nil && rule.Match.Threshold.Enabled.Active() {
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
	if c.Enabled.NotActive() {
		return false
	}
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
	case "bot":
		if in.IsBot {
			val = "true"
		} else {
			val = "false"
		}
	}
	if c.IgnoreCase {
		val = strings.ToLower(val)
	}
	match := false
	if c.Compiled != nil {
		match = c.Compiled.MatchString(val)
	} else if c.Pattern != "" {
		if re, err := regexp.Compile(c.Pattern); err == nil {
			match = re.MatchString(val)
		} else {
			e.logger.Debug("invalid regex pattern in rule", "pattern", c.Pattern)
			return false
		}
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
	if t == nil || t.Enabled.NotActive() {
		return true
	}
	key := in.IP
	if after, ok := strings.CutPrefix(t.TrackBy, "header:"); ok {
		key = in.Req.Header.Get(after)
	} else if after, ok := strings.CutPrefix(t.TrackBy, "cookie:"); ok {
		if cookie, err := in.Req.Cookie(after); err == nil {
			key = cookie.Value
		}
	}
	if rule.Match.Extract != nil && rule.Match.Extract.Enabled.Active() && rule.Match.Extract.Regex != nil {
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

	var count int64
	var err error
	if e.sharedState != nil {
		count, err = e.sharedState.Increment(in.Req.Context(), "fw:"+rule.Name+":"+key, t.Window.StdDuration())
		if err != nil {
			e.logger.Debug("redis shared state increment failed, failing open", "err", err)
			return false
		}
	} else {
		count = e.counters.Increment(rule.Name, key, t.Window.StdDuration())
	}

	return count >= int64(t.Count)
}

// List returns all active ban rules from the persistent store.
func (e *Engine) List() ([]Rule, error) {
	if e == nil || e.store == nil {
		return nil, nil
	}
	return e.store.LoadAll()
}

// ClearStore removes all ban rules from the persistent store.
func (e *Engine) ClearStore() error {
	if e == nil || e.store == nil {
		return nil
	}
	return e.store.Clear()
}

// PruneStore removes expired ban rules from the persistent store.
func (e *Engine) PruneStore() (int, error) {
	if e == nil || e.store == nil {
		return 0, nil
	}
	return e.store.PruneExpired()
}
