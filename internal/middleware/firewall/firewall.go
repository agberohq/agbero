package firewall

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/yl2chen/cidranger"
)

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
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	// Ensure templates are compiled if New was called without full Validate flow
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

func (e *Engine) Handler(next http.Handler, contextRoute *alaye.RouteFirewall) http.Handler {
	if e == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientip.ClientIP(r)

		// 1. Check Bans (Persisted)
		if ban, err := e.store.GetBan(ip); err == nil && !ban.IsExpired() {
			e.blockRequest(w, r, "banned_ip", ban.Reason)
			return
		}

		// 2. Static Whitelist (Always Global)
		if e.checkRanger(e.whitelistRanger, ip) {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Static Blacklist (Always Global)
		if e.checkRanger(e.blacklistRanger, ip) {
			e.handleAction(w, r, nil, "static_blacklist", "blocked_ip")
			return
		}

		// 4. Body Inspection
		var bodySample []byte
		if e.shouldInspectBody(r) {
			var err error
			bodySample, err = e.peekBody(r)
			if err != nil {
				e.logger.Debug("failed to peek body", "err", err)
			}
		}

		inspector := &Inspector{
			Req:    r,
			Body:   bodySample,
			IP:     ip,
			Logger: e.logger,
		}

		// 5. Global Dynamic Rules
		// Only run if the route DOES NOT ignore global rules
		runGlobal := true
		if contextRoute != nil && contextRoute.IgnoreGlobal {
			runGlobal = false
		}

		if runGlobal {
			if matched, rule := e.evaluateRules(e.cfg.Rules, inspector); matched {
				e.handleAction(w, r, rule, rule.Name, "global_rule_match")
				return
			}
		}

		// 6. Route Specific Rules
		if contextRoute != nil && contextRoute.Enabled {
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
	// ContentLength -1 means chunked (unknown size), we still peek up to limit
	if r.ContentLength == 0 {
		return false
	}

	ct := r.Header.Get("Content-Type")
	if ct == "" && len(e.cfg.InspectContentTypes) > 0 {
		return false // Require explicit CT if whitelist exists
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

	// Read limited amount
	limitReader := io.LimitReader(r.Body, e.cfg.MaxInspectBytes)
	n, err := buf.ReadFrom(limitReader)
	if err != nil && err != io.EOF {
		return nil, err
	}

	sample := make([]byte, n)
	copy(sample, buf.Bytes())

	// Restore body
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
		if r.Match != nil && len(r.Match.IP) > 0 {
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
