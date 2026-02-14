package firewall

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/retry"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/cenkalti/backoff/v4"
	"github.com/olekukonko/ll"
	"github.com/yl2chen/cidranger"
	"golang.org/x/sync/singleflight"
)

var (
	metricsLocalBlocks  uint64
	metricsRemoteBlocks uint64
	metricsRemoteErrors uint64
)

type IPSet struct {
	mu sync.RWMutex

	v4 map[netip.Addr][]*Rule
	v6 map[netip.Addr][]*Rule

	ranger cidranger.Ranger

	// blockedExceptions stores IPs explicitly unblocked even if inside a CIDR
	blockedExceptions map[netip.Addr]struct{}

	store *Store

	remote string
	client *http.Client
	flight singleflight.Group
	cache  *ttlCache
	logger *ll.Logger
}

type cacheEntry struct {
	blocked  bool
	expireAt time.Time
}

type ttlCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	stop    chan struct{}
}

func newTTLCache(cleanupInterval time.Duration) *ttlCache {
	c := &ttlCache{
		entries: make(map[string]cacheEntry),
		stop:    make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ticker.C:
				c.mu.Lock()
				now := time.Now()
				for k, v := range c.entries {
					if now.After(v.expireAt) {
						delete(c.entries, k)
					}
				}
				c.mu.Unlock()
			}
		}
	}()
	return c
}

func (c *ttlCache) get(key string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return false, false
	}
	if time.Now().After(entry.expireAt) {
		delete(c.entries, key)
		return false, false
	}
	return entry.blocked, true
}

func (c *ttlCache) set(key string, blocked bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := 1 * time.Minute
	if blocked {
		ttl = 5 * time.Minute
	}
	c.entries[key] = cacheEntry{
		blocked:  blocked,
		expireAt: time.Now().Add(ttl),
	}
}

func (c *ttlCache) close() {
	close(c.stop)
}

func New(cfg *alaye.Firewall, dataDir woos.Folder, logger *ll.Logger) (*IPSet, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	timeout := time.Duration(cfg.RemoteTimeout) * time.Second
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	f := &IPSet{
		v4:                make(map[netip.Addr][]*Rule),
		v6:                make(map[netip.Addr][]*Rule),
		ranger:            cidranger.NewPCTrieRanger(),
		blockedExceptions: make(map[netip.Addr]struct{}),
		remote:            cfg.RemoteCheck,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxConnsPerHost:     100,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		cache:  newTTLCache(5 * time.Minute),
		logger: logger.Namespace("firewall"),
	}

	store, err := NewStore(dataDir, logger)
	if err != nil {
		f.cache.close()
		return nil, fmt.Errorf("firewall store init: %w", err)
	}
	f.store = store

	rules, err := store.LoadAll()
	if err != nil {
		f.cache.close()
		return nil, fmt.Errorf("firewall load rules: %w", err)
	}
	for _, r := range rules {
		f.addRuleInMemory(r)
	}
	logger.Fields("count", len(rules)).Info("loaded persistent firewall rules")

	if cfg.BlockList != "" {
		if err := f.importTextFile(cfg.BlockList); err != nil {
			logger.Warnf("failed to load blocklist %q: %v", cfg.BlockList, err)
		}
	}

	return f, nil
}

func (f *IPSet) Close() error {
	if f == nil {
		return nil
	}
	if f.cache != nil {
		f.cache.close()
	}
	if f.store == nil {
		return nil
	}
	return f.store.Close()
}

func (f *IPSet) List() ([]Rule, error) {
	if f.store == nil {
		return nil, nil
	}
	return f.store.LoadAll()
}

func (f *IPSet) Unblock(ip string) error {
	if f.store == nil {
		return nil
	}

	if err := f.store.Remove(ip); err != nil {
		return err
	}

	addr, err := netip.ParseAddr(ip)
	if err == nil {
		addr = addr.Unmap()
		f.mu.Lock()
		f.blockedExceptions[addr] = struct{}{}
		f.mu.Unlock()
	}

	rules, err := f.store.LoadAll()
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.v4 = make(map[netip.Addr][]*Rule)
	f.v6 = make(map[netip.Addr][]*Rule)
	f.ranger = cidranger.NewPCTrieRanger()

	for _, r := range rules {
		f.addRuleInMemory(r)
	}

	f.cache.mu.Lock()
	delete(f.cache.entries, ip)
	f.cache.mu.Unlock()

	f.logger.Fields("ip", ip).Info("unblocked ip")
	return nil
}

func (f *IPSet) Block(ip, host, path, reason string, duration time.Duration) error {
	r := Rule{
		IP:        ip,
		Host:      strings.ToLower(host),
		Path:      path,
		Reason:    reason,
		CreatedAt: time.Now(),
	}
	if duration > 0 {
		r.ExpiresAt = time.Now().Add(duration)
	}

	if strings.Contains(ip, woos.Slash) {
		r.Type = BlockTypeCIDR
	} else {
		r.Type = BlockTypeSingle
	}

	if err := f.store.Add(r); err != nil {
		return err
	}

	f.mu.Lock()
	f.addRuleInMemory(r)
	f.mu.Unlock()

	return nil
}

func (f *IPSet) addRuleInMemory(r Rule) {
	if r.Type == BlockTypeCIDR {
		_, network, err := net.ParseCIDR(r.IP)
		if err == nil {
			_ = f.ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		return
	}

	addr, err := netip.ParseAddr(r.IP)
	if err == nil {
		addr = addr.Unmap()
		rCopy := r
		if addr.Is4() {
			f.v4[addr] = append(f.v4[addr], &rCopy)
		} else {
			f.v6[addr] = append(f.v6[addr], &rCopy)
		}
	}
}

func (f *IPSet) importTextFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	f.mu.Lock()
	defer f.mu.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		if strings.Contains(line, woos.Slash) {
			_, network, err := net.ParseCIDR(line)
			if err == nil {
				f.ranger.Insert(cidranger.NewBasicRangerEntry(*network))
				count++
			}
			continue
		}

		addr, err := netip.ParseAddr(line)
		if err == nil {
			addr = addr.Unmap()
			r := Rule{IP: line, Type: BlockTypeSingle}
			if addr.Is4() {
				f.v4[addr] = append(f.v4[addr], &r)
			} else {
				f.v6[addr] = append(f.v6[addr], &r)
			}
			count++
		}
	}

	f.logger.Fields("file", path, "imported", count).Info("imported firewall blocklist")
	return scanner.Err()
}

func (f *IPSet) Handler(next http.Handler) http.Handler {
	if f == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipStr := clientip.ClientIP(r)
		addr, err := netip.ParseAddr(ipStr)
		if err == nil {
			addr = addr.Unmap()

			f.mu.RLock()
			var rules []*Rule
			if addr.Is4() {
				rules = f.v4[addr]
			} else {
				rules = f.v6[addr]
			}
			f.mu.RUnlock()

			// Evaluate per-IP host/path rules
			if len(rules) > 0 {
				reqHost := core.NormalizeHost(r.Host)
				reqPath := r.URL.Path

				for _, rule := range rules {
					if rule.Host != "" && rule.Host != reqHost {
						continue
					}
					if rule.Path != "" && !strings.HasPrefix(reqPath, rule.Path) {
						continue
					}

					atomic.AddUint64(&metricsLocalBlocks, 1)
					http.Error(w, "Access Denied", http.StatusForbidden)
					return
				}
			}
		}

		// Check CIDR blocks, skip if IP is explicitly unblocked
		netIP := net.ParseIP(ipStr)
		if netIP != nil {
			addr, _ := netip.ParseAddr(ipStr)
			addr = addr.Unmap()

			f.mu.RLock()
			_, isUnblocked := f.blockedExceptions[addr]
			f.mu.RUnlock()

			if !isUnblocked {
				contains, err := f.ranger.Contains(netIP)
				if err == nil && contains {
					atomic.AddUint64(&metricsLocalBlocks, 1)
					http.Error(w, "Access Denied", http.StatusForbidden)
					return
				}
			}
		}

		// Remote check
		if f.remote != "" {
			if f.cachedRemoteCheck(r.Context(), ipStr) {
				atomic.AddUint64(&metricsRemoteBlocks, 1)
				http.Error(w, "Access Denied (R)", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (f *IPSet) cachedRemoteCheck(ctx context.Context, ip string) bool {
	if hit, ok := f.cache.get(ip); ok {
		return hit
	}

	val, err, _ := f.flight.Do(ip, func() (interface{}, error) {
		// Use the retry-enabled check
		blocked := f.checkRemote(ctx, ip)
		f.cache.set(ip, blocked)
		return blocked, nil
	})

	if err != nil {
		return false
	}
	return val.(bool)
}

func (f *IPSet) checkRemote(ctx context.Context, ip string) bool {
	u, err := url.Parse(f.remote)
	if err != nil {
		return false
	}
	q := u.Query()
	q.Set("ip", ip)
	u.RawQuery = q.Encode()

	// Short retry policy (don't block the request too long)
	b := backoff.WithContext(retry.NewShort(), ctx)

	var blocked bool

	_ = backoff.Retry(func() error {
		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			return backoff.Permanent(err)
		}

		resp, err := f.client.Do(req)
		if err != nil {
			// Network error, retry
			return err
		}
		defer func() {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()

		if resp.StatusCode == http.StatusForbidden {
			blocked = true
			return nil
		}
		if resp.StatusCode >= 500 {
			// Server error, retry
			return fmt.Errorf("remote firewall server error: %d", resp.StatusCode)
		}

		blocked = false
		return nil
	}, b)

	if blocked {
		atomic.AddUint64(&metricsRemoteBlocks, 1)
	}

	// If retries exhausted and err != nil, we default to false (allow)
	// This makes the firewall "fail open" on persistent remote errors to avoid outage.
	return blocked
}
