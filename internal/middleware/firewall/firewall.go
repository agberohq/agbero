package firewall

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/yl2chen/cidranger"
	"golang.org/x/sync/singleflight"
)

var (
	metricsLocalBlocks  uint64
	metricsRemoteBlocks uint64
	metricsRemoteErrors uint64
)

// IPSet is the main firewall controller handling local blocklists (IP/CIDR) and remote verification.
type IPSet struct {
	mu     sync.RWMutex
	v4     map[netip.Addr]struct{}
	v6     map[netip.Addr]struct{}
	ranger cidranger.Ranger

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
}

func newTTLCache(cleanupInterval time.Duration) *ttlCache {
	c := &ttlCache{entries: make(map[string]cacheEntry)}
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.entries {
				if now.After(v.expireAt) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
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

	// Cache duration strategy:
	// Blocked IPs: Cache longer (5m) to reduce load.
	// Allowed IPs: Cache shorter (1m) to catch status changes quickly.
	ttl := 1 * time.Minute
	if blocked {
		ttl = 5 * time.Minute
	}

	c.entries[key] = cacheEntry{
		blocked:  blocked,
		expireAt: time.Now().Add(ttl),
	}
}

// New initializes the firewall subsystem.
func New(cfg *alaye.Firewall, dataDir woos.Folder, logger *ll.Logger) (*IPSet, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	timeout := time.Duration(cfg.RemoteTimeout) * time.Second
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	f := &IPSet{
		v4:     make(map[netip.Addr]struct{}),
		v6:     make(map[netip.Addr]struct{}),
		ranger: cidranger.NewPCTrieRanger(),
		remote: cfg.RemoteCheck,
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
		logger: logger,
	}

	// 1. Initialize Persistent Storage (BoltDB)
	store, err := NewStore(dataDir, logger)
	if err != nil {
		return nil, fmt.Errorf("firewall store init: %w", err)
	}
	f.store = store

	// 2. Load Persisted Rules
	rules, err := store.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("firewall load persistent rules: %w", err)
	}
	for _, r := range rules {
		f.addRuleInMemory(r)
	}
	logger.Fields("count", len(rules)).Info("loaded persistent firewall rules")

	// 3. Load Static Blocklist File (if configured)
	if cfg.BlockList != "" {
		if err := f.importTextFile(cfg.BlockList); err != nil {
			logger.Warnf("failed to load blocklist file %q: %v", cfg.BlockList, err)
		}
	}

	return f, nil
}

func (f *IPSet) Close() error {
	// FIX: Nil check to prevent panic if firewall is disabled but Close is called
	if f == nil || f.store == nil {
		return nil
	}
	return f.store.Close()
}

// Block adds a rule to storage and memory immediately.
func (f *IPSet) Block(ip, reason string, duration time.Duration) error {
	r := Rule{
		IP:        ip,
		Reason:    reason,
		CreatedAt: time.Now(),
	}
	if duration > 0 {
		r.ExpiresAt = time.Now().Add(duration)
	}

	if strings.Contains(ip, "/") {
		r.Type = BlockTypeCIDR
	} else {
		r.Type = BlockTypeSingle
	}

	// Persist first
	if err := f.store.Add(r); err != nil {
		return err
	}

	// Update memory
	f.mu.Lock()
	f.addRuleInMemory(r)
	f.mu.Unlock()

	return nil
}

func (f *IPSet) addRuleInMemory(r Rule) {
	// CIDR
	if r.Type == BlockTypeCIDR {
		_, network, err := net.ParseCIDR(r.IP)
		if err == nil {
			_ = f.ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		return
	}

	// Single IP
	addr, err := netip.ParseAddr(r.IP)
	if err == nil {
		addr = addr.Unmap()
		if addr.Is4() {
			f.v4[addr] = struct{}{}
		} else {
			f.v6[addr] = struct{}{}
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

		// CIDR
		if strings.Contains(line, "/") {
			_, network, err := net.ParseCIDR(line)
			if err == nil {
				f.ranger.Insert(cidranger.NewBasicRangerEntry(*network))
				count++
			}
			continue
		}

		// Single IP
		addr, err := netip.ParseAddr(line)
		if err == nil {
			addr = addr.Unmap()
			if addr.Is4() {
				f.v4[addr] = struct{}{}
			} else {
				f.v6[addr] = struct{}{}
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

		// 1. Fast Map Lookup (Single IPs)
		addr, err := netip.ParseAddr(ipStr)
		if err == nil {
			addr = addr.Unmap()
			f.mu.RLock()
			var blocked bool
			if addr.Is4() {
				_, blocked = f.v4[addr]
			} else {
				_, blocked = f.v6[addr]
			}
			f.mu.RUnlock()

			if blocked {
				atomic.AddUint64(&metricsLocalBlocks, 1)
				// f.logger.Debugf("firewall blocked ip=%s reason=local_ip", ipStr)
				http.Error(w, "Access Denied", http.StatusForbidden)
				return
			}
		}

		// 2. Ranger Lookup (CIDRs)
		// cidranger requires net.IP
		netIP := net.ParseIP(ipStr)
		if netIP != nil {
			// Contains is thread-safe in cidranger
			contains, err := f.ranger.Contains(netIP)
			if err == nil && contains {
				atomic.AddUint64(&metricsLocalBlocks, 1)
				// f.logger.Debugf("firewall blocked ip=%s reason=local_cidr", ipStr)
				http.Error(w, "Access Denied", http.StatusForbidden)
				return
			}
		}

		// 3. Remote Check (with cache & singleflight)
		if f.remote != "" {
			if f.cachedRemoteCheck(r.Context(), ipStr) {
				atomic.AddUint64(&metricsRemoteBlocks, 1)
				// f.logger.Debugf("firewall blocked ip=%s reason=remote", ipStr)
				http.Error(w, "Access Denied (R)", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (f *IPSet) cachedRemoteCheck(ctx context.Context, ip string) bool {
	// 1. Check Cache
	if hit, ok := f.cache.get(ip); ok {
		return hit
	}

	// 2. Singleflight
	val, err, _ := f.flight.Do(ip, func() (interface{}, error) {
		blocked := f.checkRemote(ip)
		f.cache.set(ip, blocked)
		return blocked, nil
	})

	if err != nil {
		return false
	}
	return val.(bool)
}

func (f *IPSet) checkRemote(ip string) bool {
	req, err := http.NewRequest("GET", f.remote+"?ip="+ip, nil)
	if err != nil {
		return false
	}

	resp, err := f.client.Do(req)
	if err != nil {
		atomic.AddUint64(&metricsRemoteErrors, 1)
		return false // Fail Open
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusForbidden
}
