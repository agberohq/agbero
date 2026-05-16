package dnsblock

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/ll"
)

// Blocklist holds a set of blocked domains. It supports exact-match lookups
// and suffix matching (*.example.com blocks sub.example.com).
//
// All methods are safe for concurrent use. Reads via Match use RLock;
// writes via Load* use a full Lock.
//
// Domain entries are normalised to lowercase. Leading/trailing whitespace
// and blank lines are stripped. Lines beginning with '#' are comments.
// Hosts-file format entries ("0.0.0.0 ads.example.com") are parsed by
// stripping the leading IP address field.
type Blocklist struct {
	mu       sync.RWMutex
	exact    map[string]struct{} // exact domain matches
	suffixes []string            // suffix matches: entry "ads.example.com" blocks *.ads.example.com

	urlSources []string // remote URLs to refresh
	logger     *ll.Logger
}

// New returns an empty, ready-to-use Blocklist.
func New(logger *ll.Logger) *Blocklist {
	return &Blocklist{
		exact:  make(map[string]struct{}),
		logger: logger,
	}
}

// Len returns the total number of exact-match entries. Suffix entries are
// counted separately — this is informational only and not performance-critical.
func (b *Blocklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.exact)
}

// SuffixLen returns the number of suffix-match patterns.
func (b *Blocklist) SuffixLen() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.suffixes)
}

// Add inserts a single domain entry. Thread-safe.
func (b *Blocklist) Add(domain string) {
	domain = normaliseDomain(domain)
	if domain == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addLocked(domain)
}

// AddSlice adds multiple inline domain entries.
func (b *Blocklist) AddSlice(domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, d := range domains {
		d = normaliseDomain(d)
		if d != "" {
			b.addLocked(d)
		}
	}
}

// addLocked inserts a domain without acquiring the lock. Caller must hold b.mu.
func (b *Blocklist) addLocked(domain string) {
	if strings.HasPrefix(domain, "*.") {
		// Wildcard entry: strip the "*." prefix — suffix matching is implied.
		suffix := domain[2:]
		if suffix != "" && !containsSuffix(b.suffixes, suffix) {
			b.suffixes = append(b.suffixes, suffix)
		}
		return
	}
	b.exact[domain] = struct{}{}
}

// Load reads domain entries from r and adds them to the blocklist.
// Existing entries are preserved — Load is additive. Call Clear() first
// if a full replacement is needed.
//
// Accepted formats:
//   - Bare domain:           "ads.example.com"
//   - Hosts-file entry:      "0.0.0.0 ads.example.com"
//   - Wildcard:              "*.ads.example.com"
//   - Comment (ignored):     "# this is a comment"
//   - Blank line (ignored)
func (b *Blocklist) Load(r io.Reader) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := parseLine(line)
		if domain != "" {
			b.addLocked(domain)
		}
	}
	return scanner.Err()
}

// LoadFile reads domain entries from a local file path.
func (b *Blocklist) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("dnsblock: open %q: %w", path, err)
	}
	defer f.Close()
	if err := b.Load(f); err != nil {
		return fmt.Errorf("dnsblock: read %q: %w", path, err)
	}
	return nil
}

// LoadURL fetches and loads a remote blocklist.
// The URL is also stored so Refresh() can reload it on a schedule.
func (b *Blocklist) LoadURL(ctx context.Context, rawURL string) error {
	if err := b.fetchURL(ctx, rawURL); err != nil {
		return err
	}
	b.mu.Lock()
	if !containsSuffix(b.urlSources, rawURL) {
		b.urlSources = append(b.urlSources, rawURL)
	}
	b.mu.Unlock()
	return nil
}

// fetchURL downloads and loads a single URL without storing it as a source.
func (b *Blocklist) fetchURL(ctx context.Context, rawURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("dnsblock: build request for %q: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", "agbero-dnsblock/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("dnsblock: fetch %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dnsblock: fetch %q: HTTP %d", rawURL, resp.StatusCode)
	}

	if err := b.Load(resp.Body); err != nil {
		return fmt.Errorf("dnsblock: load %q: %w", rawURL, err)
	}
	return nil
}

// Refresh reloads all URL sources in the background at the given interval.
// It runs until ctx is cancelled. Typically called once after LoadURL.
func (b *Blocklist) Refresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.mu.RLock()
				sources := make([]string, len(b.urlSources))
				copy(sources, b.urlSources)
				b.mu.RUnlock()

				for _, url := range sources {
					if err := b.fetchURL(ctx, url); err != nil {
						if b.logger != nil {
							b.logger.Fields("url", url, "err", err).Warn("dnsblock: refresh failed")
						}
					} else {
						if b.logger != nil {
							b.logger.Fields("url", url).Debug("dnsblock: blocklist refreshed")
						}
					}
				}
			}
		}
	}()
}

// Match returns true if domain is blocked — either by exact match or by a
// suffix match walking the parent labels of domain.
//
// Example: if "ads.example.com" is a suffix entry, both
// "sub.ads.example.com" and "deep.sub.ads.example.com" are blocked,
// but "example.com" itself is not.
func (b *Blocklist) Match(domain string) bool {
	domain = normaliseDomain(domain)
	if domain == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Exact match
	if _, ok := b.exact[domain]; ok {
		return true
	}

	// Suffix match: walk parent labels
	for _, suffix := range b.suffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}

	return false
}

// Clear removes all entries and URL sources. Useful for reload-in-place.
func (b *Blocklist) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exact = make(map[string]struct{})
	b.suffixes = b.suffixes[:0]
	b.urlSources = b.urlSources[:0]
}

// Parsing helpers

// parseLine extracts a single domain from a blocklist line.
// Returns "" if the line should be skipped.
func parseLine(line string) string {
	// Strip inline comments
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return ""
	}

	// Hosts-file format: "0.0.0.0 ads.example.com" or "127.0.0.1 ads.example.com"
	// Split on whitespace — if there are two or more fields, the domain is the second.
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		// First field should be an IP address; second is the domain.
		// Skip localhost entries that are self-referential.
		candidate := fields[1]
		if candidate == "localhost" || candidate == "localhost.localdomain" {
			return ""
		}
		return normaliseDomain(candidate)
	}

	// Bare domain or wildcard
	return normaliseDomain(fields[0])
}

// normaliseDomain lowercases and strips leading/trailing dots and spaces.
func normaliseDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.Trim(d, ".")
	return d
}

// containsSuffix checks whether s is already in the slice.
func containsSuffix(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
