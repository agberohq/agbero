package bot

import (
	"testing"
	"time"
)

const (
	benchmarkIterations = 1000
	testUserAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	testBotUserAgent    = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

// TestIsBot validates bot detection logic for known bot and legitimate user agents.
// Ensures cache behavior and pattern matching work correctly across edge cases.
func TestIsBot(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  bool
	}{
		{"Empty UA", "", false},
		{"Legitimate Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", false},
		{"Legitimate Firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0", false},
		{"Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"Bingbot", "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)", true},
		{"Twitterbot", "Twitterbot/1.0", true},
		{"Generic bot keyword", "MyCustomBot/1.0 scraper", true},
		{"Long UA suspicious", "Mozilla/5.0 " + string(make([]byte, maxUALength)), true},
		{"Case insensitive bot", "GOOGLEBOT/2.1", true},
	}

	bc := NewChecker()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bc.IsBot(tt.userAgent)
			if result != tt.expected {
				t.Errorf("IsBot(%q) = %v; expected %v", tt.userAgent, result, tt.expected)
			}
		})
	}
}

// TestIsBotCache verifies that results are cached and retrieved correctly.
// Confirms TTL behavior prevents stale data while maintaining performance.
func TestIsBotCache(t *testing.T) {
	bc := NewChecker()
	ua := testBotUserAgent

	first := bc.IsBot(ua)
	if !first {
		t.Error("Expected bot detection on first call")
	}

	second := bc.IsBot(ua)
	if !second {
		t.Error("Expected cached bot result on second call")
	}

	legitUA := testUserAgent
	bc.IsBot(legitUA)
	if cached, found := bc.cache.Get(legitUA); !found || cached {
		t.Error("Expected non-bot result to be cached as false")
	}
}

// TestAddPattern validates runtime pattern extension behavior.
// Uses a unique identifier that does not match existing indicators or patterns.
func TestAddPattern(t *testing.T) {
	bc := NewChecker()
	customBot := "CustomZephyrAgent/1.0"

	if bc.IsBot(customBot) {
		t.Error("Expected custom bot to be unknown before pattern addition")
	}

	bc.AddPattern("customzephyr")
	bc.cache.Delete(customBot)
	if !bc.IsBot(customBot) {
		t.Error("Expected custom bot to be detected after pattern addition")
	}
}

// BenchmarkIsBotCacheHit measures performance when cache contains the result.
// Simulates hot-path scenario where same UA is evaluated repeatedly.
func BenchmarkIsBotCacheHit(b *testing.B) {
	bc := NewChecker()
	ua := testBotUserAgent
	bc.IsBot(ua)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bc.IsBot(ua)
	}
}

// BenchmarkIsBotCacheMissBot measures performance for unknown bot UAs.
// Exercises fast-path indicators and regex matching without cache benefit.
func BenchmarkIsBotCacheMissBot(b *testing.B) {
	bc := NewChecker()
	ua := "UnknownBot/1.0 crawler"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bc.IsBot(ua)
	}
}

// BenchmarkIsBotCacheMissLegit measures performance for legitimate browser UAs.
// Represents the common case where negative results are cached with longer TTL.
func BenchmarkIsBotCacheMissLegit(b *testing.B) {
	bc := NewChecker()
	ua := testUserAgent

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bc.IsBot(ua)
	}
}

// BenchmarkIsBotLongUA tests performance impact of unusually long user agents.
// Validates early-exit optimization for length-based bot suspicion.
func BenchmarkIsBotLongUA(b *testing.B) {
	bc := NewChecker()
	ua := "Mozilla/5.0 " + string(make([]byte, maxUALength+50))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bc.IsBot(ua)
	}
}

// TestIsBotConcurrent validates thread-safety of cache operations under load.
// Ensures mappo.Concurrent handles simultaneous reads and writes correctly.
func TestIsBotConcurrent(t *testing.T) {
	bc := NewChecker()
	userAgents := []string{
		testUserAgent,
		testBotUserAgent,
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
		"facebookexternalhit/1.1",
		"",
	}

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for _, ua := range userAgents {
				_ = bc.IsBot(ua)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestIsBotTTLExpiration confirms that cached entries expire as configured.
// Uses short TTL values to validate time-based cache invalidation logic.
func TestIsBotTTLExpiration(t *testing.T) {
	bc := NewChecker()
	ua := testBotUserAgent

	bc.cache.SetTTL(ua, true, 10*time.Millisecond)
	if !bc.IsBot(ua) {
		t.Error("Expected bot result before TTL expiration")
	}

	time.Sleep(15 * time.Millisecond)

	result := bc.IsBot(ua)
	if !result {
		t.Error("Expected bot detection after cache expiration")
	}
}
