package bot

import (
	"testing"
	"time"
)

const (
	testUserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	testBotUserAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
)

func newTestChecker(t *testing.T) *Checker {
	t.Helper()
	c, err := NewChecker(1000)
	if err != nil {
		t.Fatalf("failed to create checker: %v", err)
	}
	return c
}

func TestIsBot(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  bool
	}{
		{"Empty UA", "", false},
		{"Legitimate Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", false},
		{"Legitimate Firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0", false},
		{"Googlebot", testBotUserAgent, true},
		{"Bingbot", "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)", true},
		{"Twitterbot", "Twitterbot/1.0", true},
		{"Generic bot keyword", "MyCustomBot/1.0", true},
		{"Case insensitive bot", "GOOGLEBOT/2.1", true},
	}

	bc := newTestChecker(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bc.IsBot(tt.userAgent)
			if result != tt.expected {
				t.Errorf("IsBot(%q) = %v; expected %v", tt.userAgent, result, tt.expected)
			}
		})
	}
}

func TestIsBotCache(t *testing.T) {
	bc := newTestChecker(t)
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

func TestIsBotConcurrent(t *testing.T) {
	bc := newTestChecker(t)
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

func TestIsBotTTLExpiration(t *testing.T) {
	bc := newTestChecker(t)
	ua := testBotUserAgent

	bc.cache.SetWithTTL(ua, true, 10*time.Millisecond)
	if !bc.IsBot(ua) {
		t.Error("Expected bot result before TTL expiration")
	}

	time.Sleep(15 * time.Millisecond)

	result := bc.IsBot(ua)
	if !result {
		t.Error("Expected bot detection after cache expiration (re-parsed)")
	}
}

func TestMaxCacheSize(t *testing.T) {
	bc := newTestChecker(t)

	for i := 0; i < 1001; i++ {
		ua := "Bot/" + string(rune(i))
		bc.IsBot(ua)
	}

	if bc.cache.Len() > 1000 {
		t.Errorf("cache size %d exceeds max 1000", bc.cache.Len())
	}
}

func BenchmarkIsBotCacheHit(b *testing.B) {
	c, err := NewChecker(1000)
	if err != nil {
		b.Fatal(err)
	}
	ua := testBotUserAgent
	c.IsBot(ua)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.IsBot(ua)
	}
}

func BenchmarkIsBotCacheMissBot(b *testing.B) {
	c, err := NewChecker(1000)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ua := "UnknownBot/" + string(rune(i%10000)) + ".0"
		c.IsBot(ua)
	}
}

func BenchmarkIsBotCacheMissLegit(b *testing.B) {
	c, err := NewChecker(1000)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ua := "Mozilla/5.0 Chrome/" + string(rune(i%10000))
		c.IsBot(ua)
	}
}
