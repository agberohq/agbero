package bot

import (
	"regexp"
	"strings"
	"time"

	"github.com/olekukonko/mappo"
)

const (
	cacheTTLBot    = 1 * time.Hour
	cacheTTLNotBot = 24 * time.Hour
	maxUALength    = 200
)

type Checker struct {
	cache          *mappo.Concurrent[string, bool]
	combinedRegex  *regexp.Regexp
	fastIndicators []string
}

// NewChecker initializes a BotChecker with pre-compiled patterns and indicators.
// All bot detection patterns are combined into a single regex for optimal performance.
func NewChecker() *Checker {
	patterns := []string{
		`googlebot`, `bingbot`, `slurp`, `duckduckbot`,
		`baiduspider`, `yandexbot`, `facebookexternalhit`,
		`twitterbot`, `linkedinbot`, `whatsapp`,
		`telegrambot`, `slackbot`, `discordbot`,
		`bot`, `crawl`, `spider`, `scrape`, `scan`, `fetcher`,
	}

	indicators := []string{
		"bot", "crawl", "spider", "scrape", "scan", "fetcher",
	}

	return &Checker{
		cache:          mappo.NewConcurrent[string, bool](),
		combinedRegex:  regexp.MustCompile(`(?i)` + strings.Join(patterns, `|`)),
		fastIndicators: indicators,
	}
}

// IsBot determines if a User-Agent string belongs to a bot or crawler.
// Results are cached with TTL to minimize repeated evaluation on hot paths.
func (b *Checker) IsBot(ua string) bool {
	if ua == "" {
		return false
	}

	if isBot, found := b.cache.Get(ua); found {
		return isBot
	}

	if len(ua) > maxUALength {
		b.cache.SetTTL(ua, true, cacheTTLBot)
		return true
	}

	uaLower := strings.ToLower(ua)
	for _, indicator := range b.fastIndicators {
		if strings.Contains(uaLower, indicator) {
			b.cache.SetTTL(ua, true, cacheTTLBot)
			return true
		}
	}

	if b.combinedRegex.MatchString(ua) {
		b.cache.SetTTL(ua, true, cacheTTLBot)
		return true
	}

	b.cache.SetTTL(ua, false, cacheTTLNotBot)
	return false
}

// AddPattern extends the bot detection with a custom regex pattern.
// Note: Runtime pattern updates are not concurrency-safe; prefer initialization at startup.
func (b *Checker) AddPattern(pattern string) {
	base := strings.TrimPrefix(b.combinedRegex.String(), `(?i)`)
	updated := `(?i)` + base + `|` + regexp.QuoteMeta(pattern)
	b.combinedRegex = regexp.MustCompile(updated)
}
