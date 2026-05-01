package bot

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/olekukonko/mappo"
	"github.com/ua-parser/uap-go/uaparser"
)

const (
	defaultMaxSize  = 10000
	targetHitRate   = 98.0 // percentage
	growthFactor    = 1.5
	shrinkFactor    = 0.8
	metricsInterval = 5 * time.Minute
	minSampleSize   = 10000
	maxMaxSize      = 500000
	minMaxSize      = 1000
	cacheTTLBot     = 1 * time.Hour
	cacheTTLNotBot  = 24 * time.Hour
)

type Checker struct {
	cache  *mappo.LRU[string, bool]
	parser *uaparser.Parser

	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64

	currentMaxSize int
	lastMetricsAt  time.Time
}

func NewChecker(initialMaxSize int) (*Checker, error) {
	parser, err := uaparser.New()
	if err != nil {
		return nil, err
	}

	if initialMaxSize <= 0 {
		initialMaxSize = defaultMaxSize
	}

	return &Checker{
		cache: mappo.NewLRUWithConfig[string, bool](mappo.LRUConfig[string, bool]{
			MaxSize: initialMaxSize,
		}),
		parser:         parser,
		currentMaxSize: initialMaxSize,
		lastMetricsAt:  time.Now(),
	}, nil
}

func (b *Checker) IsBot(ua string) bool {
	if ua == "" {
		return false
	}

	val := b.cache.GetOrCompute(ua, func() (bool, time.Duration) {
		b.misses.Add(1)
		client := b.parser.Parse(ua)
		family := strings.ToLower(client.UserAgent.Family)
		uaLower := strings.ToLower(ua)

		isBot := family == "googlebot" ||
			family == "bingbot" ||
			family == "baiduspider" ||
			family == "yandexbot" ||
			family == "duckduckbot" ||
			family == "twitterbot" ||
			family == "facebookexternalhit" ||
			family == "linkedinbot" ||
			family == "whatsapp" ||
			family == "telegrambot" ||
			family == "slackbot" ||
			family == "discordbot" ||
			strings.Contains(family, "bot") ||
			strings.Contains(family, "crawler") ||
			strings.Contains(family, "spider") ||
			strings.Contains(uaLower, "googlebot") ||
			strings.Contains(uaLower, "bingbot")

		if isBot {
			return true, cacheTTLBot
		}
		return false, cacheTTLNotBot
	})

	b.hits.Add(1)
	b.maybeAdapt()
	return val
}

func (b *Checker) maybeAdapt() {
	hits := b.hits.Load()
	misses := b.misses.Load()
	total := hits + misses

	if total < minSampleSize {
		return
	}

	hitRate := float64(hits) / float64(total) * 100

	if hitRate < targetHitRate {
		newSize := int(float64(b.currentMaxSize) * growthFactor)
		if newSize > maxMaxSize {
			newSize = maxMaxSize
		}
		if newSize > b.currentMaxSize {
			b.cache.Resize(newSize)
			b.currentMaxSize = newSize
		}
	} else if hitRate >= 99.9 && b.currentMaxSize > minMaxSize {
		// Shrink only when we're significantly over-provisioned
		newSize := int(float64(b.currentMaxSize) * shrinkFactor)
		if newSize < minMaxSize {
			newSize = minMaxSize
		}
		if newSize < b.currentMaxSize {
			b.cache.Resize(newSize)
			b.currentMaxSize = newSize
		}
	}

	// Reset counters to get a fresh window
	b.hits.Store(0)
	b.misses.Store(0)
}

func (b *Checker) Stats() (hitRate float64, size int, maxSize int) {
	hits := b.hits.Load()
	misses := b.misses.Load()
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	size = b.cache.Len()
	maxSize = b.currentMaxSize
	return
}

func (b *Checker) Resize(newSize int) {
	if newSize < minMaxSize {
		newSize = minMaxSize
	}
	if newSize > maxMaxSize {
		newSize = maxMaxSize
	}
	b.cache.Resize(newSize)
	b.currentMaxSize = newSize
}
