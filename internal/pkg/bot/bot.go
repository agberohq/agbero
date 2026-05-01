package bot

import (
	"strings"
	"time"

	"github.com/olekukonko/mappo"
	"github.com/ua-parser/uap-go/uaparser"
)

type Checker struct {
	cache  *mappo.LRU[string, bool]
	parser *uaparser.Parser
}

func NewChecker(maxCacheSize int) (*Checker, error) {
	parser, err := uaparser.New()
	if err != nil {
		return nil, err
	}

	return &Checker{
		cache: mappo.NewLRUWithConfig[string, bool](mappo.LRUConfig[string, bool]{
			MaxSize: maxCacheSize,
		}),
		parser: parser,
	}, nil
}

func (b *Checker) IsBot(ua string) bool {
	if ua == "" {
		return false
	}

	val := b.cache.GetOrCompute(ua, func() (bool, time.Duration) {
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
			return true, 1 * time.Hour
		}
		return false, 24 * time.Hour
	})

	return val
}
