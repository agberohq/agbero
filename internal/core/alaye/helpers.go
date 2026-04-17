package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
)

// ValidateStrategy returns true if the strategy is valid
func ValidateStrategy(s string) bool {
	return def.ValidStrategies[strings.ToLower(s)]
}
