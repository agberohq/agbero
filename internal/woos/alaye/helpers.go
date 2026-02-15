package alaye

import "strings"

// ValidateStrategy returns true if the strategy is valid
func ValidateStrategy(s string) bool {
	return validStrategies[strings.ToLower(s)]
}
