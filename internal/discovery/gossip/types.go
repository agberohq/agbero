package gossip

import (
	"strings"

	"github.com/olekukonko/ll"
)

type Meta struct {
	Token string `json:"token,omitempty"`
	Port  int    `json:"port"`

	Host        string `json:"host"`
	Path        string `json:"path"`
	StripPrefix bool   `json:"strip,omitempty"`

	AuthPath string `json:"auth_path,omitempty"`

	Weight     int    `json:"weight,omitempty"`
	HealthPath string `json:"health_path,omitempty"`
}

type logAdapter struct {
	logger *ll.Logger
}

func (l *logAdapter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))

	if strings.Contains(msg, "Stream connection") ||
		strings.Contains(msg, "Initiating push/pull sync") {
		return len(p), nil
	}

	switch {
	case strings.Contains(msg, "[DEBUG]"):
		l.logger.Debug(msg)
	case strings.Contains(msg, "[WARN]"):
		l.logger.Warn(msg)
	case strings.Contains(msg, "[ERR]"):
		l.logger.Error(msg)
	default:
		l.logger.Info(msg)
	}
	return len(p), nil
}
