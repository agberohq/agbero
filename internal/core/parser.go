package core

import (
	"fmt"
	"os"
	"path/filepath"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/alecthomas/hcl"
	"github.com/olekukonko/errors"
)

type Parser struct {
	path string
}

func NewParser(path string) *Parser {
	return &Parser{path: path}
}

func (p *Parser) Unmarshal(output any) error {
	if p.path == "" {
		return woos.ErrEmptyConfigPath
	}

	abs, err := filepath.Abs(p.path)
	if err != nil {
		return errors.Newf("resolve config path: %w", err)
	}

	b, err := os.ReadFile(abs)
	if err != nil {
		return errors.Newf("read config file %q: %w", abs, err)
	}

	if err := hcl.Unmarshal(b, output); err != nil {
		return errors.Newf("parse config file %q: %w", abs, err)
	}

	return nil
}

// LoadGlobal is a convenience wrapper
func LoadGlobal(path string) (*alaye.Global, error) {
	var global alaye.Global
	parser := NewParser(path)
	if err := parser.Unmarshal(&global); err != nil {
		return nil, err
	}

	// Version Check
	if global.Version != woos.ConfigFormatVersion {
		// Specific help for the v1 -> v2 transition (Rate Limit refactor)
		if global.Version < woos.ConfigFormatVersion {
			return nil, fmt.Errorf(
				"\nConfig version mismatch (found v%d, expected v%d).\n"+
					"Please update your %s file to version = %d and restructure 'rate_limits'.",
				global.Version, woos.ConfigFormatVersion, filepath.Base(path), woos.ConfigFormatVersion,
			)
		}

		// Generic version mismatch error
		return nil, fmt.Errorf(
			"config format version mismatch: file is v%d, binary expects v%d. Please update your configuration",
			global.Version, woos.ConfigFormatVersion,
		)
	}

	return &global, nil
}

// ParseHostConfig parses a single host config file
func ParseHostConfig(path string) (*alaye.Host, error) {
	var host alaye.Host
	parser := NewParser(path)
	if err := parser.Unmarshal(&host); err != nil {
		return nil, err
	}
	return &host, nil
}

// EnsureHostsDir creates the hosts directory if it doesn't exist
func EnsureHostsDir(hostsDir string) error {
	return os.MkdirAll(hostsDir, woos.DefaultFilePermDir)
}

// ConfigPath returns the absolute path to a config file
func ConfigPath(baseDir, filename string) string {
	return filepath.Join(baseDir, filename)
}
