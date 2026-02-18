package parser

import (
	"fmt"
	"os"
	"path/filepath"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/alecthomas/hcl"
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
		return fmt.Errorf("resolve config path: %w", err)
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	// alecthomas/hcl uses simple Unmarshal
	if err := hcl.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode error in %s: %w", filepath.Base(p.path), err)
	}

	return nil
}

// LoadGlobal loads global configuration
func LoadGlobal(path string) (*alaye.Global, error) {
	var global alaye.Global
	parser := NewParser(path)
	if err := parser.Unmarshal(&global); err != nil {
		return nil, err
	}

	if global.Version != woos.ConfigFormatVersion {
		if global.Version < woos.ConfigFormatVersion {
			return nil, fmt.Errorf(
				"config version mismatch: file v%d, expected v%d. Please update %s to version = %d and restructure 'rate_limits'",
				global.Version, woos.ConfigFormatVersion, filepath.Base(path), woos.ConfigFormatVersion,
			)
		}
		return nil, fmt.Errorf(
			"config version mismatch: file v%d, binary expects v%d. Please update your configuration",
			global.Version, woos.ConfigFormatVersion,
		)
	}
	return &global, nil
}

// ParseHostConfig loads host configuration
func ParseHostConfig(path string) (*alaye.Host, error) {
	var host alaye.Host
	parser := NewParser(path)
	if err := parser.Unmarshal(&host); err != nil {
		return nil, err
	}
	return &host, nil
}
