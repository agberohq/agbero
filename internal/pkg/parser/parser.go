package parser

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
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

	if err := hcl.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode error in %s: %w", filepath.Base(p.path), err)
	}

	return nil
}

// MarshalBytes encodes the value to HCL and returns the raw bytes.
// No file I/O — caller decides what to do with the bytes.
func MarshalBytes(input any) ([]byte, error) {
	return hcl.Marshal(input)
}

// Marshal writes the encoded HCL directly to the provided io.Writer.
// No atomic writes, no temp files — pure encoding + streaming.
func Marshal(writer io.Writer, input any) error {
	data, err := hcl.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode HCL: %w", err)
	}
	_, err = writer.Write(data)
	return err
}

// MarshalFile encodes and writes atomically to a file path using temp+rename.
// Use this when you need crash-safe persistence.
func MarshalFile(path string, input any) error {
	if path == "" {
		return woos.ErrEmptyConfigPath
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}

	data, err := hcl.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode HCL: %w", err)
	}

	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, woos.DirPerm); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	tmpPath := abs + ".tmp"
	if err := os.WriteFile(tmpPath, data, woos.FilePerm); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp config: %w", err)
	}

	if err := os.Rename(tmpPath, abs); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp config: %w", err)
	}

	return nil
}

// Parser.MarshalFile is a convenience method that uses the parser's path.
func (p *Parser) MarshalFile(input any) error {
	return MarshalFile(p.path, input)
}

// LoadGlobal loads global configuration
func LoadGlobal(path string) (*alaye.Global, error) {
	if path == "" {
		return nil, fmt.Errorf("config path cannot be empty")
	}

	var global alaye.Global
	parser := NewParser(path)
	if err := parser.Unmarshal(&global); err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
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
