// internal/cluster/config.go
package cluster

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/olekukonko/ll"
)

const (
	configFilePerm         = 0644
	configTempSuffix       = ".tmp"
	configHCLExtension     = ".hcl"
	MaxReliablePayloadSize = 5 * 1024 * 1024
)

type ConfigManager struct {
	localDir  string
	logger    *ll.Logger
	checksums map[string]string
	mu        sync.RWMutex
}

// NewConfigManager initializes the configuration synchronizer.
// It populates the initial checksum cache from existing files on disk.
func NewConfigManager(localDir string, logger *ll.Logger) *ConfigManager {
	cm := &ConfigManager{
		localDir:  localDir,
		logger:    logger.Namespace("config_sync"),
		checksums: make(map[string]string),
	}
	cm.LoadExistingChecksums()
	return cm
}

// LoadExistingChecksums scans the local directory for configuration files.
// It caches the checksums to prevent unnecessary synchronization loops on startup.
func (c *ConfigManager) LoadExistingChecksums() {
	entries, err := os.ReadDir(c.localDir)
	if err != nil {
		c.logger.Fields("err", err).Debug("config_sync: failed to read local dir for checksums")
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), configHCLExtension) {
			continue
		}
		path := filepath.Join(c.localDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		domain := strings.TrimSuffix(e.Name(), configHCLExtension)
		c.checksums[domain] = c.calculateChecksum(data)
	}
	c.logger.Fields("count", len(c.checksums)).Debug("config_sync: loaded existing checksums")
}

// Apply writes or deletes a configuration file based on a cluster payload.
// It validates the incoming HCL before committing to disk to prevent cluster-wide corruption.
func (c *ConfigManager) Apply(payload ConfigPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if payload.Deleted {
		configPath := filepath.Join(c.localDir, payload.Domain+configHCLExtension)
		_ = os.Remove(configPath)
		delete(c.checksums, payload.Domain)
		c.logger.Fields("domain", payload.Domain).Info("cluster config deleted")
		return
	}

	existingChecksum := c.checksums[payload.Domain]
	if existingChecksum == payload.Checksum {
		return
	}

	configPath := filepath.Join(c.localDir, payload.Domain+configHCLExtension)

	rawHCL, err := c.decompress(payload.RawHCL)
	if err != nil {
		c.logger.Fields("domain", payload.Domain, "err", err).Error("failed to decompress config")
		return
	}

	if err := c.validateHCL(configPath, rawHCL); err != nil {
		c.logger.Fields("domain", payload.Domain, "sender", payload.NodeID, "err", err).Error("invalid cluster config received, discarded")
		return
	}

	if err := c.writeAtomic(configPath, rawHCL); err != nil {
		c.logger.Fields("domain", payload.Domain, "err", err).Error("failed to write cluster config")
		return
	}

	c.checksums[payload.Domain] = payload.Checksum
	c.logger.Fields("domain", payload.Domain).Info("cluster config applied")
}

// PreparePayload creates a compressed configuration payload for cluster distribution.
// It updates the local checksum and returns nil if the configuration is unchanged.
func (c *ConfigManager) PreparePayload(domain string, rawHCL []byte, deleted bool, nodeID string) (*ConfigPayload, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	checksum := c.calculateChecksum(rawHCL)

	if deleted {
		if _, exists := c.checksums[domain]; !exists {
			return nil, nil
		}
		delete(c.checksums, domain)
	} else {
		if c.checksums[domain] == checksum {
			return nil, nil
		}
		c.checksums[domain] = checksum
	}

	var compressed []byte
	var err error
	if !deleted {
		compressed, err = c.compress(rawHCL)
		if err != nil {
			return nil, err
		}
		if len(compressed) > MaxReliablePayloadSize {
			c.logger.Fields("domain", domain, "size", len(compressed), "limit", MaxReliablePayloadSize).Warn("config too large for tcp sync, skipped")
			return nil, nil
		}
	}

	payload := &ConfigPayload{
		Domain:   domain,
		RawHCL:   compressed,
		Checksum: checksum,
		NodeID:   nodeID,
		Deleted:  deleted,
	}

	return payload, nil
}

// ShouldBroadcast determines if the file content has changed locally.
// It prevents fsnotify echo chambers by comparing against the known cache.
func (c *ConfigManager) ShouldBroadcast(domain string, content []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	checksum := c.calculateChecksum(content)
	existing, exists := c.checksums[domain]
	if !exists {
		c.checksums[domain] = checksum
		return false
	}
	if existing == checksum {
		return false
	}
	c.checksums[domain] = checksum
	return true
}

// ShouldBroadcastDeletion determines if a deleted file was previously tracked.
// It returns true to authorize a cluster-wide deletion broadcast without modifying state.
func (c *ConfigManager) ShouldBroadcastDeletion(domain string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.checksums[domain]
	return exists
}

// UpdateChecksum manually forces a checksum update for a domain.
// Used when local changes need to bypass immediate broadcasting.
func (c *ConfigManager) UpdateChecksum(domain string, content []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checksums[domain] = c.calculateChecksum(content)
}

// validateHCL performs a dry-run parsing to ensure syntax correctness.
// Drops bad gossip payloads before they overwrite functional configurations.
func (c *ConfigManager) validateHCL(targetPath string, rawHCL []byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	tempPath := filepath.Join(dir, ".validate.tmp.hcl")
	if err := os.WriteFile(tempPath, rawHCL, configFilePerm); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	defer os.Remove(tempPath)

	if err := parser.ValidateHCL(rawHCL); err != nil {
		return fmt.Errorf("syntax validation: %w", err)
	}

	_, err := parser.ParseHostConfig(tempPath)
	if err != nil {
		return fmt.Errorf("parse host config: %w", err)
	}
	return nil
}

// writeAtomic writes configuration data safely to disk.
// Uses temp files and renaming to avoid partial writes during crashes.
func (c *ConfigManager) writeAtomic(targetPath string, data []byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tempPath := targetPath + configTempSuffix
	if err := os.WriteFile(tempPath, data, configFilePerm); err != nil {
		return err
	}
	return os.Rename(tempPath, targetPath)
}

// calculateChecksum returns the SHA256 string for the provided content.
// Used to compare configurations and detect state drifts.
func (c *ConfigManager) calculateChecksum(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// compress shrinks configuration data for efficient network transit.
// Maximizes payload capacity while remaining compatible with reliable transport.
func (c *ConfigManager) compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompress inflates configuration data received from the cluster.
// Must be paired with the local compressor implementation.
func (c *ConfigManager) decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
