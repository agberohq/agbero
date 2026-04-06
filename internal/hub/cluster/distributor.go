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

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/olekukonko/ll"
)

const (
	configFilePerm            = 0644
	configTempSuffix          = ".tmp"
	configHCLExtension        = ".hcl"
	MaxReliablePayloadSize    = 5 * 1024 * 1024
	maxDecompressedConfigSize = 10 * 1024 * 1024
)

type Distributor struct {
	localDir  expect.Folder
	logger    *ll.Logger
	checksums map[string]string
	mu        sync.RWMutex
}

// NewDistributor initializes the configuration synchronizer.
// It populates the initial checksum cache from existing files on disk.
func NewDistributor(logger *ll.Logger, localDir expect.Folder) *Distributor {
	cm := &Distributor{
		localDir:  localDir,
		logger:    logger.Namespace("config_sync"),
		checksums: make(map[string]string),
	}
	cm.LoadExistingChecksums()
	return cm
}

// LoadExistingChecksums scans the local directory for configuration files.
// It caches the checksums to prevent unnecessary synchronization loops on startup.
func (c *Distributor) LoadExistingChecksums() {
	files, err := c.localDir.ReadFiles()
	if err != nil {
		c.logger.Fields("err", err).Debug("config_sync: failed to read local dir")
		return
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), configHCLExtension) {
			continue
		}

		data, err := os.ReadFile(c.localDir.FilePath(file.Name()))
		if err != nil {
			continue
		}

		domain := strings.TrimSuffix(file.Name(), configHCLExtension)
		c.checksums[domain] = c.calculateChecksum(data)
	}

	c.logger.Fields("count", len(c.checksums)).Debug("config_sync: loaded existing checksums")
}

// Apply writes or deletes a configuration file based on a cluster payload.
// Domain values are validated to prevent path traversal before any file operation.
func (c *Distributor) Apply(payload ConfigPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := validateDomain(payload.Domain, c.localDir); err != nil {
		c.logger.Fields("domain", payload.Domain, "sender", payload.NodeID, "err", err).Error("cluster config rejected: invalid domain")
		return
	}

	if payload.Deleted {
		configPath := c.localDir.FilePath(payload.Domain + configHCLExtension)
		_ = os.Remove(configPath)
		delete(c.checksums, payload.Domain)
		c.logger.Fields("domain", payload.Domain).Info("cluster config deleted")
		return
	}

	existingChecksum := c.checksums[payload.Domain]
	if existingChecksum == payload.Checksum {
		return
	}

	configPath := c.localDir.FilePath(payload.Domain + configHCLExtension)

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
// It mutates the local checksum cache ensuring subsequent fsnotify events are ignored.
func (c *Distributor) PreparePayload(domain string, rawHCL []byte, deleted bool, nodeID string) (*ConfigPayload, error) {
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
// It is strictly a read-only check authorizing fsnotify to trigger PreparePayload.
func (c *Distributor) ShouldBroadcast(domain string, content []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	checksum := c.calculateChecksum(content)
	existing, exists := c.checksums[domain]
	if !exists {
		return true
	}
	return existing != checksum
}

// ShouldBroadcastDeletion determines if a deleted file was previously tracked.
// It returns true to authorize a cluster-wide deletion broadcast without modifying state.
func (c *Distributor) ShouldBroadcastDeletion(domain string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.checksums[domain]
	return exists
}

// UpdateChecksum manually forces a checksum update for a domain.
// Used when local changes need to bypass immediate broadcasting.
func (c *Distributor) UpdateChecksum(domain string, content []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checksums[domain] = c.calculateChecksum(content)
}

// validateHCL performs a dry-run parsing to ensure syntax correctness.
// Drops bad gossip payloads before they overwrite functional configurations.
func (c *Distributor) validateHCL(targetPath string, rawHCL []byte) error {
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
func (c *Distributor) writeAtomic(targetPath string, data []byte) error {
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
func (c *Distributor) calculateChecksum(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// compress shrinks configuration data for efficient network transit.
// Maximizes payload capacity while remaining compatible with reliable transport.
func (c *Distributor) compress(data []byte) ([]byte, error) {
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
// Decompressed output is capped at maxDecompressedConfigSize to prevent memory exhaustion.
func (c *Distributor) decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	result, err := io.ReadAll(io.LimitReader(reader, maxDecompressedConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(result) > maxDecompressedConfigSize {
		return nil, fmt.Errorf("decompressed config exceeds maximum allowed size of %d bytes", maxDecompressedConfigSize)
	}
	return result, nil
}

// validateDomain rejects domain values that could escape the localDir via path traversal.
// A domain must contain no path separators, no ".." sequences, and the resolved path
// must remain within localDir.
func validateDomain(domain string, localDir expect.Folder) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if strings.ContainsAny(domain, "/\\") {
		return fmt.Errorf("domain contains illegal path separator characters")
	}
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain contains illegal path traversal sequence")
	}

	resolved := localDir.FilePath(domain + configHCLExtension)
	rel, err := filepath.Rel(localDir.Path(), resolved)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("domain resolves outside the configured hosts directory")
	}
	return nil
}
