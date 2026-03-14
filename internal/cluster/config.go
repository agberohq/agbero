package cluster

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/olekukonko/ll"
)

const (
	configFilePerm       = 0644
	configTempSuffix     = ".tmp"
	configValidateSuffix = ".validate"
	configHCLExtension   = ".hcl"
	configHCLSuffixLen   = 4
	MaxGossipPayloadSize = 1200
)

type ConfigManager struct {
	localDir  string
	logger    *ll.Logger
	checksums map[string]string
	mu        sync.RWMutex
}

func NewConfigManager(localDir string, logger *ll.Logger) *ConfigManager {
	cm := &ConfigManager{
		localDir:  localDir,
		logger:    logger.Namespace("config_sync"),
		checksums: make(map[string]string),
	}
	cm.LoadExistingChecksums()
	return cm
}

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

func (c *ConfigManager) Apply(payload ConfigPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()

	existingChecksum := c.checksums[payload.Domain]
	if existingChecksum == payload.Checksum {
		return
	}

	configPath := filepath.Join(c.localDir, payload.Domain+configHCLExtension)

	if payload.Deleted {
		_ = os.Remove(configPath)
		delete(c.checksums, payload.Domain)
		c.logger.Fields("domain", payload.Domain).Info("cluster config deleted")
		return
	}

	rawHCL, err := c.decompress(payload.RawHCL)
	if err != nil {
		c.logger.Fields("domain", payload.Domain, "err", err).Error("failed to decompress config")
		return
	}

	if !c.validateHCL(configPath, rawHCL) {
		c.logger.Fields("domain", payload.Domain, "sender", payload.NodeID).Error("invalid cluster config received, discarded")
		return
	}

	if err := c.writeAtomic(configPath, rawHCL); err != nil {
		c.logger.Fields("domain", payload.Domain, "err", err).Error("failed to write cluster config")
		return
	}

	c.checksums[payload.Domain] = payload.Checksum
	c.logger.Fields("domain", payload.Domain).Info("cluster config applied")
}

func (c *ConfigManager) LoadAndBroadcast(domain string, rawHCL []byte, deleted bool, nodeID string, del *delegate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	checksum := c.calculateChecksum(rawHCL)
	if c.checksums[domain] == checksum {
		return nil
	}

	var compressed []byte
	var err error
	if !deleted {
		compressed, err = c.compress(rawHCL)
		if err != nil {
			return err
		}
		if len(compressed) > MaxGossipPayloadSize {
			c.logger.Fields("domain", domain, "size", len(compressed), "limit", MaxGossipPayloadSize).Warn("config too large for gossip, skipped")
			return nil
		}
	}

	payload := ConfigPayload{
		Domain:    domain,
		RawHCL:    compressed,
		Checksum:  checksum,
		Timestamp: time.Now().UnixNano(),
		NodeID:    nodeID,
		Deleted:   deleted,
	}

	c.checksums[domain] = checksum

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	del.broadcast(OpConfig, "config:"+domain, data, nodeID)
	return nil
}

func (c *ConfigManager) ShouldBroadcast(domain string, content []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	checksum := c.calculateChecksum(content)
	if c.checksums[domain] == checksum {
		return false
	}
	return true
}

func (c *ConfigManager) UpdateChecksum(domain string, content []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checksums[domain] = c.calculateChecksum(content)
}

func (c *ConfigManager) validateHCL(targetPath string, rawHCL []byte) bool {
	tempPath := targetPath + configValidateSuffix
	if err := os.WriteFile(tempPath, rawHCL, configFilePerm); err != nil {
		return false
	}
	defer os.Remove(tempPath)
	_, err := parser.ParseHostConfig(tempPath)
	return err == nil
}

func (c *ConfigManager) writeAtomic(targetPath string, data []byte) error {
	tempPath := targetPath + configTempSuffix
	if err := os.WriteFile(tempPath, data, configFilePerm); err != nil {
		return err
	}
	return os.Rename(tempPath, targetPath)
}

func (c *ConfigManager) calculateChecksum(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

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
