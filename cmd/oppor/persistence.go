package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

const configDir = ".oppor"
const configFile = "config.json"

type SavedConfig struct {
	Presets []ConfigPreset `json:"presets"`
}

type ConfigPreset struct {
	Name   string `json:"name"`
	Config Config `json:"config"`
}

func saveCurrentConfig(cfg Config, name string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(home, configDir)
	if err := os.MkdirAll(configPath, 0755); err != nil {
		return err
	}

	filePath := filepath.Join(configPath, configFile)

	var saved SavedConfig
	if data, err := os.ReadFile(filePath); err == nil {
		json.Unmarshal(data, &saved)
	}

	// Remove existing preset with same name
	for i, preset := range saved.Presets {
		if preset.Name == name {
			saved.Presets = append(saved.Presets[:i], saved.Presets[i+1:]...)
			break
		}
	}

	saved.Presets = append(saved.Presets, ConfigPreset{
		Name:   name,
		Config: cfg,
	})

	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, woos.FilePermSecured)
}

func loadConfigPreset(name string) (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}

	filePath := filepath.Join(home, configDir, configFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return Config{}, err
	}

	var saved SavedConfig
	if err := json.Unmarshal(data, &saved); err != nil {
		return Config{}, err
	}

	for _, preset := range saved.Presets {
		if preset.Name == name {
			return preset.Config, nil
		}
	}

	return Config{}, fmt.Errorf("preset not found: %s", name)
}

func listConfigPresets() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	filePath := filepath.Join(home, configDir, configFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return []string{}, nil
	}

	var saved SavedConfig
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}

	var names []string
	for _, preset := range saved.Presets {
		names = append(names, preset.Name)
	}

	return names, nil
}
