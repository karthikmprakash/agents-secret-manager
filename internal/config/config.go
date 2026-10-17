// Package config locates sm's configuration directory.
package config

import (
	"os"
	"path/filepath"
)

// Dir returns ~/.config/sm. SM_CONFIG_DIR overrides it (tests, throwaway runs).
func Dir() (string, error) {
	if dir := os.Getenv("SM_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sm"), nil
}
