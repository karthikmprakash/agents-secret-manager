// Package keys manages the vault master identity: generated once and stored
// in the OS Keychain. SM_IDENTITY overrides the Keychain for CI and tests.
package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/zalando/go-keyring"

	"github.com/karthikmprakash/agents-secret-manager/internal/config"
)

const (
	service = "sm"
	account = "identity"
)

// ErrNotFound means no identity is configured yet.
var ErrNotFound = errors.New("no vault identity found — run `sm init`")

// Get returns the master identity (AGE-SECRET-KEY-1...).
func Get() (string, error) {
	if v := os.Getenv("SM_IDENTITY"); v != "" {
		return v, nil
	}
	id, err := keyring.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("read Keychain: %w", err)
	}
	return id, nil
}

// Exists reports whether an identity is already configured.
func Exists() bool {
	_, err := Get()
	return err == nil
}

// Create generates a new identity and stores it in the Keychain. It refuses
// to overwrite an existing identity.
func Create() (string, error) {
	if os.Getenv("SM_IDENTITY") != "" {
		return "", fmt.Errorf("SM_IDENTITY is set; refusing to create a Keychain identity")
	}
	if _, err := keyring.Get(service, account); err == nil {
		return "", fmt.Errorf("identity already exists in Keychain")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	s := id.String()
	if err := keyring.Set(service, account, s); err != nil {
		return "", fmt.Errorf("store identity in Keychain: %w (or set SM_IDENTITY to override)", err)
	}
	return s, nil
}

// VaultPath returns ~/.config/sm/vault.age (honoring SM_CONFIG_DIR).
func VaultPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vault.age"), nil
}
