// Package vaultfile implements the local encrypted vault: a single age
// (X25519) encrypted JSON file, keyed by ref path.
package vaultfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"filippo.io/age"
)

// Vault is the local encrypted store.
type Vault struct {
	path     string
	identity *age.X25519Identity
	values   map[string]string
}

// Open loads the vault at path. A missing file yields an empty vault that is
// created on the first write (or by Save).
func Open(path, identity string) (*Vault, error) {
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		return nil, fmt.Errorf("parse vault identity: %w", err)
	}
	v := &Vault{path: path, identity: id, values: map[string]string{}}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return v, nil
		}
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(raw), id)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s (wrong identity, or the file is corrupt): %w", path, err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(plain, &v.values); err != nil {
		return nil, fmt.Errorf("decode vault contents: %w", err)
	}
	return v, nil
}

// Get returns the value for key. found is false when the key is absent.
func (v *Vault) Get(key string) (string, bool, error) {
	val, ok := v.values[key]
	return val, ok, nil
}

// Set writes (or replaces) the value for key and persists the vault.
func (v *Vault) Set(key, value string) error {
	v.values[key] = value
	return v.save()
}

// Delete removes key. Deleting an absent key is not an error.
func (v *Vault) Delete(key string) error {
	if _, ok := v.values[key]; !ok {
		return nil
	}
	delete(v.values, key)
	return v.save()
}

// List returns all keys, sorted.
func (v *Vault) List() ([]string, error) {
	keys := make([]string, 0, len(v.values))
	for k := range v.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Save persists the current state even when nothing changed (used by
// `sm init` to materialize an empty vault).
func (v *Vault) Save() error {
	return v.save()
}

func (v *Vault) save() error {
	plain, err := json.MarshalIndent(v.values, "", "  ")
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, v.identity.Recipient())
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	dir := filepath.Dir(v.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, v.path)
}
