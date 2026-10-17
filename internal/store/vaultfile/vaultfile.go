// Package vaultfile implements the local encrypted vault: a single age
// (X25519) encrypted JSON file, keyed by ref path.
package vaultfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"filippo.io/age"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
)

// Vault is the local encrypted store.
type Vault struct {
	mu       sync.Mutex
	path     string
	identity *age.X25519Identity
	values   map[string]string
}

// Open loads the vault at path. A missing file yields an empty vault that is
// created on the first write (or by Save).
func Open(path, identity string) (*Vault, error) {
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		return nil, fmt.Errorf("invalid vault identity")
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
		return nil, fmt.Errorf("invalid vault contents")
	}
	if v.values == nil {
		return nil, fmt.Errorf("invalid vault contents: expected an object")
	}
	return v, nil
}

// Get returns the value for key. found is false when the key is absent.
func (v *Vault) Get(key string) (string, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	val, ok := v.values[key]
	return val, ok, nil
}

// Set writes (or replaces) the value for key and persists the vault.
func (v *Vault) Set(key, value string) error {
	return v.update(func(values map[string]string) error { values[key] = value; return nil })
}

// SetNew refuses to replace an existing path, including an orphaned value.
func (v *Vault) SetNew(key, value string) error {
	return v.update(func(values map[string]string) error {
		if _, ok := values[key]; ok {
			return fmt.Errorf("vault path already exists; use rotate or a different ref")
		}
		values[key] = value
		return nil
	})
}

// Delete removes key. Deleting an absent key is not an error.
func (v *Vault) Delete(key string) error {
	return v.update(func(values map[string]string) error { delete(values, key); return nil })
}

// List returns all keys, sorted.
func (v *Vault) List() ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
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
	return v.update(func(map[string]string) error { return nil })
}

func (v *Vault) update(change func(map[string]string) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	unlock, err := safeio.Lock(v.path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	// Reload under the lock: another UI, CLI or MCP process may have written.
	latest, err := Open(v.path, v.identity.String())
	if err != nil {
		return err
	}
	if err := change(latest.values); err != nil {
		return err
	}
	if err := latest.save(); err != nil {
		return err
	}
	v.values = latest.values
	return nil
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

	return safeio.Write(v.path, buf.Bytes(), 0o600)
}
