// Package store defines the secret storage interface.
//
// The v0.1 implementation is the local encrypted vault (vaultfile);
// connectors (op://, infisical://, aws-sm://) plug in behind this interface
// in v0.3.
package store

// Store is a keyed secret store. Keys are ref paths like "dev/github/pat".
type Store interface {
	// Get returns the value for key. found is false when the key is absent.
	Get(key string) (value string, found bool, err error)
	// Set writes (or replaces) the value for key.
	Set(key, value string) error
	// Delete removes key. Deleting an absent key is not an error.
	Delete(key string) error
	// List returns all keys, sorted.
	List() ([]string, error)
}
