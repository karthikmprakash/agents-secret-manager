// Package recovery creates passphrase-encrypted local archives. It has no
// network access and never writes plaintext archives or exports a master key.
package recovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

const MaxArchive = 32 << 20

type archive struct {
	Version  int               `json:"version"`
	Created  string            `json:"created"`
	Manifest string            `json:"manifest"`
	Values   map[string]string `json:"values"`
}

// Contents retains decrypted data in memory only, until restore completes.
type Contents struct{ data archive }
type Summary struct {
	Created      string `json:"created"`
	Entries      int    `json:"entries"`
	StoredValues int    `json:"storedValues"`
}

func (c *Contents) Summary() Summary {
	return Summary{c.data.Created, len(c.manifest().Secrets), len(c.data.Values)}
}
func (c *Contents) manifest() *manifest.Manifest {
	var m manifest.Manifest
	_, _ = toml.Decode(c.data.Manifest, &m)
	return &m
}

func validate(a archive) error {
	if a.Version != 1 || a.Values == nil {
		return fmt.Errorf("unsupported or invalid recovery archive")
	}
	var m manifest.Manifest
	md, err := toml.Decode(a.Manifest, &m)
	if err != nil || len(md.Undecoded()) > 0 {
		return fmt.Errorf("recovery manifest is invalid")
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("recovery manifest is invalid")
	}
	for _, s := range m.Secrets {
		ref, _ := manifest.ParseRef(s.Ref)
		if _, ok := a.Values[ref.Path]; !ok {
			return fmt.Errorf("a declared recovery value is missing")
		}
	}
	for _, value := range a.Values {
		if value == "" || strings.ContainsRune(value, 0) || len(value) > 1<<20 {
			return fmt.Errorf("recovery contains an invalid value")
		}
	}
	return nil
}

// Export snapshots the global manifest and all vault values under the shared
// mutation lock. Keep project reference manifests in their repositories.
func Export(dir, identity, passphrase string) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, fmt.Errorf("use a recovery passphrase of at least 12 characters")
	}
	unlock, err := safeio.Lock(filepath.Join(dir, "mutation.lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := os.Stat(filepath.Join(dir, "vault.age")); err != nil {
		return nil, fmt.Errorf("initialize the vault before backing up")
	}
	v, err := vaultfile.Open(filepath.Join(dir, "vault.age"), identity)
	if err != nil {
		return nil, fmt.Errorf("vault unavailable; unlock it before backing up")
	}
	manifestText, err := os.ReadFile(filepath.Join(dir, "manifest.toml"))
	if os.IsNotExist(err) {
		manifestText = []byte("[secrets]\n")
	} else if err != nil {
		return nil, err
	}
	a := archive{Version: 1, Created: time.Now().UTC().Format(time.RFC3339), Manifest: string(manifestText), Values: map[string]string{}}
	paths, _ := v.List()
	for _, path := range paths {
		value, _, _ := v.Get(path)
		a.Values[path] = value
	}
	if err := validate(a); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("could not encode recovery archive")
	}
	if len(plain) > MaxArchive-4096 {
		return nil, fmt.Errorf("recovery archive exceeds 32 MiB")
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, fmt.Errorf("could not create recovery encryption")
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Open verifies the entire authenticated ciphertext before any destination is
// touched. Work factor and plaintext size are bounded for untrusted archives.
func Open(ciphertext []byte, passphrase string) (*Contents, error) {
	if len(ciphertext) > MaxArchive {
		return nil, fmt.Errorf("recovery archive exceeds 32 MiB")
	}
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("enter the recovery passphrase")
	}
	id.SetMaxWorkFactor(18)
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase or damaged recovery archive")
	}
	plain, err := io.ReadAll(io.LimitReader(r, MaxArchive+1))
	if err != nil || len(plain) > MaxArchive {
		return nil, fmt.Errorf("damaged or oversized recovery archive")
	}
	var a archive
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return nil, fmt.Errorf("invalid recovery archive")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("invalid recovery archive")
	}
	if err := validate(a); err != nil {
		return nil, err
	}
	return &Contents{data: a}, nil
}

// Restore re-encrypts values with the destination's identity, which may differ
// from the original Mac. Existing vaults/manifests are never replaced.
func (c *Contents) Restore(dir, identity string) error {
	unlock, err := safeio.Lock(filepath.Join(dir, "mutation.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	for _, name := range []string{"vault.age", "manifest.toml"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("restore requires an empty vault directory; existing data was not changed")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := validate(c.data); err != nil {
		return err
	}
	// Encrypt in a private staging directory before installing either file.
	stage, err := os.MkdirTemp(dir, ".sm-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	v, err := vaultfile.Open(filepath.Join(stage, "vault.age"), identity)
	if err != nil {
		return err
	}
	if err := v.SetBatch(c.data.Values); err != nil {
		return err
	}
	if err := safeio.Write(filepath.Join(stage, "manifest.toml"), []byte(c.data.Manifest), 0o600); err != nil {
		return err
	}
	// Hard links give no-replace semantics even if a non-cooperating writer races.
	installed := []string{}
	for _, name := range []string{"vault.age", "manifest.toml"} {
		path := filepath.Join(dir, name)
		if err := os.Link(filepath.Join(stage, name), path); err != nil {
			for _, created := range installed {
				original, e1 := os.Stat(filepath.Join(stage, filepath.Base(created)))
				current, e2 := os.Lstat(created)
				if e1 == nil && e2 == nil && os.SameFile(original, current) {
					_ = os.Remove(created)
				}
			}
			return fmt.Errorf("could not install recovery files; destination was not overwritten")
		}
		installed = append(installed, path)
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
