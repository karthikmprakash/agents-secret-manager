// Package secrets shares validated, serialized mutations across CLI and UI.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

// Initialize is explicit: opening the UI must not create or replace an identity.
func Initialize() error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	unlock, err := safeio.Lock(filepath.Join(dir, "mutation.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	identity, err := keys.Get()
	if errors.Is(err, keys.ErrNotFound) {
		vp, e := keys.VaultPath()
		if e != nil {
			return e
		}
		if _, e := os.Stat(vp); e == nil {
			return fmt.Errorf("vault exists but its Keychain identity is missing; restore the identity before continuing")
		} else if !os.IsNotExist(e) {
			return e
		}
		identity, err = keys.Create()
	}
	if err != nil {
		return err
	}
	vp, err := keys.VaultPath()
	if err != nil {
		return err
	}
	v, err := vaultfile.Open(vp, identity)
	if err != nil {
		return err
	}
	if err := v.Save(); err != nil {
		return err
	}
	_, _, err = manifest.EnsureGlobal()
	return err
}

type Input struct {
	Name   string
	Value  string
	Secret manifest.Secret
}

func validValue(value string) error {
	if value == "" {
		return fmt.Errorf("secret value must not be empty")
	}
	if strings.ContainsRune(value, 0) {
		return fmt.Errorf("secret values cannot contain NUL bytes")
	}
	if len(value) > 1<<20 {
		return fmt.Errorf("secret exceeds the 1 MiB limit")
	}
	return nil
}

// AddBatch validates every item before writing. It never silently overwrites a
// path, including paths shared by old manifests. Import may reuse equal values.
func AddBatch(target string, inputs []Input, importing bool) error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	unlock, err := safeio.Lock(filepath.Join(dir, "mutation.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	current, err := manifest.Load(target)
	if err != nil {
		return err
	}
	id, err := keys.Get()
	if err != nil {
		return err
	}
	vp, err := keys.VaultPath()
	if err != nil {
		return err
	}
	v, err := vaultfile.Open(vp, id)
	if err != nil {
		return err
	}
	additions := map[string]manifest.Secret{}
	paths := map[string]string{}
	writes := map[string]string{}
	for _, in := range inputs {
		if !manifest.ValidName(in.Name) {
			return fmt.Errorf("invalid secret name")
		}
		if err := validValue(in.Value); err != nil {
			return err
		}
		s := in.Secret
		if old, exists := current.Secrets[in.Name]; exists {
			if !importing {
				return fmt.Errorf("%s already exists; use rotate", in.Name)
			}
			s = old
		} else {
			if _, duplicate := additions[in.Name]; duplicate {
				return fmt.Errorf("duplicate secret name %s", in.Name)
			}
			if s.Ref == "" {
				s.Ref = manifest.DefaultRef(target, in.Name)
			}
			if s.Transport == "" {
				s.Transport = manifest.TransportEnv
			}
			additions[in.Name] = s
		}
		check := manifest.Manifest{Secrets: map[string]manifest.Secret{in.Name: s}}
		if err := check.Validate(); err != nil {
			return err
		}
		if importing && s.Transport != manifest.TransportEnv {
			return fmt.Errorf("%s cannot be imported as an env reference with transport %s", in.Name, s.Transport)
		}
		r, _ := manifest.ParseRef(s.Ref)
		if other, ok := paths[r.Path]; ok && other != in.Name {
			return fmt.Errorf("%s and %s use the same vault path", other, in.Name)
		}
		paths[r.Path] = in.Name
		existing, found, err := v.Get(r.Path)
		if err != nil {
			return err
		}
		if found {
			if !importing || existing != in.Value {
				return fmt.Errorf("%s conflicts with a stored value; nothing imported, use rotate explicitly", in.Name)
			}
		} else {
			writes[r.Path] = in.Value
		}
	}
	if err := record(dir, "store", inputsNames(inputs)); err != nil {
		return err
	}
	var written []string
	rollback := func() {
		for _, path := range written {
			_ = v.Delete(path)
		}
	}
	for path, value := range writes {
		if err := v.SetNew(path, value); err != nil {
			rollback()
			return err
		}
		written = append(written, path)
	}
	if len(additions) > 0 {
		if err := manifest.AppendSecrets(target, additions); err != nil {
			rollback()
			return err
		}
	}
	return nil
}

func inputsNames(inputs []Input) []string {
	names := make([]string, 0, len(inputs))
	for _, in := range inputs {
		names = append(names, in.Name)
	}
	sort.Strings(names)
	return names
}

// SetService moves one declared secret into (or out of) a service group by
// editing the manifest entry in place. Empty service ungroups.
func SetService(target, name, service string) error {
	service = strings.TrimSpace(service)
	if service != "" && !manifest.ValidService(service) {
		return fmt.Errorf("invalid service name %q (letters, digits, dot, dash, underscore; max 32)", service)
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	unlock, err := safeio.Lock(filepath.Join(dir, "mutation.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	current, err := manifest.Load(target)
	if err != nil {
		return err
	}
	if _, ok := current.Secrets[name]; !ok {
		return fmt.Errorf("%s is not declared in %s", name, target)
	}
	if err := record(dir, "group", []string{name}); err != nil {
		return err
	}
	return manifest.SetService(target, name, service)
}

// MoveService changes only the selected labels. Expected source labels prevent
// stale Undo actions from regrouping entries edited by another process.
func MoveService(target, from, to string, names []string) ([]string, error) {
	if (from != "" && !manifest.ValidService(from)) || (to != "" && !manifest.ValidService(to)) {
		return nil, fmt.Errorf("invalid group name")
	}
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	unlock, err := safeio.Lock(filepath.Join(dir, "mutation.lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	current, err := manifest.Load(target)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		if from == "" {
			return nil, fmt.Errorf("select the entries to regroup")
		}
		names = current.ServiceMembers(from)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("group has no entries in this scope")
	}
	changes := map[string]string{}
	for _, name := range names {
		s, ok := current.Secrets[name]
		if !ok || s.Service != from {
			return nil, fmt.Errorf("group changed since it was opened; refresh before saving")
		}
		changes[name] = to
	}
	if err := record(dir, "group", names); err != nil {
		return nil, err
	}
	if err := manifest.SetServices(target, changes); err != nil {
		return nil, err
	}
	return names, nil
}

// Rotate updates only the declared path; it does not rotate a provider's key.
func Rotate(cwd, name, value string) error {
	if err := validValue(value); err != nil {
		return err
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	unlock, err := safeio.Lock(filepath.Join(dir, "mutation.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	l, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}
	s, ok := l.Merged().Secrets[name]
	if !ok {
		return fmt.Errorf("secret %s is not declared", name)
	}
	id, err := keys.Get()
	if err != nil {
		return err
	}
	vp, err := keys.VaultPath()
	if err != nil {
		return err
	}
	v, err := vaultfile.Open(vp, id)
	if err != nil {
		return err
	}
	r, _ := manifest.ParseRef(s.Ref)
	if err := record(dir, "rotate", []string{name}); err != nil {
		return err
	}
	return v.Set(r.Path, value)
}

// Audit records mutation intent before performing it (not proof of success).
func record(dir, action string, names []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	return audit.Append(dir, audit.Entry{TS: time.Now().UTC().Format(time.RFC3339), Session: audit.NewSession(), Action: action, Secrets: names, Cmd: "sm " + action, CWD: cwd})
}
