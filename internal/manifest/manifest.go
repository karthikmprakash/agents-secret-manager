// Package manifest implements the .agentsecrets.toml schema, discovery
// (git-style walk-up plus a global layer) and validation.
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/karthikmprakash/agents-secret-manager/internal/config"
)

// Transports frozen in the v0.1 design.
const (
	TransportEnv   = "env"
	TransportFile  = "file"
	TransportProxy = "proxy"
	TransportGen   = "generated"
)

var validTransports = map[string]bool{
	TransportEnv:   true,
	TransportFile:  true,
	TransportProxy: true,
	TransportGen:   true,
}

// Secret is one entry under [secrets.NAME].
type Secret struct {
	Ref       string   `toml:"ref"`
	Transport string   `toml:"transport"`
	Scope     []string `toml:"scope,omitempty"`
	Hosts     []string `toml:"hosts,omitempty"`
	Generate  string   `toml:"generate,omitempty"`
}

// Project is the [project] table.
type Project struct {
	Name       string `toml:"name"`
	DefaultTTL string `toml:"default_ttl"`
}

// Manifest is a parsed .agentsecrets.toml.
type Manifest struct {
	Project Project           `toml:"project"`
	Secrets map[string]Secret `toml:"secrets"`
}

// Ref is a parsed store reference like vault://dev/github/pat.
type Ref struct {
	Scheme string
	Path   string
}

// ParseRef splits "scheme://path" into its parts.
func ParseRef(s string) (Ref, error) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || scheme == "" {
		return Ref{}, fmt.Errorf("invalid ref %q: expected scheme://path", s)
	}
	path := strings.TrimPrefix(rest, "/")
	if path == "" {
		return Ref{}, fmt.Errorf("invalid ref %q: empty path", s)
	}
	return Ref{Scheme: scheme, Path: path}, nil
}

// Load reads and validates one manifest file.
func Load(path string) (*Manifest, error) {
	var m Manifest
	if _, err := toml.DecodeFile(path, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.Secrets == nil {
		m.Secrets = map[string]Secret{}
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Validate checks transports and refs. The empty transport defaults to "env".
func (m *Manifest) Validate() error {
	for name, s := range m.Secrets {
		if s.Transport == "" {
			s.Transport = TransportEnv
			m.Secrets[name] = s
		}
		if !validTransports[s.Transport] {
			return fmt.Errorf("secret %s: unknown transport %q (want env, file, proxy or generated)", name, s.Transport)
		}
		if s.Ref == "" {
			return fmt.Errorf("secret %s: ref is required", name)
		}
		ref, err := ParseRef(s.Ref)
		if err != nil {
			return fmt.Errorf("secret %s: %w", name, err)
		}
		if ref.Scheme != "vault" {
			return fmt.Errorf("secret %s: store scheme %q is not supported yet (v0.1 supports vault://; connectors arrive in v0.3)", name, ref.Scheme)
		}
	}
	return nil
}

// GlobalPath returns the global manifest path (~/.config/sm/manifest.toml).
func GlobalPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "manifest.toml"), nil
}

// EnsureGlobal creates the global manifest with a header when it does not
// exist. created reports whether the file was written.
func EnsureGlobal() (path string, created bool, err error) {
	gp, err := GlobalPath()
	if err != nil {
		return "", false, err
	}
	if _, statErr := os.Stat(gp); statErr == nil {
		return gp, false, nil
	} else if !os.IsNotExist(statErr) {
		return "", false, statErr
	}
	if err := os.MkdirAll(filepath.Dir(gp), 0o700); err != nil {
		return "", false, err
	}
	header := "# global manifest — shared across projects; no values, ever\n[secrets]\n"
	if err := os.WriteFile(gp, []byte(header), 0o644); err != nil {
		return "", false, err
	}
	return gp, true, nil
}

// FindProject walks up from start looking for the nearest .agentsecrets.toml.
func FindProject(start string) (string, bool) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", false
	}
	for {
		p := filepath.Join(dir, ".agentsecrets.toml")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// Loaded carries the two manifest layers.
type Loaded struct {
	Global      *Manifest
	GlobalPath  string
	Project     *Manifest
	ProjectPath string
}

// LoadLayers loads the global layer (if present) and the project layer found
// by walking up from startDir. It errors when neither exists.
func LoadLayers(startDir string) (*Loaded, error) {
	l := &Loaded{}

	if gp, err := GlobalPath(); err == nil {
		if _, statErr := os.Stat(gp); statErr == nil {
			m, err := Load(gp)
			if err != nil {
				return nil, err
			}
			l.Global, l.GlobalPath = m, gp
		}
	}

	if pp, ok := FindProject(startDir); ok {
		m, err := Load(pp)
		if err != nil {
			return nil, err
		}
		l.Project, l.ProjectPath = m, pp
	}

	if l.Global == nil && l.Project == nil {
		return nil, fmt.Errorf("no .agentsecrets.toml found in %s or any parent (run `sm init` to create one)", startDir)
	}
	return l, nil
}

// Merged flattens the layers: global first, project overrides per secret and
// per project setting.
func (l *Loaded) Merged() *Manifest {
	out := &Manifest{Secrets: map[string]Secret{}}
	if l.Global != nil {
		out.Project = l.Global.Project
		for k, v := range l.Global.Secrets {
			out.Secrets[k] = v
		}
	}
	if l.Project != nil {
		if l.Project.Project.Name != "" {
			out.Project.Name = l.Project.Project.Name
		}
		if l.Project.Project.DefaultTTL != "" {
			out.Project.DefaultTTL = l.Project.Project.DefaultTTL
		}
		for k, v := range l.Project.Secrets {
			out.Secrets[k] = v
		}
	}
	return out
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// AppendSecret appends a [secrets.NAME] block to the manifest file, preserving
// existing formatting and comments. The result is re-parsed before writing so
// a bad append can never leave a broken manifest behind. It does not check for
// duplicate names.
func AppendSecret(path, name string, s Secret) error {
	if s.Transport == "" {
		s.Transport = TransportEnv
	}

	key := name
	if !bareKey.MatchString(name) {
		key = fmt.Sprintf("%q", name)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n[secrets.%s]\n", key)
	fmt.Fprintf(&b, "ref = %q\n", s.Ref)
	fmt.Fprintf(&b, "transport = %q\n", s.Transport)
	if len(s.Scope) > 0 {
		fmt.Fprintf(&b, "scope = [%s]\n", quoteList(s.Scope))
	}
	if len(s.Hosts) > 0 {
		fmt.Fprintf(&b, "hosts = [%s]\n", quoteList(s.Hosts))
	}
	if s.Generate != "" {
		fmt.Fprintf(&b, "generate = %q\n", s.Generate)
	}

	orig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated := string(orig)
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += b.String()

	var check Manifest
	if _, err := toml.Decode(updated, &check); err != nil {
		return fmt.Errorf("appending would break the manifest: %w", err)
	}
	return os.WriteFile(path, []byte(updated), 0o644)
}

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

// Template is the starter manifest written by `sm init`.
func Template(projectName string) string {
	return fmt.Sprintf(`# .agentsecrets.toml — committed; no values, ever
[project]
name = %q
default_ttl = "8h"

[secrets]
`, projectName)
}
