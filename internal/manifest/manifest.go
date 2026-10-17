// Package manifest implements the .agentsecrets.toml schema, discovery
// (git-style walk-up plus a global layer) and validation.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
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
	// Service groups related entries (e.g. "stripe" around BASE_URL + API_KEY).
	Service string `toml:"service,omitempty"`
	// Sensitive false marks plain config (base URLs, model names): still stored,
	// injected and never displayed, but not masked and not reported as a leak.
	Sensitive *bool `toml:"sensitive,omitempty"`
}

// IsSensitive defaults to true; only an explicit false opts out.
func (s Secret) IsSensitive() bool { return s.Sensitive == nil || *s.Sensitive }

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
	if strings.ContainsAny(path, "\x00\r\n\t?# ") {
		return Ref{}, fmt.Errorf("invalid store reference path")
	}
	return Ref{Scheme: scheme, Path: path}, nil
}

// Load reads and validates one manifest file.
func Load(path string) (*Manifest, error) {
	var m Manifest
	md, err := toml.DecodeFile(path, &m)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("%s: unknown manifest fields; values must only be stored in the vault", path)
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
	if ttl := m.Project.DefaultTTL; ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil || d <= 0 {
			return fmt.Errorf("default_ttl must be a positive duration (advisory, not enforced)")
		}
	}
	for name, s := range m.Secrets {
		if !ValidName(name) {
			return fmt.Errorf("invalid secret name; use letters, digits and underscore")
		}
		if s.Service != "" && !ValidService(s.Service) {
			return fmt.Errorf("secret %s: invalid service name %q (letters, digits, dot, dash, underscore; max 32)", name, s.Service)
		}
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
	unlock, err := safeio.Lock(gp + ".lock")
	if err != nil {
		return "", false, err
	}
	defer unlock()
	if _, statErr := os.Stat(gp); statErr == nil {
		if _, err := Load(gp); err != nil {
			return "", false, err
		}
		return gp, false, nil
	} else if !os.IsNotExist(statErr) {
		return "", false, statErr
	}
	if err := os.MkdirAll(filepath.Dir(gp), 0o700); err != nil {
		return "", false, err
	}
	header := "# global manifest — shared across projects; no values, ever\n[secrets]\n"
	if err := safeio.Write(gp, []byte(header), 0o600); err != nil {
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
	l, err := LoadOptional(startDir)
	if err != nil {
		return nil, err
	}
	if l.Global == nil && l.Project == nil {
		return nil, fmt.Errorf("no secret manifest found; run `sm onboard` or `sm add --global NAME`")
	}
	return l, nil
}

// LoadOptional accepts missing manifests, never malformed or unreadable ones.
func LoadOptional(startDir string) (*Loaded, error) {
	l := &Loaded{}

	gp, err := GlobalPath()
	if err != nil {
		return nil, err
	}
	{
		if _, statErr := os.Stat(gp); statErr == nil {
			m, err := Load(gp)
			if err != nil {
				return nil, err
			}
			l.Global, l.GlobalPath = m, gp
		} else if !os.IsNotExist(statErr) {
			return nil, statErr
		}
	}

	if pp, ok := FindProject(startDir); ok {
		m, err := Load(pp)
		if err != nil {
			return nil, err
		}
		l.Project, l.ProjectPath = m, pp
	}

	return l, nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func ValidName(name string) bool {
	return envName.MatchString(name) && name != "SM_IDENTITY" && name != "SM_CONFIG_DIR" && name != "SM_ALLOW_PLAINTEXT"
}

var serviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)

// ValidService accepts short labels used to group related secrets.
func ValidService(name string) bool { return serviceName.MatchString(name) }

// DefaultRef separates projects and preserves case. Existing refs stay valid.
func DefaultRef(target, name string) string {
	global, _ := GlobalPath()
	if target == global {
		return "vault://global/" + name
	}
	abs, _ := filepath.Abs(target)
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	id := sha256.Sum256([]byte(abs))
	return fmt.Sprintf("vault://projects/%x/%s", id[:12], name)
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

// ServiceMembers returns the declared secret names belonging to a service,
// sorted. The comparison is exact.
func (m *Manifest) ServiceMembers(service string) []string {
	var out []string
	for name, s := range m.Secrets {
		if s.Service == service {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Services lists the distinct service names, sorted.
func (m *Manifest) Services() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range m.Secrets {
		if s.Service != "" && !seen[s.Service] {
			seen[s.Service] = true
			out = append(out, s.Service)
		}
	}
	sort.Strings(out)
	return out
}

// SetService updates one entry's service field in place, preserving the rest
// of the file. An empty service removes the field (ungrouped).
func SetService(path, name, service string) error {
	return SetServices(path, map[string]string{name: service})
}

// SetServices applies a whole group's label changes in one validated write.
func SetServices(path string, services map[string]string) error {
	unlock, err := safeio.Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(data)
	var expected Manifest
	if _, err := toml.Decode(text, &expected); err != nil {
		return fmt.Errorf("manifest is invalid; nothing changed")
	}
	if err := expected.Validate(); err != nil {
		return err
	}
	for name, service := range services {
		entry, ok := expected.Secrets[name]
		if !ok {
			return fmt.Errorf("entry is not declared")
		}
		entry.Service = service
		expected.Secrets[name] = entry
	}
	var errEdit error
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		text, errEdit = setServiceText(text, name, services[name])
		if errEdit != nil {
			return errEdit
		}
	}
	var check Manifest
	if _, err := toml.Decode(text, &check); err != nil {
		return fmt.Errorf("group edit would produce invalid TOML; manifest unchanged")
	}
	if err := check.Validate(); err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, check) {
		return fmt.Errorf("group edit would change other manifest data; nothing changed")
	}
	for name, service := range services {
		if check.Secrets[name].Service != service {
			return fmt.Errorf("group edit did not apply cleanly")
		}
	}
	if bytes.Equal(data, []byte(text)) {
		return nil
	}
	return safeio.Write(path, []byte(text), 0o600)
}

func setServiceText(text, name, service string) (string, error) {
	header := "[secrets." + name + "]"
	lines := strings.Split(text, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == header {
			start = i
			break
		}
	}
	if start == -1 {
		return "", fmt.Errorf("no %s entry; use a plain [secrets.NAME] table for group editing", header)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "[") {
			end = i
			break
		}
	}

	var kept []string
	for _, line := range lines[start+1 : end] {
		if key, _, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.TrimSpace(key) == "service" {
			continue
		}
		kept = append(kept, line)
	}
	last := len(kept) - 1
	for last >= 0 && strings.TrimSpace(kept[last]) == "" {
		last--
	}
	out := append([]string{}, lines[:start+1]...)
	out = append(out, kept[:last+1]...)
	if service != "" {
		out = append(out, fmt.Sprintf("service = %q", service))
	}
	out = append(out, kept[last+1:]...)
	out = append(out, lines[end:]...)
	updated := strings.Join(out, "\n")

	return updated, nil
}

// AppendSecret appends a [secrets.NAME] block to the manifest file, preserving
// existing formatting and comments. The result is re-parsed before writing so
// a bad append can never leave a broken manifest behind. It does not check for
// duplicate names.
func AppendSecret(path, name string, s Secret) error {
	return AppendSecrets(path, map[string]Secret{name: s})
}

func AppendSecrets(path string, entries map[string]Secret) error {
	unlock, err := safeio.Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	var names []string
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		s := entries[name]
		if s.Transport == "" {
			s.Transport = TransportEnv
		}

		key := name
		if !bareKey.MatchString(name) {
			key = fmt.Sprintf("%q", name)
		}

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
		if s.Service != "" {
			fmt.Fprintf(&b, "service = %q\n", s.Service)
		}
		if s.Sensitive != nil && !*s.Sensitive {
			fmt.Fprintf(&b, "sensitive = false\n")
		}
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
	if err := check.Validate(); err != nil {
		return err
	}
	return safeio.Write(path, []byte(updated), 0o600)
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
