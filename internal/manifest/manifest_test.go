package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseRef(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		path   string
		err    bool
	}{
		{"vault://dev/github/pat", "vault", "dev/github/pat", false},
		{"vault:///dev/x", "vault", "dev/x", false},
		{"op://vault/item", "op", "vault/item", false},
		{"nope", "", "", true},
		{"vault://", "", "", true},
		{"://x", "", "", true},
	}
	for _, c := range cases {
		got, err := ParseRef(c.in)
		if c.err {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.Scheme != c.scheme || got.Path != c.path {
			t.Errorf("%q → %+v, want %s / %s", c.in, got, c.scheme, c.path)
		}
	}
}

func TestLoadValidation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".agentsecrets.toml")

	writeFile(t, p, "[project]\nname = \"demo\"\n\n[secrets.TOKEN]\nref = \"vault://dev/token\"\n")
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Secrets["TOKEN"].Transport; got != TransportEnv {
		t.Errorf("transport default = %q, want %q", got, TransportEnv)
	}

	bad := map[string]string{
		"unknown transport":  "[secrets.T]\nref = \"vault://x\"\ntransport = \"smoke\"\n",
		"missing ref":        "[secrets.T]\ntransport = \"env\"\n",
		"unsupported scheme": "[secrets.T]\nref = \"op://vault/item\"\n",
	}
	for name, content := range bad {
		writeFile(t, p, content)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestFindProjectWalkUp(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".agentsecrets.toml"), "[secrets]\n")
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	got, ok := FindProject(nested)
	if !ok {
		t.Fatal("manifest not found")
	}
	if want := filepath.Join(root, ".agentsecrets.toml"); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestLoadLayersMerge(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", cfg)
	writeFile(t, filepath.Join(cfg, "manifest.toml"), `[secrets.SHARED]
ref = "vault://global/shared"

[secrets.ONLY_GLOBAL]
ref = "vault://global/only"
`)

	proj := t.TempDir()
	writeFile(t, filepath.Join(proj, ".agentsecrets.toml"), `[project]
name = "proj"

[secrets.SHARED]
ref = "vault://project/shared"
`)

	l, err := LoadLayers(proj)
	if err != nil {
		t.Fatal(err)
	}
	m := l.Merged()
	if got := m.Secrets["SHARED"].Ref; got != "vault://project/shared" {
		t.Errorf("SHARED ref = %s, want project override", got)
	}
	if _, ok := m.Secrets["ONLY_GLOBAL"]; !ok {
		t.Error("ONLY_GLOBAL missing after merge")
	}
	if m.Project.Name != "proj" {
		t.Errorf("project name = %q, want proj", m.Project.Name)
	}
}

func TestAppendSecret(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".agentsecrets.toml")
	writeFile(t, p, Template("demo"))

	if err := AppendSecret(p, "GITHUB_TOKEN", Secret{Ref: "vault://dev/github/pat", Transport: "env", Scope: []string{"cmd:gh"}}); err != nil {
		t.Fatal(err)
	}
	if err := AppendSecret(p, "weird.name", Secret{Ref: "vault://dev/weird", Transport: "env"}); err != nil {
		t.Fatal(err)
	}

	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := m.Secrets["GITHUB_TOKEN"]
	if !ok || s.Ref != "vault://dev/github/pat" {
		t.Fatalf("GITHUB_TOKEN = %+v", s)
	}
	if len(s.Scope) != 1 || s.Scope[0] != "cmd:gh" {
		t.Errorf("scope = %v", s.Scope)
	}
	if _, ok := m.Secrets["weird.name"]; !ok {
		t.Error("quoted key missing after append")
	}
}

func TestEnsureGlobal(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", cfg)

	p, created, err := EnsureGlobal()
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("expected created=true on first call")
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("global manifest is not valid TOML: %v", err)
	}

	p2, created2, err := EnsureGlobal()
	if err != nil {
		t.Fatal(err)
	}
	if created2 || p2 != p {
		t.Errorf("second call = %q, created=%v; want %q, false", p2, created2, p)
	}
}
