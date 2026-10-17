package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
)

type fakeStore map[string]string

func (f fakeStore) Get(key string) (string, bool, error) {
	v, ok := f[key]
	return v, ok, nil
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func loadedWith(dir string, secrets map[string]manifest.Secret) *manifest.Loaded {
	return &manifest.Loaded{
		Project: &manifest.Manifest{
			Project: manifest.Project{Name: "test"},
			Secrets: secrets,
		},
		ProjectPath: filepath.Join(dir, ".agentsecrets.toml"),
	}
}

func envOf(res *Result, key string) string {
	for _, kv := range res.Env {
		if strings.HasPrefix(kv, key+"=") {
			return strings.TrimPrefix(kv, key+"=")
		}
	}
	return ""
}

func TestParseDotenv(t *testing.T) {
	src := "# comment\n" +
		"export A=1\n" +
		"B = two\n" +
		"C=\"three\\nfour\"\n" +
		"D='raw # not comment'\n" +
		"E=plain # trailing comment\n" +
		"F=\"quoted # hash\"\n"
	m, err := ParseDotenv([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"A": "1",
		"B": "two",
		"C": "three\nfour",
		"D": "raw # not comment",
		"E": "plain",
		"F": "quoted # hash",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
	if _, err := ParseDotenv([]byte("NOT A LINE")); err == nil {
		t.Error("expected an error for a malformed line")
	}
}

func TestManifestInjection(t *testing.T) {
	dir := t.TempDir()
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"GITHUB_TOKEN": {Ref: "vault://dev/gh", Transport: manifest.TransportEnv},
	})
	res, err := Build(loaded, fakeStore{"dev/gh": "tok"}, dir, Options{Environ: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "GITHUB_TOKEN"); got != "tok" {
		t.Fatalf("GITHUB_TOKEN = %q", got)
	}
	if len(res.Injected) != 1 || res.Injected[0] != "GITHUB_TOKEN" {
		t.Errorf("Injected = %v", res.Injected)
	}
}

func TestMasterIdentityNotInheritedAndOriginalStillRedacted(t *testing.T) {
	dir := t.TempDir()
	l := loadedWith(dir, map[string]manifest.Secret{"TOKEN": {Ref: "vault://t", Transport: manifest.TransportEnv}})
	r, err := Build(l, fakeStore{"t": "original"}, dir, Options{Environ: []string{"TOKEN=override", "SM_IDENTITY=master-key"}, AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if envOf(r, "SM_IDENTITY") != "" {
		t.Fatal("master identity leaked")
	}
	if r.Redactions["original"] == "" || r.Redactions["override"] == "" {
		t.Fatal("override dropped original redaction")
	}
}

func TestOnlySelectedSecretsAndAliasesReachChild(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "OTHER_ALIAS=sm://OTHER\n")
	l := loadedWith(dir, map[string]manifest.Secret{"TOKEN": {Ref: "vault://t", Transport: manifest.TransportEnv}, "OTHER": {Ref: "vault://missing", Transport: manifest.TransportEnv}})
	r, err := Build(l, fakeStore{"t": "token"}, dir, Options{Names: []string{"TOKEN"}, Environ: []string{"OTHER=inherited"}})
	if err != nil {
		t.Fatal(err)
	}
	if envOf(r, "TOKEN") != "token" || envOf(r, "OTHER") != "" || envOf(r, "OTHER_ALIAS") != "" {
		t.Fatal("selection leaked other credentials")
	}
}

func TestDotenvPrecedence(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "K=base\nONLY_BASE=1\n")
	write(t, filepath.Join(dir, ".env.prod"), "K=prod\n")
	write(t, filepath.Join(dir, ".env.local"), "K=local\n")
	loaded := loadedWith(dir, nil)

	res, err := Build(loaded, fakeStore{}, dir, Options{Profile: "prod", Environ: []string{"K=parent"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "K"); got != "parent" {
		t.Errorf("K = %q, want parent (process env wins)", got)
	}
	if got := envOf(res, "ONLY_BASE"); got != "1" {
		t.Errorf("ONLY_BASE = %q", got)
	}

	res, err = Build(loaded, fakeStore{}, dir, Options{Profile: "prod", Environ: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "K"); got != "local" {
		t.Errorf("K = %q, want local (.env.local wins over .env.prod)", got)
	}
}

func TestRefBinding(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "OPENAI_API_KEY=sm://OPENAI_KEY\n")
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"OPENAI_KEY": {Ref: "vault://openai", Transport: manifest.TransportEnv},
	})
	res, err := Build(loaded, fakeStore{"openai": "sk-123"}, dir, Options{Environ: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "OPENAI_API_KEY"); got != "sk-123" {
		t.Errorf("OPENAI_API_KEY = %q", got)
	}
	if len(res.DotenvRef) != 1 || res.DotenvRef[0] != "OPENAI_API_KEY" {
		t.Errorf("DotenvRef = %v", res.DotenvRef)
	}
}

func TestRefOverridesLowerPlaintext(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "API_KEY=old-plain\n")
	write(t, filepath.Join(dir, ".env.local"), "API_KEY=sm://K\n")
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"K": {Ref: "vault://k", Transport: manifest.TransportEnv},
	})
	res, err := Build(loaded, fakeStore{"k": "fresh"}, dir, Options{Environ: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "API_KEY"); got != "fresh" {
		t.Errorf("API_KEY = %q, want fresh", got)
	}
}

func TestRefShadowIdenticalNoWarning(t *testing.T) {
	// Nested sm exec: the parent env already carries the resolved value.
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "API_KEY=sm://K\n")
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"K": {Ref: "vault://k", Transport: manifest.TransportEnv},
	})
	res, err := Build(loaded, fakeStore{"k": "same"}, dir, Options{Environ: []string{"API_KEY=same"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "API_KEY"); got != "same" {
		t.Errorf("API_KEY = %q, want same", got)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}
}

func TestRefShadowDifferentRefuses(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "API_KEY=sm://K\n")
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"K": {Ref: "vault://k", Transport: manifest.TransportEnv},
	})
	if _, err := Build(loaded, fakeStore{"k": "fresh"}, dir, Options{Environ: []string{"API_KEY=stale"}}); err == nil {
		t.Fatal("alias must refuse plaintext shadows")
	}
	res, err := Build(loaded, fakeStore{"k": "fresh"}, dir, Options{Environ: []string{"API_KEY=stale"}, AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "API_KEY"); got != "stale" {
		t.Errorf("API_KEY = %q, want stale (process env wins)", got)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a shadow warning")
	}
}

func TestShadowRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "GITHUB_TOKEN=stale\n")
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"GITHUB_TOKEN": {Ref: "vault://gh", Transport: manifest.TransportEnv},
	})

	_, err := Build(loaded, fakeStore{"gh": "fresh"}, dir, Options{Environ: []string{}})
	if err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("expected a shadow error, got %v", err)
	}

	res, err := Build(loaded, fakeStore{"gh": "fresh"}, dir, Options{Environ: []string{}, AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "GITHUB_TOKEN"); got != "stale" {
		t.Errorf("override = %q, want stale", got)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected an override warning")
	}
}

func TestEqualPlaintextAllowed(t *testing.T) {
	dir := t.TempDir()
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"GITHUB_TOKEN": {Ref: "vault://gh", Transport: manifest.TransportEnv},
	})
	res, err := Build(loaded, fakeStore{"gh": "same"}, dir, Options{Environ: []string{"GITHUB_TOKEN=same"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(res, "GITHUB_TOKEN"); got != "same" {
		t.Errorf("GITHUB_TOKEN = %q", got)
	}
}

func TestTransportViolations(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "X=sm://PROXY_SECRET\n")
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"PROXY_SECRET": {Ref: "vault://p", Transport: manifest.TransportProxy},
	})
	if _, err := Build(loaded, fakeStore{"p": "v"}, dir, Options{Environ: []string{}}); err == nil {
		t.Fatal("expected a proxy transport error")
	}
}

func TestMissingVaultValue(t *testing.T) {
	dir := t.TempDir()
	loaded := loadedWith(dir, map[string]manifest.Secret{
		"S": {Ref: "vault://s", Transport: manifest.TransportEnv},
	})
	if _, err := Build(loaded, fakeStore{}, dir, Options{Environ: []string{}}); err == nil {
		t.Fatal("expected a missing vault error")
	}
}

func TestUnknownRef(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".env"), "X=sm://NOPE\n")
	loaded := loadedWith(dir, nil)
	if _, err := Build(loaded, fakeStore{}, dir, Options{Environ: []string{}}); err == nil {
		t.Fatal("expected an unknown ref error")
	}
}

func TestKeys(t *testing.T) {
	data := []byte("B=1\n# c\nA=2\nexport C=3\nB=4\n")
	if got, want := strings.Join(Keys(data), ","), "B,A,C"; got != want {
		t.Errorf("Keys = %q, want %q", got, want)
	}
}

func TestReplaceValues(t *testing.T) {
	data := []byte("A=secret\nB=keep\n# A=x\nexport C=zzz\n")
	out := ReplaceValues(data, map[string]string{"A": "sm://A", "C": "sm://C"})
	want := "A=sm://A\nB=keep\n# A=x\nC=sm://C\n"
	if string(out) != want {
		t.Errorf("ReplaceValues = %q, want %q", out, want)
	}
}
