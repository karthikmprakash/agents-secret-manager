package secrets

import (
	"filippo.io/age"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", dir)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())
	if err := Initialize(); err != nil {
		t.Fatal(err)
	}
	p, _, err := manifest.EnsureGlobal()
	if err != nil {
		t.Fatal(err)
	}
	return dir, p
}

func TestProjectAndCaseIsolation(t *testing.T) {
	dir, global := fixture(t)
	projects := []string{filepath.Join(t.TempDir(), ".agentsecrets.toml"), filepath.Join(t.TempDir(), ".agentsecrets.toml")}
	for _, p := range projects {
		if err := os.WriteFile(p, []byte("[secrets]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range append(projects, global) {
		if err := AddBatch(p, []Input{{Name: "TOKEN", Value: p}, {Name: "token", Value: "lower"}}, false); err != nil {
			t.Fatal(err)
		}
	}
	v, err := vaultfile.Open(filepath.Join(dir, "vault.age"), os.Getenv("SM_IDENTITY"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range append(projects, global) {
		m, err := manifest.Load(p)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := manifest.ParseRef(m.Secrets["TOKEN"].Ref)
		got, ok, _ := v.Get(r.Path)
		if !ok || got != p {
			t.Fatal("namespace collision")
		}
	}
}

func TestConflictPreflightDoesNotChangeAnything(t *testing.T) {
	dir, p := fixture(t)
	if err := AddBatch(p, []Input{{Name: "OLD", Value: "keep"}}, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddBatch(p, []Input{{Name: "NEW", Value: "new"}, {Name: "OLD", Value: "different"}}, true); err == nil {
		t.Fatal("expected conflict")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("conflict changed manifest")
	}
	v, err := vaultfile.Open(filepath.Join(dir, "vault.age"), os.Getenv("SM_IDENTITY"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := v.Get("global/NEW"); ok {
		t.Fatal("partial import")
	}
}

func TestInvalidInputsNeverReachVault(t *testing.T) {
	_, p := fixture(t)
	for _, in := range []Input{
		{Name: "BAD=NAME", Value: "test"}, {Name: "SM_IDENTITY", Value: "test"},
		{Name: "EMPTY"}, {Name: "NUL", Value: "abc\x00def"},
		{Name: "BAD_TRANSPORT", Value: "test", Secret: manifest.Secret{Transport: "smoke"}},
	} {
		if err := AddBatch(p, []Input{in}, false); err == nil {
			t.Fatalf("accepted %s", in.Name)
		}
	}
	m, err := manifest.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Secrets) != 0 {
		t.Fatal("invalid input mutated manifest")
	}
}

func TestSameValueImportIdempotentAndRotate(t *testing.T) {
	dir, p := fixture(t)
	for i := 0; i < 2; i++ {
		if err := AddBatch(p, []Input{{Name: "KEY", Value: "old"}}, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := Rotate(t.TempDir(), "KEY", "new"); err != nil {
		t.Fatal(err)
	}
	v, err := vaultfile.Open(filepath.Join(dir, "vault.age"), os.Getenv("SM_IDENTITY"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := v.Get("global/KEY"); got != "new" {
		t.Fatal("rotation failed")
	}
}
