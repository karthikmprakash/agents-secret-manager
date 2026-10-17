package vaultfile

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func newIdentity(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.age")
	ident := newIdentity(t)

	v, err := Open(path, ident)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("dev/a", "one"); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("dev/b", "two"); err != nil {
		t.Fatal(err)
	}

	v2, err := Open(path, ident)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := v2.Get("dev/a")
	if err != nil || !ok || got != "one" {
		t.Fatalf("Get(dev/a) = %q, %v, %v", got, ok, err)
	}
	keys, err := v2.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "dev/a" || keys[1] != "dev/b" {
		t.Fatalf("List = %v", keys)
	}
}

func TestWrongIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.age")
	v, err := Open(path, newIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, newIdentity(t)); err == nil {
		t.Fatal("expected decrypt error with a different identity")
	}
}

func TestFilePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.age")
	v, err := Open(path, newIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
}
