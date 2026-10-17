package main

import (
	"errors"
	"filippo.io/age"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
	"os"
	"path/filepath"
	"testing"
)

func cliFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", filepath.Join(dir, "config"))
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())
	t.Chdir(dir)
	return dir
}

func TestImportDryRunDoesNotWrite(t *testing.T) {
	dir := cliFixture(t)
	if err := os.WriteFile("creds.env", []byte("TOKEN=test-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdImport([]string{"--global", "--file", "creds.env", "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config", "manifest.toml")); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote manifest")
	}
	data, _ := os.ReadFile("creds.env")
	if string(data) != "TOKEN=test-value\n" {
		t.Fatal("dry-run changed source")
	}
}

func TestImportConflictPreservesSource(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	p, _, _ := manifest.EnsureGlobal()
	if err := secrets.AddBatch(p, []secrets.Input{{Name: "TOKEN", Value: "stored"}}, false); err != nil {
		t.Fatal(err)
	}
	original := "TOKEN=different\nNEW=other\n"
	if err := os.WriteFile("creds.env", []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdImport([]string{"--global", "--file", "creds.env", "--all"}); err == nil {
		t.Fatal("conflicting import succeeded")
	}
	data, _ := os.ReadFile("creds.env")
	if string(data) != original {
		t.Fatal("source lost a differing value")
	}
}

func TestExecDoesNotPassMasterKeyAndReturnsExitCode(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := cmdAdd([]string{"TOKEN", "--global", "--generate", "hex/32"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdExec([]string{"--", "/bin/sh", "-c", `test -z "$SM_IDENTITY" && test -n "$TOKEN"`}); err != nil {
		t.Fatal(err)
	}
	err := cmdExec([]string{"--", "/bin/sh", "-c", "exit 7"})
	var exit *exitCodeError
	if !errors.As(err, &exit) || exit.code != 7 {
		t.Fatalf("exit propagation: %v", err)
	}
}

func TestInvalidTransportAddDoesNotDeclare(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := cmdAdd([]string{"TOKEN", "--global", "--generate", "hex/32", "--transport", "typo"}); err == nil {
		t.Fatal("invalid transport accepted")
	}
	p, _ := manifest.GlobalPath()
	m, err := manifest.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Secrets) != 0 {
		t.Fatal("invalid add broke manifest")
	}
}
