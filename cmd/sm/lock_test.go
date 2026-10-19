package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func withStdin(t *testing.T, input string, fn func() error) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old; r.Close() }()
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(w, input)
		done <- err
		w.Close()
	}()
	callErr := fn()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return callErr
}

func TestGetPrintsValueAndAudits(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	global, _, err := manifest.EnsureGlobal()
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.AddBatch(global, []secrets.Input{{Name: "TOKEN", Value: "known-value-123"}}, false); err != nil {
		t.Fatal(err)
	}
	out, err := captureOutput(t, func() error { return cmdGet([]string{"TOKEN"}) })
	if err != nil {
		t.Fatal(err)
	}
	if out != "known-value-123\n" {
		t.Fatalf("sm get printed %q", out)
	}
	dir, _ := config.Dir()
	entries, err := audit.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == "reveal" && len(entry.Secrets) == 1 && entry.Secrets[0] == "TOKEN" {
			found = true
		}
	}
	if !found {
		t.Fatal("sm get did not record a reveal entry")
	}
	if err := cmdGet([]string{"MISSING"}); err == nil {
		t.Fatal("sm get accepted an undeclared name")
	}
}

func TestLockCLI(t *testing.T) {
	cliFixture(t)

	out, err := captureOutput(t, func() error { return cmdLock([]string{"status"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "no desktop passphrase") {
		t.Fatalf("status before set:\n%s", out)
	}

	if err := withStdin(t, "short\n", func() error { return cmdLock([]string{"set", "--stdin"}) }); err == nil {
		t.Fatal("short passphrase accepted")
	}
	const passphrase = "correct horse battery staple"
	if err := withStdin(t, passphrase+"\n", func() error { return cmdLock([]string{"set", "--stdin"}) }); err != nil {
		t.Fatal(err)
	}

	out, err = captureOutput(t, func() error { return cmdLock([]string{"status"}) })
	if err != nil || !strings.Contains(out, "desktop passphrase is set") {
		t.Fatalf("status after set = %q, %v", out, err)
	}

	if err := withStdin(t, "wrong passphrase\n", func() error {
		return cmdLock([]string{"verify", "--stdin", "--quiet"})
	}); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	out, err = captureOutput(t, func() error {
		return withStdin(t, passphrase+"\n", func() error {
			return cmdLock([]string{"verify", "--stdin", "--quiet"})
		})
	})
	if err != nil || out != "" {
		t.Fatalf("quiet verify = %q, %v", out, err)
	}

	if err := withStdin(t, "another passphrase\n", func() error {
		return cmdLock([]string{"set", "--stdin"})
	}); err == nil {
		t.Fatal("existing passphrase replaced without --force")
	}
	if err := withStdin(t, "another passphrase\n", func() error {
		return cmdLock([]string{"set", "--stdin", "--force"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := withStdin(t, passphrase+"\n", func() error {
		return cmdLock([]string{"verify", "--stdin", "--quiet"})
	}); err == nil {
		t.Fatal("old passphrase still accepted after --force")
	}

	if err := cmdLock([]string{"clear", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if err := withStdin(t, "another passphrase\n", func() error {
		return cmdLock([]string{"verify", "--stdin", "--quiet"})
	}); err == nil {
		t.Fatal("verify succeeded after clear")
	}
}
