package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	callErr := fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = old
	return string(out), callErr
}

func TestStatusBeforeAndAfterInit(t *testing.T) {
	cliFixture(t)

	out, err := captureOutput(t, func() error { return cmdStatus(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not initialized") || !strings.Contains(out, "sm onboard") {
		t.Fatalf("uninitialized status missing guidance:\n%s", out)
	}

	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	out, err = captureOutput(t, func() error { return cmdStatus(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "✓") || !strings.Contains(out, "secrets") || !strings.Contains(out, "agents") {
		t.Fatalf("status dashboard missing sections:\n%s", out)
	}
}

func TestAgentsCommandRenders(t *testing.T) {
	cliFixture(t)
	out, err := captureOutput(t, func() error { return cmdAgents(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "configuration on disk") {
		t.Fatalf("agents output missing explanation:\n%s", out)
	}
}

func TestCompletionScriptsMentionCommands(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		out, err := captureOutput(t, func() error { return cmdCompletion([]string{shell}) })
		if err != nil {
			t.Fatalf("%s: %v", shell, err)
		}
		if !strings.Contains(out, "sm") || !strings.Contains(out, "onboard") || !strings.Contains(out, "status") {
			t.Fatalf("%s completion missing commands:\n%s", shell, out)
		}
	}
	if err := cmdCompletion([]string{"powershell"}); err == nil {
		t.Fatal("unknown shell accepted")
	}
}

func TestAddGroupAndConfigAliases(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	err := cmdAdd([]string{"DEMO_BASE_URL", "--global", "--group", "demo", "--config", "--generate", "hex/16"})
	if err != nil {
		t.Fatal(err)
	}
	path, _ := manifest.GlobalPath()
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := m.Secrets["DEMO_BASE_URL"]
	if !ok {
		t.Fatal("secret not declared")
	}
	if secret.Service != "demo" {
		t.Fatalf("group alias not applied: %q", secret.Service)
	}
	if secret.IsSensitive() {
		t.Fatal("--config did not mark the value as plain config")
	}
}

func TestAddAcceptsFlagsAroundName(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	err := cmdAdd([]string{"--global", "INTERSPERSED", "--generate", "hex/16", "--group", "demo", "--config"})
	if err != nil {
		t.Fatal(err)
	}
	path, _ := manifest.GlobalPath()
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := m.Secrets["INTERSPERSED"]
	if !ok {
		t.Fatal("flags after the name were not parsed")
	}
	if secret.Service != "demo" || secret.IsSensitive() {
		t.Fatalf("unexpected metadata: %+v", secret)
	}
}

func TestEnvShowConfigOnlyPrintsConfig(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	global, _, err := manifest.EnsureGlobal()
	if err != nil {
		t.Fatal(err)
	}
	no := false
	if err := secrets.AddBatch(global, []secrets.Input{
		{Name: "DEMO_URL", Value: "https://demo.example.org", Secret: manifest.Secret{Sensitive: &no}},
		{Name: "DEMO_TOKEN", Value: "demo-secret-123456"},
	}, false); err != nil {
		t.Fatal(err)
	}
	out, err := captureOutput(t, func() error { return cmdEnv([]string{"--show-config"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "https://demo.example.org") {
		t.Fatalf("config value missing from --show-config:\n%s", out)
	}
	if strings.Contains(out, "demo-secret-123456") {
		t.Fatalf("sensitive value leaked into --show-config:\n%s", out)
	}
	out, err = captureOutput(t, func() error { return cmdEnv(nil) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "https://demo.example.org") {
		t.Fatalf("config value printed without --show-config:\n%s", out)
	}
}

func TestEnvVerboseRenders(t *testing.T) {
	cliFixture(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := cmdAdd([]string{"TOKEN", "--global", "--generate", "hex/16"}); err != nil {
		t.Fatal(err)
	}
	out, err := captureOutput(t, func() error { return cmdEnv([]string{"--verbose"}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "TOKEN") || !strings.Contains(out, "vault://") || !strings.Contains(out, "present") {
		t.Fatalf("verbose env output incomplete:\n%s", out)
	}
}
