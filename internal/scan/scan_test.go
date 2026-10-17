package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunFindsValuesAndPlaintextNames(t *testing.T) {
	proj := t.TempDir()
	home := t.TempDir()

	write(t, filepath.Join(proj, ".env"), "GITHUB_TOKEN=gh-secret-1\nOTHER=plain\n")
	write(t, filepath.Join(home, ".zshrc"), "export GITHUB_TOKEN=gh-secret-1\nexport STRIPE_KEY=pk-different\n")
	write(t, filepath.Join(home, ".claude", "projects", "p", "s.jsonl"), `{"text":"token gh-secret-1"}`+"\n")
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"env":{"K":"gh-secret-1"}}`+"\n")

	res := Run(
		Options{ProjectDir: proj, HomeDir: home, NoHistory: true},
		[]Secret{{Value: "gh-secret-1", Name: "GITHUB_TOKEN"}},
		[]string{"GITHUB_TOKEN", "STRIPE_KEY"},
	)

	if len(res.Findings) < 5 {
		t.Fatalf("findings = %d, want at least 5: %+v", len(res.Findings), res.Findings)
	}
	kinds := map[string]int{}
	for _, f := range res.Findings {
		kinds[f.Kind]++
		if f.Kind == "value" && f.Snippet == "" {
			t.Error("value finding without redacted snippet")
		}
		if f.Kind == "value" && f.Snippet != "" && strings.Contains(f.Snippet, "gh-secret-1") {
			t.Errorf("snippet leaks the value: %q", f.Snippet)
		}
	}
	if kinds["value"] == 0 || kinds["plaintext"] == 0 {
		t.Errorf("kinds = %v", kinds)
	}
}

func TestRunClean(t *testing.T) {
	proj := t.TempDir()
	home := t.TempDir()
	write(t, filepath.Join(proj, ".env"), "GITHUB_TOKEN=sm://GITHUB_TOKEN\n")
	write(t, filepath.Join(home, ".zshrc"), "export PATH=/usr/bin\n")

	res := Run(
		Options{ProjectDir: proj, HomeDir: home, NoHistory: true},
		[]Secret{{Value: "gh-secret-1", Name: "GITHUB_TOKEN"}},
		[]string{"GITHUB_TOKEN"},
	)
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Scanned == 0 {
		t.Error("expected files to be scanned")
	}
}
