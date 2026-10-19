package wireup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenCodeJSONCStatusAndRemove(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "opencode.jsonc")
	original := `{
  // existing provider settings
  "mcp": {
    "servers": {
      "other": { "type": "local" },
      "sm": { "type": "local", "command": ["/old/sm", "mcp"] }
    }
  },
  "theme": "dark"
}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range Detect("/new/sm", home) {
		if target.Name != "opencode" {
			continue
		}
		if got := target.Status(); got != "different command" {
			t.Fatalf("JSONC status = %q, want different command", got)
		}
		msg, err := target.Remove()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(msg, "removed") {
			t.Fatalf("remove message = %q", msg)
		}
		if got := target.Status(); got != "not configured" {
			t.Fatalf("status after remove = %q", got)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"sm"`) {
			t.Fatalf("sm entry survived removal:\n%s", data)
		}
		if !strings.Contains(string(data), `"other"`) || !strings.Contains(string(data), `"theme"`) {
			t.Fatalf("unrelated config was lost:\n%s", data)
		}
		return
	}
	t.Fatal("opencode not detected")
}

func TestApplyThenRemoveForEveryDetectedTarget(t *testing.T) {
	home := t.TempDir()
	mkdir := func(parts ...string) string {
		path := filepath.Join(append([]string{home}, parts...)...)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write := func(path, body string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mkdir(".cursor")
	write(filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"other":{"command":"/bin/other","args":["mcp"]}}}`)
	write(filepath.Join(home, ".claude.json"), `{"mcpServers":{}}`)
	mkdir(".codex")
	write(filepath.Join(home, ".codex", "config.toml"), "model = \"gpt\"\n")
	mkdir(".hermes")
	write(filepath.Join(home, ".hermes", "config.yaml"), "model: hermes\n")
	mkdir(".dsh", "profiles", "desktop")
	write(filepath.Join(home, ".dsh", "profiles", "desktop", "cordis.patch.yml"), "# patch\n- id: llm\n")
	mkdir(".gemini")
	write(filepath.Join(home, ".gemini", "settings.json"), `{}`)
	mkdir(".codeium", "windsurf")
	write(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{}`)
	mkdir("Library", "Application Support", "Claude")
	write(filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), `{}`)

	targets := Detect("/bin/sm", home)
	if len(targets) == 0 {
		t.Fatal("no targets detected")
	}
	for _, target := range targets {
		if target.Name == "opencode" {
			continue // its Apply prefers a real opencode binary; covered above
		}
		if got := target.Status(); got != "not configured" {
			t.Fatalf("%s initial status = %q", target.Name, got)
		}
		if _, err := target.Apply(); err != nil {
			t.Fatalf("%s apply: %v", target.Name, err)
		}
		if got := target.Status(); got != "configured" {
			t.Fatalf("%s status after apply = %q", target.Name, got)
		}
		if _, err := target.Remove(); err != nil {
			t.Fatalf("%s remove: %v", target.Name, err)
		}
		if got := target.Status(); got != "not configured" {
			t.Fatalf("%s status after remove = %q", target.Name, got)
		}
	}
}
