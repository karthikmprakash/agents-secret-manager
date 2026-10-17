package wireup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusReflectsDiskNotSessionMemory(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"mcpServers":{"sm":{"command":"/old/sm","args":["mcp"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range Detect("/new/sm", home) {
		if target.Name != "cursor" {
			continue
		}
		if target.Status() != "different command" {
			t.Fatal("stale command reported configured")
		}
		if _, err := target.Apply(); err != nil {
			t.Fatal(err)
		}
		if target.Status() != "configured" {
			t.Fatal("new config not recognized")
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if target.Status() != "not configured" {
			t.Fatal("configuration status cached")
		}
		return
	}
	t.Fatal("cursor not detected")
}

func TestCodexStatusAndApply(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[mcp_servers.sm]\ncommand = \"/old/sm\"\nargs = [\"mcp\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range Detect("/new/sm", home) {
		if target.Name != "codex" {
			continue
		}
		if target.Status() != "different command" {
			t.Fatalf("status = %q", target.Status())
		}
		if _, err := target.Apply(); err != nil {
			t.Fatal(err)
		}
		if target.Status() != "configured" {
			t.Fatalf("status after apply = %q", target.Status())
		}
		return
	}
	t.Fatal("codex not detected")
}

func TestDeepSeekStatusAndApply(t *testing.T) {
	home := t.TempDir()
	desktop := filepath.Join(home, ".dsh", "profiles", "desktop")
	web := filepath.Join(home, ".dsh", "profiles", "web")
	for _, dir := range []string{desktop, web} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	patch := filepath.Join(desktop, "cordis.patch.yml")
	original := "# patch layer\n- id: llm\n  name: \"@deepseek-ai/dsh-llm-pi-ai\"\n  config:\n    key: !!js process.env.DEEPSEEK_API_KEY\n"
	if err := os.WriteFile(patch, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	webPatch := filepath.Join(web, "cordis.patch.yml")
	if err := os.WriteFile(webPatch, []byte("# patch layer\n[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range Detect("/new/sm", home) {
		if target.Name != "deepseek" {
			continue
		}
		if got := target.Status(); got != "not configured" {
			t.Fatalf("status = %q", got)
		}
		if _, err := target.Apply(); err != nil {
			t.Fatal(err)
		}
		if got := target.Status(); got != "configured" {
			t.Fatalf("status after apply = %q", got)
		}
		for _, p := range []string{patch, webPatch} {
			data, _ := os.ReadFile(p)
			if !strings.Contains(string(data), "@deepseek-ai/dsh-mcp-client") {
				t.Errorf("%s missing the inserted row", p)
			}
		}
		data, _ := os.ReadFile(patch)
		if !strings.Contains(string(data), "!!js process.env.DEEPSEEK_API_KEY") {
			t.Error("existing !!js config was not preserved")
		}
		if _, err := target.Apply(); err != nil {
			t.Fatal(err)
		}
		data, _ = os.ReadFile(patch)
		if strings.Count(string(data), "# sm:mcp") != 1 {
			t.Fatalf("duplicate block:\n%s", data)
		}
		stale := strings.Replace(string(data), "/new/sm", "/old/sm", 1)
		if err := os.WriteFile(patch, []byte(stale), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := target.Status(); got != "different command" {
			t.Fatalf("stale status = %q", got)
		}
		if _, err := target.Apply(); err != nil {
			t.Fatal(err)
		}
		if got := target.Status(); got != "configured" {
			t.Fatalf("status after re-apply = %q", got)
		}
		return
	}
	t.Fatal("deepseek not detected")
}
