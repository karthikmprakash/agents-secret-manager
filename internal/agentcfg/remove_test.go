package agentcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseJSONLooseAcceptsJSONC(t *testing.T) {
	root, err := ParseJSONLoose([]byte(`{
  // leading comment
  "mcp": { "servers": { "sm": { "type": "local" } } }, /* trailing */
  "url": "https://example.org/a//b"
}`))
	if err != nil {
		t.Fatal(err)
	}
	if root["url"] != "https://example.org/a//b" {
		t.Fatalf("comment stripping damaged a string: %#v", root["url"])
	}
	if _, ok := root["mcp"]; !ok {
		t.Fatal("mcp object missing")
	}
}

func TestMergeAndRemoveJSONPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencode.jsonc")
	original := `{
  // keep this entry
  "mcp": { "servers": { "other": { "type": "local" } } },
  "theme": "dark"
}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := map[string]any{"type": "local", "command": []string{"/bin/sm", "mcp"}}
	if err := MergeJSONPath(path, []string{"mcp", "servers"}, "sm", entry); err != nil {
		t.Fatal(err)
	}
	root, err := ParseJSONLoose(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	servers := root["mcp"].(map[string]any)["servers"].(map[string]any)
	if _, ok := servers["sm"]; !ok {
		t.Fatal("sm entry missing after merge")
	}
	if _, ok := servers["other"]; !ok {
		t.Fatal("unrelated entry was lost")
	}
	if root["theme"] != "dark" {
		t.Fatal("unrelated key was lost")
	}
	if _, err := os.Stat(path + ".sm-backup"); err != nil {
		t.Fatal("backup was not created")
	}

	if err := RemoveJSONPath(path, []string{"mcp", "servers"}, "sm"); err != nil {
		t.Fatal(err)
	}
	root, err = ParseJSONLoose(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	servers = root["mcp"].(map[string]any)["servers"].(map[string]any)
	if _, ok := servers["sm"]; ok {
		t.Fatal("sm entry still present after removal")
	}
	if _, ok := servers["other"]; !ok {
		t.Fatal("removal lost an unrelated entry")
	}
	if err := RemoveJSONPath(path, []string{"mcp", "servers"}, "sm"); err != nil {
		t.Fatalf("removing a missing entry should be a no-op: %v", err)
	}
}

func TestRemoveYAMLMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := "model: hermes\nmcp_servers:\n  sm:\n    command: /bin/sm\n    args: [mcp]\n  other:\n    command: /bin/other\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveYAMLMCPServers(path, "sm"); err != nil {
		t.Fatal(err)
	}
	data := string(mustRead(t, path))
	if strings.Contains(data, "sm:") {
		t.Fatalf("sm entry still present:\n%s", data)
	}
	if !strings.Contains(data, "other:") || !strings.Contains(data, "model: hermes") {
		t.Fatalf("unrelated YAML was lost:\n%s", data)
	}
}

func TestRemoveTOMLTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	original := "model = \"gpt\"\n\n[mcp_servers.sm]\ncommand = \"/bin/sm\"\nargs = [\"mcp\"]\n\n[mcp_servers.other]\ncommand = \"/bin/other\"\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTOMLTable(path, "mcp_servers.sm"); err != nil {
		t.Fatal(err)
	}
	data := string(mustRead(t, path))
	if strings.Contains(data, "mcp_servers.sm") {
		t.Fatalf("sm table still present:\n%s", data)
	}
	if !strings.Contains(data, "mcp_servers.other") || !strings.Contains(data, "model = \"gpt\"") {
		t.Fatalf("unrelated TOML was lost:\n%s", data)
	}
}

func TestRemoveYAMLBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cordis.patch.yml")
	original := "# patch layer\n- id: llm\n  name: \"@deepseek-ai/dsh-llm-pi-ai\"\n\n# sm:mcp\n- insert:\n    - id: mcp-sm\n# /sm:mcp\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveYAMLBlock(path, "sm:mcp"); err != nil {
		t.Fatal(err)
	}
	data := string(mustRead(t, path))
	if strings.Contains(data, "sm:mcp") || strings.Contains(data, "mcp-sm") {
		t.Fatalf("sm block still present:\n%s", data)
	}
	if !strings.Contains(data, "dsh-llm-pi-ai") {
		t.Fatalf("unrelated YAML was lost:\n%s", data)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
