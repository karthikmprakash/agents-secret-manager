package agentcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

func TestMergeJSONMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	original := `{
  "mcpServers": {
    "other": {"command": "other-binary"}
  },
  "keep": true
}
`
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	entry := map[string]any{"command": "/usr/local/bin/sm", "args": []string{"mcp"}}
	if err := MergeJSONMCPServers(path, entry); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if root["keep"] != true {
		t.Error("unrelated key was lost")
	}
	servers := root["mcpServers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Error("existing server was lost")
	}
	sm, ok := servers["sm"].(map[string]any)
	if !ok || sm["command"] != "/usr/local/bin/sm" {
		t.Errorf("sm entry = %+v", servers["sm"])
	}

	if _, err := os.Stat(path + ".sm-backup"); err != nil {
		t.Error("backup missing")
	}

	// Idempotent.
	if err := MergeJSONMCPServers(path, entry); err != nil {
		t.Fatal(err)
	}
}

func TestMergeYAMLMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := `# hermes config
mcp_servers:
  other:
    command: other-binary
    enabled: true
platform_toolsets:
  cli:
    - hermes-cli
`
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	entry := map[string]any{
		"command":         "/usr/local/bin/sm",
		"args":            []string{"mcp"},
		"enabled":         true,
		"connect_timeout": 60.0,
	}
	if err := MergeYAMLMCPServers(path, "sm", entry); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# hermes config") {
		t.Error("comment was lost")
	}

	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	servers := root["mcp_servers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Error("existing server was lost")
	}
	sm, ok := servers["sm"].(map[string]any)
	if !ok || sm["command"] != "/usr/local/bin/sm" {
		t.Errorf("sm entry = %+v", servers["sm"])
	}
	if _, ok := root["platform_toolsets"]; !ok {
		t.Error("unrelated section was lost")
	}

	if _, err := os.Stat(path + ".sm-backup"); err != nil {
		t.Error("backup missing")
	}

	// Idempotent: replace, not duplicate.
	if err := MergeYAMLMCPServers(path, "sm", entry); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Count(string(data), "sm:") != 1 {
		t.Errorf("duplicate sm entry:\n%s", data)
	}
}

func TestMergeTOMLMCPServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	original := "# codex config\nmodel = \"gpt\"\n\n[desktop]\nfollowUpQueueMode = \"steer\"\n\n[mcp_servers.other]\ncommand = \"other\"\n\n[plugins.browser]\nenabled = true\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	entry := map[string]any{"command": "/new/sm", "args": []string{"mcp"}}
	if err := MergeTOMLMCPServers(path, "sm", entry); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# codex config") {
		t.Error("comment lost")
	}
	var root map[string]any
	if _, err := toml.Decode(string(data), &root); err != nil {
		t.Fatal(err)
	}
	servers, _ := root["mcp_servers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Error("existing server lost")
	}
	if sm, ok := servers["sm"].(map[string]any); !ok || sm["command"] != "/new/sm" {
		t.Errorf("sm entry = %+v", servers["sm"])
	}
	if _, ok := root["plugins"]; !ok {
		t.Error("later tables lost")
	}
	if err := MergeTOMLMCPServers(path, "sm", map[string]any{"command": "/moved/sm", "args": []string{"mcp"}}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Count(string(data), "[mcp_servers.sm]") != 1 {
		t.Errorf("duplicate sm table:\n%s", data)
	}
	if !strings.Contains(string(data), "/moved/sm") {
		t.Error("existing table was not replaced")
	}
	if _, err := os.Stat(path + ".sm-backup"); err != nil {
		t.Error("backup missing")
	}
}

func TestUpsertYAMLBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cordis.patch.yml")
	original := "# comment line\n[]\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	block := "# sm:mcp\n- insert:\n    - id: a\n      name: \"@deepseek-ai/dsh-mcp-client\"\n# /sm:mcp\n"
	if err := UpsertYAMLBlock(path, "sm:mcp", block); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# comment line") {
		t.Error("comment lost")
	}
	if strings.Contains(string(data), "\n[]") {
		t.Errorf("empty list not replaced:\n%s", data)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("result is not valid YAML: %v", err)
	}
	block2 := "# sm:mcp\n- insert:\n    - id: b\n      name: \"@deepseek-ai/dsh-mcp-client\"\n# /sm:mcp\n"
	if err := UpsertYAMLBlock(path, "sm:mcp", block2); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "id: a") || !strings.Contains(string(data), "id: b") {
		t.Errorf("block not replaced:\n%s", data)
	}
	if strings.Count(string(data), "# sm:mcp") != 1 {
		t.Errorf("duplicate markers:\n%s", data)
	}
	broken := filepath.Join(dir, "broken.yml")
	if err := os.WriteFile(broken, []byte("# sm:mcp\n- 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UpsertYAMLBlock(broken, "sm:mcp", block); err == nil {
		t.Error("expected error for an unterminated block")
	}
}
