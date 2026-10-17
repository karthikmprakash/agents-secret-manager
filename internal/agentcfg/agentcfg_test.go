package agentcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
