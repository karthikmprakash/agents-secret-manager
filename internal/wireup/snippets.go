package wireup

import (
	"encoding/json"
	"fmt"
)

// Snippet is a copy-pasteable MCP client configuration for one or more
// harnesses that share a config shape, for manual wiring where sm does not
// (or cannot) write the file itself.
type Snippet struct {
	Agents []string `json:"agents"`
	Files  []string `json:"files"`
	Lang   string   `json:"lang"`
	Body   string   `json:"body"`
}

// Snippets returns manual-wiring snippets for the sm binary at exe.
func Snippets(exe string) []Snippet {
	jsonBody := func(v any) string {
		b, _ := json.MarshalIndent(v, "", "  ")
		return string(b)
	}
	return []Snippet{
		{
			Agents: []string{"claude", "claude-desktop", "cursor", "gemini", "windsurf"},
			Files: []string{
				"~/.claude.json (Claude Code, user scope)",
				"~/Library/Application Support/Claude/claude_desktop_config.json",
				"~/.cursor/mcp.json",
				"~/.gemini/settings.json",
				"~/.codeium/windsurf/mcp_config.json",
			},
			Lang: "json",
			Body: jsonBody(map[string]any{
				"mcpServers": map[string]any{
					"sm": map[string]any{"command": exe, "args": []string{"mcp"}},
				},
			}),
		},
		{
			Agents: []string{"opencode"},
			Files:  []string{"~/.config/opencode/opencode.json"},
			Lang:   "json",
			Body: jsonBody(map[string]any{
				"mcp": map[string]any{
					"servers": map[string]any{
						"sm": map[string]any{"type": "local", "command": []string{exe, "mcp"}},
					},
				},
			}),
		},
		{
			Agents: []string{"codex"},
			Files:  []string{"~/.codex/config.toml"},
			Lang:   "toml",
			Body:   fmt.Sprintf("[mcp_servers.sm]\ncommand = %q\nargs = [\"mcp\"]\n", exe),
		},
		{
			Agents: []string{"hermes"},
			Files:  []string{"~/.hermes/config.yaml"},
			Lang:   "yaml",
			Body:   fmt.Sprintf("mcp_servers:\n  sm:\n    command: %q\n    args: [mcp]\n", exe),
		},
		{
			Agents: []string{"deepseek"},
			Files:  []string{"~/.dsh/profiles/<profile>/cordis.patch.yml (patch layer)"},
			Lang:   "yaml",
			Body:   fmt.Sprintf("- insert:\n    - id: mcp-sm\n      name: \"@deepseek-ai/dsh-mcp-client\"\n      config:\n        serverName: sm\n        transport: stdio\n        command: %q\n        args: [\"mcp\"]\n", exe),
		},
		{
			Agents: []string{"any other MCP client"},
			Files:  []string{"stdio transport"},
			Lang:   "text",
			Body:   fmt.Sprintf("command: %s\nargs: [\"mcp\"]\ntransport: stdio", exe),
		},
	}
}
