// Package wireup detects installed agent harnesses and wires the sm MCP
// server into their configuration.
package wireup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/agentcfg"
)

// Target is one detected harness and its wiring action.
type Target struct {
	Name   string
	Detail string
	dry    string
	apply  func() (string, error)
}

// Apply wires the harness and returns a human-readable status.
func (t Target) Apply() (string, error) { return t.apply() }

// DryRun describes what Apply would do.
func (t Target) DryRun() string { return t.dry }

// Detect returns installed harnesses. exe is the absolute path to sm.
func Detect(exe, home string) []Target {
	var targets []Target

	runCLI := func(argv []string, detail string) (string, error) {
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		msg := strings.TrimSpace(string(out))
		if err != nil {
			if strings.Contains(strings.ToLower(msg), "already") {
				return detail + " — already configured", nil
			}
			return "", fmt.Errorf("%v: %s", err, msg)
		}
		return detail + " — configured", nil
	}

	// OpenCode — global config, via its own CLI (preserves unrelated config).
	opencode := findBin("opencode", home)
	if opencode != "" || dirExists(filepath.Join(home, ".config", "opencode")) {
		if opencode == "" {
			opencode = "opencode"
		}
		argv := []string{opencode, "mcp", "add", "--global", "sm", "--", exe, "mcp"}
		targets = append(targets, Target{
			Name:   "opencode",
			Detail: "global MCP server",
			dry:    "would run: " + strings.Join(argv, " "),
			apply: func() (string, error) {
				return runCLI(argv, `global MCP server "sm"`)
			},
		})
	}

	// Claude Code — user scope, via its own CLI.
	if claude := findBin("claude", home); claude != "" {
		argv := []string{claude, "mcp", "add", "-s", "user", "sm", "--", exe, "mcp"}
		targets = append(targets, Target{
			Name:   "claude",
			Detail: "user-scope MCP server",
			dry:    "would run: " + strings.Join(argv, " "),
			apply: func() (string, error) {
				return runCLI(argv, `user-scope MCP server "sm"`)
			},
		})
	}

	// Hermes — mcp_servers in ~/.hermes/config.yaml (auto-reloads on change).
	hermesCfg := filepath.Join(home, ".hermes", "config.yaml")
	if fileExists(hermesCfg) {
		entry := map[string]any{
			"command":         exe,
			"args":            []string{"mcp"},
			"enabled":         true,
			"connect_timeout": 60.0,
		}
		targets = append(targets, Target{
			Name:   "hermes",
			Detail: "~/.hermes/config.yaml",
			dry:    "would add mcp_servers.sm to ~/.hermes/config.yaml",
			apply: func() (string, error) {
				if err := agentcfg.MergeYAMLMCPServers(hermesCfg, "sm", entry); err != nil {
					return "", err
				}
				return "mcp_servers.sm in ~/.hermes/config.yaml (auto-reloads)", nil
			},
		})
	}

	// JSON-config clients.
	jsonTargets := []struct {
		name    string
		path    string
		detail  string
		display string
	}{
		{"cursor", filepath.Join(home, ".cursor", "mcp.json"), "~/.cursor/mcp.json", "~/.cursor/mcp.json"},
		{"claude-desktop", filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "Claude Desktop config", "~/Library/Application Support/Claude/claude_desktop_config.json"},
		{"gemini", filepath.Join(home, ".gemini", "settings.json"), "~/.gemini/settings.json", "~/.gemini/settings.json"},
		{"windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "Windsurf config", "~/.codeium/windsurf/mcp_config.json"},
	}
	for _, t := range jsonTargets {
		if !dirExists(filepath.Dir(t.path)) {
			continue
		}
		t := t
		targets = append(targets, Target{
			Name:   t.name,
			Detail: t.detail,
			dry:    "would add mcpServers.sm to " + t.display,
			apply: func() (string, error) {
				entry := map[string]any{"command": exe, "args": []string{"mcp"}}
				if err := agentcfg.MergeJSONMCPServers(t.path, entry); err != nil {
					return "", err
				}
				return "mcpServers.sm in " + t.display, nil
			},
		})
	}

	return targets
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// findBin resolves a tool even when the caller has a minimal PATH (GUI apps).
func findBin(name, home string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".local", "bin")} {
		p := filepath.Join(dir, name)
		if fileExists(p) {
			return p
		}
	}
	return ""
}
