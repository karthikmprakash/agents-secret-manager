// Package wireup detects installed agent harnesses and wires the sm MCP
// server into their configuration.
package wireup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/karthikmprakash/agents-secret-manager/internal/agentcfg"
)

// Target is one detected harness and its wiring action.
type Target struct {
	Name   string
	Detail string
	dry    string
	apply  func() (string, error)
	remove func() (string, error)
	status func() string
}

// Apply wires the harness and returns a human-readable status.
func (t Target) Apply() (string, error) { return t.apply() }

// Remove un-wires the harness. It is a no-op when sm is already absent.
func (t Target) Remove() (string, error) {
	if t.remove == nil {
		return "", fmt.Errorf("removing %s is not supported yet", t.Name)
	}
	return t.remove()
}

// DryRun describes what Apply would do.
func (t Target) DryRun() string { return t.dry }

// Status means configuration on disk, not a live client connection.
func (t Target) Status() string {
	if t.status == nil {
		return "unknown"
	}
	return t.status()
}

func configStatus(path, key, name, exe string) string {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "not configured"
	}
	if err != nil {
		return "unreadable"
	}
	var root map[string]any
	if strings.HasSuffix(path, ".yaml") {
		err = yaml.Unmarshal(data, &root)
	} else if strings.HasSuffix(path, ".toml") {
		_, err = toml.Decode(string(data), &root)
	} else {
		root, err = agentcfg.ParseJSONLoose(data)
	}
	if err != nil {
		return "unknown"
	}
	var node any = root
	for _, k := range strings.Split(key, ".") {
		m, ok := node.(map[string]any)
		if !ok {
			return "not configured"
		}
		node = m[k]
	}
	m, _ := node.(map[string]any)
	entry, ok := m[name].(map[string]any)
	if !ok {
		return "not configured"
	}
	if entry["disabled"] == true || entry["enabled"] == false {
		return "disabled"
	}
	command, args := entry["command"], entry["args"]
	if argv, ok := command.([]any); ok {
		if len(argv) != 2 {
			return "different command"
		}
		command = argv[0]
		args = []any{argv[1]}
	}
	argv, ok := args.([]any)
	if command == exe && ok && len(argv) == 1 && argv[0] == "mcp" {
		return "configured"
	}
	return "different command"
}

func yamlMappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// dshMcpEntries collects mappings that mount the DeepSeek MCP client plugin,
// wherever they sit in the patch layer (top level or wrapped in an insert).
func dshMcpEntries(n *yaml.Node, out *[]*yaml.Node) {
	if n.Kind == yaml.MappingNode {
		if name := yamlMappingValue(n, "name"); name != nil && name.Value == "@deepseek-ai/dsh-mcp-client" {
			*out = append(*out, n)
		}
	}
	for _, child := range n.Content {
		dshMcpEntries(child, out)
	}
}

func dshPatchStatus(path, exe string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return "unknown"
	}
	var entries []*yaml.Node
	dshMcpEntries(&root, &entries)
	for _, entry := range entries {
		config := yamlMappingValue(entry, "config")
		if name := yamlMappingValue(config, "serverName"); name == nil || name.Value != "sm" {
			continue
		}
		command := yamlMappingValue(config, "command")
		args := yamlMappingValue(config, "args")
		if command == nil || command.Value != exe || args == nil || len(args.Content) != 1 || args.Content[0].Value != "mcp" {
			return "different command"
		}
		return "configured"
	}
	return "not configured"
}

func dshStatus(patches []string, exe string) string {
	if len(patches) == 0 {
		return "not configured"
	}
	configured, notConfigured := 0, 0
	for _, patch := range patches {
		switch state := dshPatchStatus(patch, exe); state {
		case "configured":
			configured++
		case "not configured":
			notConfigured++
		default:
			return state
		}
	}
	switch {
	case configured == len(patches):
		return "configured"
	case notConfigured == len(patches):
		return "not configured"
	default:
		return "partially configured"
	}
}

// Detect returns installed harnesses. exe is the absolute path to sm.
func Detect(exe, home string) []Target {
	var targets []Target

	runCLI := func(argv []string, detail string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
		msg := strings.TrimSpace(string(out))
		if err != nil {
			_ = msg // CLI errors may contain existing credentials; do not print them.
			return "", fmt.Errorf("configuration command failed; inspect the harness MCP settings")
		}
		return detail + " — configured", nil
	}

	// OpenCode — global config. Prefer the official CLI when it is available,
	// then fall back to a direct JSON/JSONC merge so a GUI PATH or a changed
	// CLI syntax cannot leave the harness unwired.
	opencodeDir := filepath.Join(home, ".config", "opencode")
	opencodeBin := findBin("opencode", home)
	if opencodeBin != "" || dirExists(opencodeDir) {
		opencodeConfig := filepath.Join(opencodeDir, "opencode.json")
		for _, base := range []string{"opencode.json", "opencode.jsonc"} {
			p := filepath.Join(opencodeDir, base)
			if fileExists(p) {
				opencodeConfig = p
				break
			}
		}
		argv := []string{}
		if opencodeBin != "" {
			argv = []string{opencodeBin, "mcp", "add", "--global", "sm", "--", exe, "mcp"}
		}
		dry := "would add sm to " + shortHomePath(home, opencodeConfig)
		if len(argv) > 0 {
			dry = "would run: " + strings.Join(argv, " ") + " (direct config fallback)"
		}
		targets = append(targets, Target{
			Name:   "opencode",
			Detail: "global MCP server",
			dry:    dry,
			status: func() string { return configStatus(opencodeConfig, "mcp.servers", "sm", exe) },
			apply: func() (string, error) {
				if len(argv) > 0 {
					if msg, err := runCLI(argv, `global MCP server "sm"`); err == nil {
						return msg, nil
					}
				}
				entry := map[string]any{"type": "local", "command": []string{exe, "mcp"}, "enabled": true}
				if err := agentcfg.MergeJSONPath(opencodeConfig, []string{"mcp", "servers"}, "sm", entry); err != nil {
					return "", err
				}
				return "global MCP server \"sm\" in " + shortHomePath(home, opencodeConfig) + " (restart OpenCode)", nil
			},
			remove: func() (string, error) {
				if err := agentcfg.RemoveJSONPath(opencodeConfig, []string{"mcp", "servers"}, "sm"); err != nil {
					return "", err
				}
				return "removed sm from " + shortHomePath(home, opencodeConfig), nil
			},
		})
	}

	// Claude Code — user scope. Its config can exist even when the CLI is not
	// on a GUI app's PATH, so detect either.
	claudeConfig := filepath.Join(home, ".claude.json")
	if findBin("claude", home) != "" || fileExists(claudeConfig) {
		targets = append(targets, Target{
			Name:   "claude",
			Detail: "user-scope MCP server",
			dry:    "would add user MCP server to ~/.claude.json",
			status: func() string { return configStatus(claudeConfig, "mcpServers", "sm", exe) },
			apply: func() (string, error) {
				if err := agentcfg.MergeJSONMCPServers(claudeConfig, map[string]any{"command": exe, "args": []string{"mcp"}}); err != nil {
					return "", err
				}
				return "user MCP configuration saved; reconnect or restart Claude Code", nil
			},
			remove: func() (string, error) {
				if err := agentcfg.RemoveJSONMCPServers(claudeConfig); err != nil {
					return "", err
				}
				return "removed sm from ~/.claude.json", nil
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
			status: func() string { return configStatus(hermesCfg, "mcp_servers", "sm", exe) },
			apply: func() (string, error) {
				if err := agentcfg.MergeYAMLMCPServers(hermesCfg, "sm", entry); err != nil {
					return "", err
				}
				return "mcp_servers.sm in ~/.hermes/config.yaml (auto-reloads)", nil
			},
			remove: func() (string, error) {
				if err := agentcfg.RemoveYAMLMCPServers(hermesCfg, "sm"); err != nil {
					return "", err
				}
				return "removed mcp_servers.sm from ~/.hermes/config.yaml", nil
			},
		})
	}

	// Codex (OpenAI desktop app / CLI) — mcp_servers in ~/.codex/config.toml.
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if findBin("codex", home) != "" || fileExists(codexConfig) {
		targets = append(targets, Target{
			Name:   "codex",
			Detail: "~/.codex/config.toml",
			dry:    "would add mcp_servers.sm to ~/.codex/config.toml",
			status: func() string { return configStatus(codexConfig, "mcp_servers", "sm", exe) },
			apply: func() (string, error) {
				entry := map[string]any{"command": exe, "args": []string{"mcp"}}
				if err := agentcfg.MergeTOMLMCPServers(codexConfig, "sm", entry); err != nil {
					return "", err
				}
				return "mcp_servers.sm in ~/.codex/config.toml (restart Codex)", nil
			},
			remove: func() (string, error) {
				if err := agentcfg.RemoveTOMLTable(codexConfig, "mcp_servers.sm"); err != nil {
					return "", err
				}
				return "removed mcp_servers.sm from ~/.codex/config.toml", nil
			},
		})
	}

	// DeepSeek Harness (dsh) — MCP rows go through the profile patch layer:
	// ~/.dsh/profiles/*/cordis.patch.yml, loaded by the desktop app (profile
	// "desktop") and by the CLI (profile "web").
	profilesDir := filepath.Join(home, ".dsh", "profiles")
	var dshPatches, dshProfiles []string
	if entries, err := os.ReadDir(profilesDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			patch := filepath.Join(profilesDir, entry.Name(), "cordis.patch.yml")
			if fileExists(patch) {
				dshProfiles = append(dshProfiles, entry.Name())
				dshPatches = append(dshPatches, patch)
			}
		}
	}
	if len(dshPatches) > 0 || dirExists(profilesDir) ||
		dirExists(filepath.Join("/Applications", "DeepSeek Harness.app")) ||
		dirExists(filepath.Join(home, "Applications", "DeepSeek Harness.app")) {
		detail := "~/.dsh/profiles"
		if len(dshProfiles) == 1 {
			detail = "~/.dsh/profiles/" + dshProfiles[0] + "/cordis.patch.yml"
		} else if len(dshProfiles) > 1 {
			detail = fmt.Sprintf("~/.dsh/profiles (%d profiles)", len(dshProfiles))
		}
		patches := dshPatches
		targets = append(targets, Target{
			Name:   "deepseek",
			Detail: detail,
			dry:    "would add the sm MCP server to the dsh profile patch layer",
			status: func() string { return dshStatus(patches, exe) },
			apply: func() (string, error) {
				if len(patches) == 0 {
					return "", errors.New("no dsh profile exists yet — launch DeepSeek Harness once, then retry")
				}
				block := fmt.Sprintf("# sm:mcp\n- insert:\n    - id: mcp-sm\n      name: \"@deepseek-ai/dsh-mcp-client\"\n      config:\n        serverName: sm\n        transport: stdio\n        command: %q\n        args: [\"mcp\"]\n# /sm:mcp\n", exe)
				for _, patch := range patches {
					if err := agentcfg.UpsertYAMLBlock(patch, "sm:mcp", block); err != nil {
						return "", err
					}
				}
				if len(patches) == 1 {
					return "sm MCP server in " + detail + " (restart DeepSeek Harness)", nil
				}
				return fmt.Sprintf("sm MCP server in %d dsh profiles (restart DeepSeek Harness)", len(patches)), nil
			},
			remove: func() (string, error) {
				if len(patches) == 0 {
					return "", errors.New("no dsh profile exists yet")
				}
				for _, patch := range patches {
					if err := agentcfg.RemoveYAMLBlock(patch, "sm:mcp"); err != nil {
						return "", err
					}
				}
				if len(patches) == 1 {
					return "removed sm from " + detail, nil
				}
				return fmt.Sprintf("removed sm from %d dsh profiles", len(patches)), nil
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
			status: func() string { return configStatus(t.path, "mcpServers", "sm", exe) },
			apply: func() (string, error) {
				entry := map[string]any{"command": exe, "args": []string{"mcp"}}
				if err := agentcfg.MergeJSONMCPServers(t.path, entry); err != nil {
					return "", err
				}
				return "mcpServers.sm in " + t.display, nil
			},
			remove: func() (string, error) {
				if err := agentcfg.RemoveJSONMCPServers(t.path); err != nil {
					return "", err
				}
				return "removed mcpServers.sm from " + t.display, nil
			},
		})
	}

	return targets
}

func shortHomePath(home, path string) string {
	if home != "" && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
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
