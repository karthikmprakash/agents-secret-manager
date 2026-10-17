package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/agentcfg"
)

// agentTarget is one harness that sm can wire the MCP server into.
type agentTarget struct {
	name  string
	dry   string
	apply func() (string, error)
}

// detectTargets finds installed agents and returns a wiring action for each.
func detectTargets(exe, home string) []agentTarget {
	var targets []agentTarget

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
		targets = append(targets, agentTarget{
			name: "opencode",
			dry:  "would run: " + strings.Join(argv, " "),
			apply: func() (string, error) {
				return runCLI(argv, `global MCP server "sm"`)
			},
		})
	}

	// Claude Code — user scope, via its own CLI.
	if claude := findBin("claude", home); claude != "" {
		argv := []string{claude, "mcp", "add", "-s", "user", "sm", "--", exe, "mcp"}
		targets = append(targets, agentTarget{
			name: "claude",
			dry:  "would run: " + strings.Join(argv, " "),
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
		targets = append(targets, agentTarget{
			name: "hermes",
			dry:  "would add mcp_servers.sm to ~/.hermes/config.yaml",
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
		display string
	}{
		{"cursor", filepath.Join(home, ".cursor", "mcp.json"), "~/.cursor/mcp.json"},
		{"claude-desktop", filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "~/Library/Application Support/Claude/claude_desktop_config.json"},
		{"gemini", filepath.Join(home, ".gemini", "settings.json"), "~/.gemini/settings.json"},
		{"windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "~/.codeium/windsurf/mcp_config.json"},
	}
	for _, t := range jsonTargets {
		if !dirExists(filepath.Dir(t.path)) {
			continue
		}
		t := t
		targets = append(targets, agentTarget{
			name: t.name,
			dry:  "would add mcpServers.sm to " + t.display,
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

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("sm setup", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "show what would be configured without changing anything")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm setup [--dry-run]")
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	targets := detectTargets(exe, home)
	fmt.Printf("sm setup — %d target(s)\n\n", len(targets))
	failed := 0
	for _, t := range targets {
		if *dryRun {
			fmt.Printf("  ok  %-14s %s\n", t.name, t.dry)
			continue
		}
		status, err := t.apply()
		if err != nil {
			fmt.Printf("  !!  %-14s error: %v\n", t.name, err)
			failed++
			continue
		}
		fmt.Printf("  ok  %-14s %s\n", t.name, status)
	}
	if len(targets) == 0 {
		fmt.Println("  no supported agents detected")
	}
	if *dryRun {
		fmt.Println("\n(dry run — nothing changed)")
	}
	fmt.Println("\nrestart the apps so they load the server; agents get secret_list / secret_run.")
	fmt.Println("add secrets once with: sm add --global AWS_ACCESS_KEY_ID")
	if failed > 0 {
		return fmt.Errorf("%d target(s) failed", failed)
	}
	return nil
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
