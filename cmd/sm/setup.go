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

// cmdSetup detects installed agent harnesses and wires the sm MCP server into
// each one. Idempotent: existing entries are replaced where the config format
// allows it, and "already configured" is not an error.
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

	type result struct {
		name   string
		status string
		failed bool
	}
	var results []result
	add := func(name, status string, failed bool) {
		results = append(results, result{name: name, status: status, failed: failed})
	}

	runCLI := func(argv []string) (string, error) {
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		msg := strings.TrimSpace(string(out))
		if err != nil {
			if strings.Contains(strings.ToLower(msg), "already") {
				return "already configured", nil
			}
			return "", fmt.Errorf("%v: %s", err, msg)
		}
		return "configured", nil
	}

	// OpenCode — global config, via its own CLI (preserves unrelated config).
	if _, err := exec.LookPath("opencode"); err == nil || dirExists(filepath.Join(home, ".config", "opencode")) {
		argv := []string{"opencode", "mcp", "add", "--global", "sm", "--", exe, "mcp"}
		if *dryRun {
			add("opencode", "would run: "+strings.Join(argv, " "), false)
		} else if status, err := runCLI(argv); err != nil {
			add("opencode", "error: "+err.Error(), true)
		} else {
			add("opencode", `global MCP server "sm" — `+status, false)
		}
	}

	// Claude Code — user scope, via its own CLI.
	if _, err := exec.LookPath("claude"); err == nil {
		argv := []string{"claude", "mcp", "add", "-s", "user", "sm", "--", exe, "mcp"}
		if *dryRun {
			add("claude", "would run: "+strings.Join(argv, " "), false)
		} else if status, err := runCLI(argv); err != nil {
			add("claude", "error: "+err.Error(), true)
		} else {
			add("claude", "user-scope MCP server \"sm\" — "+status, false)
		}
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
		if *dryRun {
			add("hermes", "would add mcp_servers.sm to ~/.hermes/config.yaml", false)
		} else if err := agentcfg.MergeYAMLMCPServers(hermesCfg, "sm", entry); err != nil {
			add("hermes", "error: "+err.Error(), true)
		} else {
			add("hermes", "mcp_servers.sm in ~/.hermes/config.yaml (auto-reloads)", false)
		}
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
		if *dryRun {
			add(t.name, "would add mcpServers.sm to "+t.display, false)
			continue
		}
		entry := map[string]any{"command": exe, "args": []string{"mcp"}}
		if err := agentcfg.MergeJSONMCPServers(t.path, entry); err != nil {
			add(t.name, "error: "+err.Error(), true)
		} else {
			add(t.name, "mcpServers.sm in "+t.display, false)
		}
	}

	fmt.Printf("sm setup — %d target(s)\n\n", len(results))
	failed := 0
	for _, r := range results {
		mark := "ok"
		if r.failed {
			mark = "!!"
			failed++
		}
		fmt.Printf("  %s  %-14s %s\n", mark, r.name, r.status)
	}
	if len(results) == 0 {
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
