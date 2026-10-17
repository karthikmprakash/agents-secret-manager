// Package mcpserver exposes the vault over the Model Context Protocol (stdio).
//
// Tools: secret_list and secret_run. There is deliberately no secret_get:
// values are injected into child processes and never returned to the model.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/redact"
	"github.com/karthikmprakash/agents-secret-manager/internal/resolve"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

const instructions = `You are connected to the user's local secrets vault (sm).

Rules:
- When a command needs credentials (aws, modal, gh, kubectl, database clients, package publishing), call secret_run with the full shell command instead of asking the user for keys or reading .env files.
- Call secret_list to see which secret names exist and whether they are present in the vault.
- Secret values are injected into the child process and are never returned to you. Output is redacted as [redacted:NAME]; treat those markers as "a secret was used here".
- Never ask the user to paste secrets into the chat and never write secrets into files. If a credential is missing, say which name is missing and ask the user to add it (secret_list shows names).
- Set the cwd argument to the project directory when the command should run in a specific project.`

type listArgs struct {
	Cwd string `json:"cwd,omitempty" jsonschema:"optional project directory; defaults to the agent's working directory"`
}

type runArgs struct {
	Command string `json:"command" jsonschema:"shell command to run with the project's secrets injected as environment variables, e.g. \"aws s3 ls\""`
	Cwd     string `json:"cwd,omitempty" jsonschema:"optional project directory; defaults to the agent's working directory"`
}

// Run serves MCP over stdio until the client disconnects.
func Run(ctx context.Context, version string) error {
	server := newServer(version)
	return server.Run(ctx, &mcp.StdioTransport{})
}

func newServer(version string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:        "sm",
		Title:       "Agent Secrets Manager",
		Description: "Run commands with vault-injected credentials; values are never returned.",
		Version:     version,
	}, &mcp.ServerOptions{Instructions: instructions})

	mcp.AddTool(server, &mcp.Tool{
		Name:  "secret_list",
		Title: "List secrets",
		Description: "List secret names declared for the current project (plus global secrets), " +
			"with transport and vault status. Never returns values.",
	}, listTool)

	mcp.AddTool(server, &mcp.Tool{
		Name:  "secret_run",
		Title: "Run with secrets",
		Description: "Run a shell command with the project's secrets injected as environment variables. " +
			"Secret values never appear in the result; output is redacted as [redacted:NAME]. " +
			"Use for aws, modal, gh, kubectl, database clients and any command that needs credentials. " +
			"Never ask the user for secrets.",
	}, runTool)

	return server
}

func listTool(ctx context.Context, req *mcp.CallToolRequest, args listArgs) (*mcp.CallToolResult, any, error) {
	cwd, err := resolveCwd(args.Cwd)
	if err != nil {
		return nil, nil, err
	}
	loaded, err := loadLayers(cwd)
	if err != nil {
		return nil, nil, err
	}
	merged := loaded.Merged()

	status := map[string]string{}
	if identity, err := keys.Get(); err == nil {
		if vp, err := keys.VaultPath(); err == nil {
			if v, err := vaultfile.Open(vp, identity); err == nil {
				for name, s := range merged.Secrets {
					ref, err := manifest.ParseRef(s.Ref)
					if err != nil {
						status[name] = "invalid ref"
						continue
					}
					if _, found, _ := v.Get(ref.Path); found {
						status[name] = "present"
					} else {
						status[name] = "missing"
					}
				}
			}
		}
	}

	type item struct {
		Name      string `json:"name"`
		Transport string `json:"transport"`
		Status    string `json:"status"`
	}
	items := make([]item, 0, len(merged.Secrets))
	for name, s := range merged.Secrets {
		st := status[name]
		if st == "" {
			st = "unknown (vault unavailable)"
		}
		items = append(items, item{Name: name, Transport: s.Transport, Status: st})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

	manifestPath := loaded.ProjectPath
	if manifestPath == "" {
		manifestPath = "(global only)"
	}
	payload := map[string]any{
		"manifest": manifestPath,
		"secrets":  items,
	}
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return textResult(string(out)), nil, nil
}

func runTool(ctx context.Context, req *mcp.CallToolRequest, args runArgs) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.Command) == "" {
		return nil, nil, fmt.Errorf("command is required")
	}
	cwd, err := resolveCwd(args.Cwd)
	if err != nil {
		return nil, nil, err
	}
	loaded, err := loadLayers(cwd)
	if err != nil {
		return nil, nil, err
	}
	projectDir := cwd
	if loaded.ProjectPath != "" {
		projectDir = filepath.Dir(loaded.ProjectPath)
	}

	identity, err := keys.Get()
	if err != nil {
		return nil, nil, err
	}
	vp, err := keys.VaultPath()
	if err != nil {
		return nil, nil, err
	}
	v, err := vaultfile.Open(vp, identity)
	if err != nil {
		return nil, nil, err
	}
	res, err := resolve.Build(loaded, v, projectDir, resolve.Options{
		AllowPlaintext: os.Getenv("SM_ALLOW_PLAINTEXT") == "1",
	})
	if err != nil {
		return nil, nil, err
	}

	labels := map[string]string{}
	for envName, val := range res.Values {
		if val == "" {
			continue
		}
		if _, ok := labels[val]; !ok {
			labels[val] = envName
		}
	}

	auditDir, err := config.Dir()
	if err != nil {
		return nil, nil, err
	}
	entry := audit.Entry{
		TS:      time.Now().UTC().Format(time.RFC3339),
		Session: audit.NewSession(),
		Cmd:     redact.String(args.Command, labels),
		Secrets: res.Secrets,
		Action:  "inject",
		CWD:     cwd,
	}
	if err := audit.Append(auditDir, entry); err != nil {
		return nil, nil, fmt.Errorf("append audit log: %w", err)
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, "sh", "-c", args.Command)
	cmd.Dir = cwd
	cmd.Env = res.Env
	out, runErr := cmd.CombinedOutput()
	elapsed := time.Since(start)

	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			code = ee.ExitCode()
			if code < 0 {
				code = 1
			}
		} else {
			return nil, nil, fmt.Errorf("run %s: %w", args.Command, runErr)
		}
	}

	text := redact.String(string(out), labels)
	if text == "" {
		text = "(no output)"
	}
	if len(text) > 100_000 {
		text = text[:100_000] + "\n… output truncated"
	}
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("exit %d · %s\n%s", code, elapsed.Round(time.Millisecond), text)},
		},
		IsError: code != 0,
	}
	return result, nil, nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// loadLayers wraps the "no manifest" error with the global-secret hint.
func loadLayers(cwd string) (*manifest.Loaded, error) {
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return nil, fmt.Errorf("%w — add global secrets with `sm add --global NAME`, or run `sm init` in a project", err)
	}
	return loaded, nil
}

func resolveCwd(arg string) (string, error) {
	if arg == "" {
		return os.Getwd()
	}
	abs, err := filepath.Abs(arg)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", abs)
	}
	return abs, nil
}
