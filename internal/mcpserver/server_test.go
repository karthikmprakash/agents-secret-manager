package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func TestServerTools(t *testing.T) {
	cfg := t.TempDir()
	proj := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", cfg)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())

	v, err := vaultfile.Open(filepath.Join(cfg, "vault.age"), id.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Set("demo/token", "sekret-123"); err != nil {
		t.Fatal(err)
	}

	manifestTOML := "[secrets.TOKEN]\nref = \"vault://demo/token\"\ntransport = \"env\"\n"
	if err := os.WriteFile(filepath.Join(proj, ".agentsecrets.toml"), []byte(manifestTOML), 0o644); err != nil {
		t.Fatal(err)
	}

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	server := newServer("test")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() { _ = server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	if !names["secret_list"] || !names["secret_run"] {
		t.Fatalf("tools = %v", names)
	}
	if names["secret_get"] {
		t.Fatal("secret_get must not be exposed")
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "secret_run",
		Arguments: map[string]any{"command": "echo $TOKEN", "cwd": proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := contentText(res)
	if !strings.Contains(text, "[redacted:TOKEN]") {
		t.Errorf("expected redaction, got %q", text)
	}
	if strings.Contains(text, "sekret-123") {
		t.Errorf("value leaked: %q", text)
	}
	if res.IsError {
		t.Errorf("unexpected error result: %s", text)
	}

	auditData, err := os.ReadFile(filepath.Join(cfg, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditData), "sekret-123") {
		t.Error("audit log leaked the value")
	}
	if !strings.Contains(string(auditData), "TOKEN") {
		t.Error("audit log missing secret name")
	}

	res, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "secret_list",
		Arguments: map[string]any{"cwd": proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	text = contentText(res)
	if !strings.Contains(text, "TOKEN") || !strings.Contains(text, "present") {
		t.Errorf("list = %q", text)
	}
	if strings.Contains(text, "sekret-123") {
		t.Error("list leaked the value")
	}
}

func TestRunToolFailureIsError(t *testing.T) {
	cfg := t.TempDir()
	proj := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", cfg)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())

	if err := os.WriteFile(filepath.Join(proj, ".agentsecrets.toml"), []byte("[secrets]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	server := newServer("test")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() { _ = server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "secret_run",
		Arguments: map[string]any{"command": "exit 3", "cwd": proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("expected IsError for a failing command")
	}
	if !strings.Contains(contentText(res), "exit 3") {
		t.Errorf("result = %q", contentText(res))
	}
}

func contentText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestRunBoundsOutputAndRemovesIdentity(t *testing.T) {
	proj := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", cfg)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())
	if err := os.WriteFile(filepath.Join(proj, ".agentsecrets.toml"), []byte("[secrets]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _, err := runTool(context.Background(), nil, runArgs{Cwd: proj, Command: `test -z "$SM_IDENTITY" || exit 99; head -c 200000 /dev/zero | tr '\000' x`})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatal(contentText(res))
	}
	text := contentText(res)
	if len(text) > 101000 || !strings.Contains(text, "truncated") {
		t.Fatal("output not bounded")
	}
	if strings.Contains(text, id.String()) {
		t.Fatal("master identity leaked")
	}
}

func TestRunCancellationKillsShellGroup(t *testing.T) {
	proj := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", t.TempDir())
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())
	if err := os.WriteFile(filepath.Join(proj, ".agentsecrets.toml"), []byte("[secrets]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, _, err := runTool(ctx, nil, runArgs{Cwd: proj, Command: "sleep 30 & wait"})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second || !res.IsError || !strings.Contains(contentText(res), "timed out") {
		t.Fatal("cancellation failed")
	}
}
