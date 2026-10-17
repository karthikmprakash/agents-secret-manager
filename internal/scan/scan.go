// Package scan finds plaintext copies of managed secrets across local files
// and git history. Findings carry names and redacted snippets — never values.
package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/resolve"
)

const (
	maxFileSize        = 32 << 20
	maxFindingsPerFile = 20
	maxFiles           = 2000
)

// Secret is a value to search for.
type Secret struct {
	Value string
	Name  string
}

// Options configures a scan.
type Options struct {
	ProjectDir string
	HomeDir    string
	Depth      int // max commits in git history (default 500)
	NoHistory  bool
}

// Finding is one leak.
type Finding struct {
	Location string
	Kind     string // "value" (vault value present) or "plaintext" (managed name set)
	Name     string
	Snippet  string // redacted; empty for "plaintext"
}

// Result is the scan outcome.
type Result struct {
	Findings []Finding
	Scanned  int
	Skipped  int
	Warnings []string
}

type scanner struct {
	secrets []Secret
	managed map[string]bool
	result  *Result
}

type target struct {
	path    string
	display string
}

// Run scans the standard locations for plaintext copies of secrets.
func Run(opts Options, secrets []Secret, managedNames []string) *Result {
	s := &scanner{
		secrets: append([]Secret(nil), secrets...),
		managed: map[string]bool{},
		result:  &Result{},
	}
	sort.Slice(s.secrets, func(i, j int) bool {
		return len(s.secrets[i].Value) > len(s.secrets[j].Value)
	})
	for _, n := range managedNames {
		s.managed[n] = true
	}

	var targets []target
	addFile := func(path, display string) {
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			targets = append(targets, target{path: path, display: display})
		}
	}

	if opts.ProjectDir != "" {
		if matches, _ := filepath.Glob(filepath.Join(opts.ProjectDir, ".env*")); len(matches) > 0 {
			for _, m := range matches {
				addFile(m, relHome(m, opts.HomeDir))
			}
		}
	}
	if opts.HomeDir != "" {
		for _, name := range []string{".zshrc", ".zshenv", ".bashrc", ".bash_profile", ".profile"} {
			addFile(filepath.Join(opts.HomeDir, name), "~/"+name)
		}
		targets = append(targets, walkJSONL(filepath.Join(opts.HomeDir, ".claude"), "~/.claude")...)
		targets = append(targets, walkJSONL(filepath.Join(opts.HomeDir, ".codex"), "~/.codex")...)
		addFile(filepath.Join(opts.HomeDir, ".hermes", "config.yaml"), "~/.hermes/config.yaml")
		addFile(filepath.Join(opts.HomeDir, ".hermes", ".env"), "~/.hermes/.env")
		targets = append(targets, walkJSONL(filepath.Join(opts.HomeDir, ".hermes", "sessions"), "~/.hermes/sessions")...)
		addFile(filepath.Join(opts.HomeDir, ".config", "opencode", "opencode.json"), "~/.config/opencode/opencode.json")
		addFile(filepath.Join(opts.HomeDir, ".config", "opencode", "opencode.jsonc"), "~/.config/opencode/opencode.jsonc")
		if matches, _ := filepath.Glob(filepath.Join(opts.HomeDir, ".cursor", "projects", "*", "agent-transcripts", "*.jsonl")); len(matches) > 0 {
			for _, m := range matches {
				addFile(m, relHome(m, opts.HomeDir))
			}
		}
		addFile(filepath.Join(opts.HomeDir, ".cursor", "mcp.json"), "~/.cursor/mcp.json")
		addFile(filepath.Join(opts.HomeDir, ".claude.json"), "~/.claude.json")
		addFile(filepath.Join(opts.HomeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			"~/Library/Application Support/Claude/claude_desktop_config.json")
	}

	if len(targets) >= maxFiles {
		s.result.Warnings = append(s.result.Warnings, "File limit reached; scan is incomplete.")
		targets = targets[:maxFiles]
	}
	for _, t := range targets {
		s.scanFile(t.path, t.display)
	}
	if !opts.NoHistory && opts.ProjectDir != "" {
		depth := opts.Depth
		if depth <= 0 {
			depth = 500
		}
		s.scanGit(opts.ProjectDir, depth)
	}
	return s.result
}

func walkJSONL(root, displayRoot string) []target {
	var out []target
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		if len(out) >= maxFiles {
			return filepath.SkipAll
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		out = append(out, target{path: path, display: filepath.Join(displayRoot, rel)})
		return nil
	})
	return out
}

func relHome(path, home string) string {
	if home == "" {
		return path
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	return "~/" + rel
}

func (s *scanner) scanFile(path, display string) {
	f, err := os.Open(path)
	if err != nil {
		s.result.Skipped++
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() > maxFileSize {
		s.result.Skipped++
		return
	}
	s.result.Scanned++

	reader := bufio.NewReader(f)
	lineNo, findings := 0, 0
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			lineNo++
			if s.check(line, display, lineNo) {
				findings++
			}
			if findings >= maxFindingsPerFile {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// check reports a finding for one line. Returns true when a finding was added.
func (s *scanner) check(line, loc string, lineNo int) bool {
	line = strings.TrimRight(line, "\r\n")
	for _, sec := range s.secrets {
		if sec.Value == "" || !strings.Contains(line, sec.Value) {
			continue
		}
		s.result.Findings = append(s.result.Findings, Finding{
			Location: fmt.Sprintf("%s:%d", loc, lineNo),
			Kind:     "value",
			Name:     sec.Name,
			// Never echo surrounding transcript text: it may contain a different,
			// unregistered credential on the same line.
			Snippet: "[redacted:" + sec.Name + "]",
		})
		return true
	}

	t := strings.TrimSpace(line)
	t = strings.TrimSpace(strings.TrimPrefix(t, "export "))
	if i := strings.IndexByte(t, '='); i > 0 {
		key := strings.TrimSpace(t[:i])
		if s.managed[key] {
			v := strings.TrimSpace(t[i+1:])
			if parsed, err := resolve.ParseDotenv([]byte(t)); err == nil {
				v = parsed[key]
			}
			if v != "" && !strings.HasPrefix(v, "sm://") && !strings.HasPrefix(v, "vault://") {
				s.result.Findings = append(s.result.Findings, Finding{
					Location: fmt.Sprintf("%s:%d", loc, lineNo),
					Kind:     "plaintext",
					Name:     key,
				})
				return true
			}
		}
	}
	return false
}

// scanGit walks added lines in git history.
func (s *scanner) scanGit(dir string, depth int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Not being in a repository is normal for global-only use.
	if err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--git-dir").Run(); err != nil {
		return
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "log", "--no-ext-diff", "--no-textconv", "--format=commit %H", "-p", "--all", "--max-count", strconv.Itoa(depth))
	cmd.Stderr = io.Discard
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		s.result.Warnings = append(s.result.Warnings, "Could not read git history.")
		return
	}
	if err := cmd.Start(); err != nil {
		s.result.Warnings = append(s.result.Warnings, "Could not scan git history.")
		return
	}
	defer func() {
		_ = pipe.Close()
		if err := cmd.Wait(); err != nil {
			s.result.Warnings = append(s.result.Warnings, "Git history scan did not complete.")
		}
	}()

	reader := bufio.NewReader(io.LimitReader(pipe, 64<<20))
	commit, file := "", ""
	lineNo, count := 0, 0
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			switch {
			case strings.HasPrefix(line, "commit "):
				fields := strings.Fields(strings.TrimPrefix(line, "commit "))
				if len(fields) > 0 {
					h := fields[0]
					if len(h) > 7 {
						h = h[:7]
					}
					commit = h
				}
			case strings.HasPrefix(line, "+++ b/"):
				file = strings.TrimSpace(strings.TrimPrefix(line, "+++ b/"))
				count = 0
			case strings.HasPrefix(line, "@@"):
				lineNo = hunkStart(line)
			case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
				if file != "" && count < maxFindingsPerFile {
					if s.check(strings.TrimPrefix(line, "+"), fmt.Sprintf("git %s %s", commit, file), lineNo) {
						count++
					}
				}
				lineNo++
			case strings.HasPrefix(line, " "):
				lineNo++
			}
		}
		if err != nil {
			return
		}
	}
}

// hunkStart parses the new-file start line from an "@@ -a,b +c,d @@" header.
func hunkStart(line string) int {
	i := strings.Index(line, "+")
	if i < 0 {
		return 0
	}
	rest := line[i+1:]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		return 0
	}
	return n
}
