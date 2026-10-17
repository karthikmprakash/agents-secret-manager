package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/redact"
	"github.com/karthikmprakash/agents-secret-manager/internal/resolve"
	"github.com/karthikmprakash/agents-secret-manager/internal/runner"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

// exitCodeError carries the child's exit code through main without printing it.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func cmdExec(args []string) error {
	fs := flag.NewFlagSet("sm exec", flag.ContinueOnError)
	profile := fs.String("profile", "", "load .env.<profile> between .env and .env.local")
	only := fs.String("only", "", "comma-separated secret names to inject (default: all env secrets)")
	service := fs.String("service", "", "comma-separated service names to inject (all their declared members)")
	verbose := fs.Bool("v", false, "print what was resolved (names only)")
	verboseLong := fs.Bool("verbose", false, "print what was resolved (names only)")
	redactMode := fs.String("redact", "auto", "redact secret values in child output: auto | always | never")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return fmt.Errorf("usage: sm exec [--profile NAME] [--only A,B] [--service stripe] [--redact MODE] [-v] -- <command> [args...]")
	}
	switch *redactMode {
	case "auto", "always", "never":
	default:
		return fmt.Errorf("invalid --redact mode %q (want auto, always or never)", *redactMode)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}

	selected := splitNames(*only)
	for _, svc := range splitNames(*service) {
		members := loaded.Merged().ServiceMembers(svc)
		if len(members) == 0 {
			return fmt.Errorf("no secrets are declared with service %q", svc)
		}
		selected = append(selected, members...)
	}

	// .env files live next to the project manifest (cwd for global-only).
	projectDir := cwd
	if loaded.ProjectPath != "" {
		projectDir = filepath.Dir(loaded.ProjectPath)
	}

	identity, err := keys.Get()
	if err != nil {
		return err
	}
	vaultPath, err := keys.VaultPath()
	if err != nil {
		return err
	}
	v, err := vaultfile.Open(vaultPath, identity)
	if err != nil {
		return err
	}

	res, err := resolve.Build(loaded, v, projectDir, resolve.Options{
		Profile:        *profile,
		AllowPlaintext: os.Getenv("SM_ALLOW_PLAINTEXT") == "1",
		Names:          selected,
	})
	if err != nil {
		return err
	}

	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "sm: warning:", w)
	}

	// Redact when output leaves the terminal (auto), or as told.
	useRedact := *redactMode == "always"
	if *redactMode == "auto" {
		useRedact = !term.IsTerminal(int(os.Stdout.Fd())) || !term.IsTerminal(int(os.Stderr.Fd()))
	}

	var outW io.Writer = os.Stdout
	var errW io.Writer = os.Stderr
	var flushes []func() error
	labels := res.Redactions
	if useRedact {
		o := redact.New(os.Stdout, labels)
		e := redact.New(os.Stderr, labels)
		outW, errW = o, e
		flushes = append(flushes, o.Flush, e.Flush)
	}

	auditDir, err := config.Dir()
	if err != nil {
		return err
	}
	entry := audit.Entry{
		TS:      time.Now().UTC().Format(time.RFC3339),
		Session: audit.NewSession(),
		Cmd:     redact.String(strings.Join(cmdArgs, " "), labels),
		Secrets: res.Secrets,
		Action:  "inject",
		CWD:     cwd,
	}
	if err := audit.Append(auditDir, entry); err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}

	if *verbose || *verboseLong {
		if loaded.ProjectPath != "" {
			fmt.Fprintln(os.Stderr, "sm: manifest", loaded.ProjectPath)
		}
		for _, f := range res.Files {
			fmt.Fprintln(os.Stderr, "sm: env file", f)
		}
		if len(res.Injected) > 0 {
			fmt.Fprintln(os.Stderr, "sm: injected", strings.Join(res.Injected, ", "))
		}
		if len(res.DotenvRef) > 0 {
			fmt.Fprintln(os.Stderr, "sm: refs", strings.Join(res.DotenvRef, ", "))
		}
		fmt.Fprintf(os.Stderr, "sm: %d vars from .env files\n", res.FromFiles)
		fmt.Fprintf(os.Stderr, "sm: session %s · audit %s\n", entry.Session, audit.Path(auditDir))
		fmt.Fprintf(os.Stderr, "sm: redaction %s\n", onOff(useRedact))
	}

	child := runner.Command(cmdArgs, res.Env)
	child.Stdin = os.Stdin
	child.Stdout = outW
	child.Stderr = errW

	runErr := runner.Run(child)
	for _, flush := range flushes {
		if ferr := flush(); ferr != nil && runErr == nil {
			runErr = ferr
		}
	}

	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			code := ee.ExitCode()
			if code < 0 {
				code = 1
			}
			return &exitCodeError{code: code}
		}
		return fmt.Errorf("command failed: %s", redact.String(runErr.Error(), labels))
	}
	return nil
}

func splitNames(s string) []string {
	var out []string
	for _, name := range strings.Split(s, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
