package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/redact"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
	"github.com/karthikmprakash/agents-secret-manager/internal/tpl"
)

func cmdInject(args []string) error {
	fs := flag.NewFlagSet("sm inject", flag.ContinueOnError)
	tplPath := fs.String("tpl", "", "template file with {{sm:NAME}} placeholders")
	outPath := fs.String("out", "", "output file (mode 0600, shredded when the command exits)")
	verbose := fs.Bool("v", false, "print what was materialized (names only)")
	verboseLong := fs.Bool("verbose", false, "print what was materialized (names only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cmdArgs := fs.Args()
	if *tplPath == "" || *outPath == "" || len(cmdArgs) == 0 {
		return fmt.Errorf("usage: sm inject --tpl TEMPLATE --out FILE -- <command> [args...]")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}
	merged := loaded.Merged()

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

	used := []string{}
	seen := map[string]bool{}
	labels := map[string]string{}
	resolveFn := func(name string) (string, error) {
		s, ok := merged.Secrets[name]
		if !ok {
			return "", fmt.Errorf("placeholder {{sm:%s}} has no declared secret", name)
		}
		if s.Transport == manifest.TransportProxy {
			return "", fmt.Errorf("secret %s: transport \"proxy\" cannot be materialized (v0.3 broker)", name)
		}
		ref, err := manifest.ParseRef(s.Ref)
		if err != nil {
			return "", fmt.Errorf("secret %s: %w", name, err)
		}
		val, found, err := v.Get(ref.Path)
		if err != nil {
			return "", fmt.Errorf("secret %s: %w", name, err)
		}
		if !found {
			return "", fmt.Errorf("secret %s is declared but missing from the vault (%s)", name, s.Ref)
		}
		if !seen[name] {
			seen[name] = true
			used = append(used, name)
		}
		if _, ok := labels[val]; !ok {
			labels[val] = name
		}
		return val, nil
	}

	data, err := os.ReadFile(*tplPath)
	if err != nil {
		return err
	}
	rendered, err := tpl.Render(string(data), resolveFn)
	if err != nil {
		return err
	}
	sort.Strings(used)

	// Audit before materializing; fail closed.
	auditDir, err := config.Dir()
	if err != nil {
		return err
	}
	entry := audit.Entry{
		TS:      time.Now().UTC().Format(time.RFC3339),
		Session: audit.NewSession(),
		Cmd:     fmt.Sprintf("sm inject --tpl %s --out %s", *tplPath, *outPath),
		Secrets: used,
		Action:  "materialize",
		CWD:     cwd,
	}
	if err := audit.Append(auditDir, entry); err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}

	if err := tpl.WriteFile(*outPath, []byte(rendered)); err != nil {
		return err
	}
	if *verbose || *verboseLong {
		fmt.Fprintf(os.Stderr, "sm: materialized %s (mode 0600)\n", *outPath)
		fmt.Fprintf(os.Stderr, "sm: secrets %s\n", strings.Join(used, ", "))
		fmt.Fprintf(os.Stderr, "sm: session %s · file shredded on exit\n", entry.Session)
	}

	child := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	child.Stdin = os.Stdin
	out := redact.New(os.Stdout, labels)
	errW := redact.New(os.Stderr, labels)
	child.Stdout = out
	child.Stderr = errW

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		if sig, ok := <-sigCh; ok && child.Process != nil {
			_ = child.Process.Signal(sig)
		}
	}()

	runErr := child.Run()
	signal.Stop(sigCh)
	close(sigCh)
	if ferr := out.Flush(); ferr != nil && runErr == nil {
		runErr = ferr
	}
	if ferr := errW.Flush(); ferr != nil && runErr == nil {
		runErr = ferr
	}

	if err := tpl.Shred(*outPath); err != nil {
		fmt.Fprintln(os.Stderr, "sm: warning: could not shred output:", err)
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
		return fmt.Errorf("run %s: %w", cmdArgs[0], runErr)
	}
	return nil
}
