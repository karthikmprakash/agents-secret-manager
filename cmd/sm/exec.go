package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/resolve"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

// exitCodeError carries the child's exit code through main without printing it.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func cmdExec(args []string) error {
	fs := flag.NewFlagSet("sm exec", flag.ContinueOnError)
	profile := fs.String("profile", "", "load .env.<profile> between .env and .env.local")
	verbose := fs.Bool("v", false, "print what was resolved (names only)")
	verboseLong := fs.Bool("verbose", false, "print what was resolved (names only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return fmt.Errorf("usage: sm exec [--profile NAME] [-v] -- <command> [args...]")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
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
	})
	if err != nil {
		return err
	}

	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "sm: warning:", w)
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
	}

	child := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	child.Env = res.Env
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	if err := child.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code := ee.ExitCode()
			if code < 0 {
				code = 1
			}
			return &exitCodeError{code: code}
		}
		return fmt.Errorf("run %s: %w", cmdArgs[0], err)
	}
	return nil
}
