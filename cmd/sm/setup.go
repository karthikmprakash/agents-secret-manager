package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
)

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

	targets := wireup.Detect(exe, home)
	fmt.Printf("sm setup — %d target(s)\n\n", len(targets))
	failed := 0
	for _, t := range targets {
		if *dryRun {
			fmt.Printf("  ok  %-14s %s\n", t.Name, t.DryRun())
			continue
		}
		status, err := t.Apply()
		if err != nil {
			fmt.Printf("  !!  %-14s error: %v\n", t.Name, err)
			failed++
			continue
		}
		fmt.Printf("  ok  %-14s %s\n", t.Name, status)
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
