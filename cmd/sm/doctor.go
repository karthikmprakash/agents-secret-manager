package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/scan"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("sm doctor", flag.ContinueOnError)
	noHistory := fs.Bool("no-history", false, "skip git history")
	depth := fs.Int("depth", 500, "max commits to scan in git history")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm doctor [--no-history] [--depth N]")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}
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

	merged := loaded.Merged()
	if len(merged.Secrets) == 0 {
		fmt.Println("  " + markWarn() + " no registered secrets to check")
		fmt.Println(dim("  sm doctor finds copies of values you have already stored — not general API keys in files."))
		nextBlock("add or import credentials first: " + cyan("sm add --global NAME"))
		return nil
	}
	names := make([]string, 0, len(merged.Secrets))
	var secrets []scan.Secret
	for name, secret := range merged.Secrets {
		if !secret.IsSensitive() {
			continue // config values are not leaks
		}
		names = append(names, name)
		ref, err := manifest.ParseRef(secret.Ref)
		if err != nil {
			continue
		}
		if val, found, _ := v.Get(ref.Path); found {
			secrets = append(secrets, scan.Secret{Value: val, Name: name})
		}
	}

	fmt.Printf("%s %s\n\n", bold("sm doctor"), dim("· scanning for registered values in plaintext"))
	home, _ := os.UserHomeDir()
	res := scan.Run(scan.Options{
		ProjectDir: projectDir,
		HomeDir:    home,
		Depth:      *depth,
		NoHistory:  *noHistory,
	}, secrets, names)
	for _, warning := range res.Warnings {
		fmt.Fprintln(os.Stderr, yellow("sm: warning:"), warning)
	}
	if len(res.Warnings) > 0 && len(res.Findings) == 0 {
		return &exitCodeError{code: 2}
	}

	if len(res.Findings) == 0 {
		fmt.Printf("%s no registered values found in %d scanned files %s\n", markOK(), res.Scanned, dim(fmt.Sprintf("(%d skipped)", res.Skipped)))
		fmt.Println(dim("  encoded, rotated and unregistered values may not be detected"))
		return nil
	}

	fmt.Printf("%s %s\n\n", markErr(), bold(fmt.Sprintf("%d finding(s) across %d scanned files", len(res.Findings), res.Scanned)))
	for _, finding := range res.Findings {
		if finding.Kind == "value" {
			fmt.Printf("  %s\n    vault value %s is present in plaintext: %s\n", red(finding.Location), bold(finding.Name), finding.Snippet)
		} else {
			fmt.Printf("  %s\n    managed name %s is set in plaintext\n", red(finding.Location), bold(finding.Name))
		}
	}
	nextBlock("rotate what was exposed: "+cyan("sm rotate NAME"),
		"remove the plaintext copies, then rerun "+cyan("sm doctor"),
		dim("assuming a leaked value is compromised is cheaper than guessing"))
	return &exitCodeError{code: 1}
}
