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
	names := make([]string, 0, len(merged.Secrets))
	var secrets []scan.Secret
	for name, s := range merged.Secrets {
		names = append(names, name)
		ref, err := manifest.ParseRef(s.Ref)
		if err != nil {
			continue
		}
		if val, found, _ := v.Get(ref.Path); found {
			secrets = append(secrets, scan.Secret{Value: val, Name: name})
		}
	}

	home, _ := os.UserHomeDir()
	res := scan.Run(scan.Options{
		ProjectDir: projectDir,
		HomeDir:    home,
		Depth:      *depth,
		NoHistory:  *noHistory,
	}, secrets, names)

	if len(res.Findings) == 0 {
		fmt.Printf("clean — no plaintext copies of managed secrets found (%d files scanned, %d skipped)\n", res.Scanned, res.Skipped)
		return nil
	}

	fmt.Printf("%d finding(s) across %d files scanned\n\n", len(res.Findings), res.Scanned)
	for _, f := range res.Findings {
		if f.Kind == "value" {
			fmt.Printf("  %s\n    vault value %s is present in plaintext: %s\n", f.Location, f.Name, f.Snippet)
		} else {
			fmt.Printf("  %s\n    managed name %s is set in plaintext\n", f.Location, f.Name)
		}
	}
	fmt.Println("\nnext: rotate what was exposed, remove the plaintext copies, then rerun `sm doctor`")
	return &exitCodeError{code: 1}
}
