package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

// cmdGet prints one value to the local terminal and records a reveal. This is
// deliberately a CLI/UI-only capability; the MCP server still has no
// value-returning tool.
func cmdGet(args []string) error {
	fs := flag.NewFlagSet("sm get", flag.ContinueOnError)
	scope := fs.String("scope", "", "global or project (default: the merged entry)")
	const usage = "usage: sm get NAME [--scope global|project]"
	name, err := parseOnePositional(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if name == "" {
		return fmt.Errorf("%s", usage)
	}
	if *scope != "" && *scope != "global" && *scope != "project" {
		return fmt.Errorf("scope must be global or project")
	}
	if !manifest.ValidName(name) {
		return fmt.Errorf("invalid secret name")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadOptional(cwd)
	if err != nil {
		return err
	}
	secret, ok := loaded.Merged().Secrets[name]
	if !ok {
		return fmt.Errorf("%s is not declared — use `sm add %s` first", name, name)
	}
	if *scope == "global" {
		if loaded.Global == nil {
			return fmt.Errorf("no global manifest found")
		}
		secret, ok = loaded.Global.Secrets[name]
		if !ok {
			return fmt.Errorf("%s is not declared globally", name)
		}
	}
	if *scope == "project" {
		if loaded.Project == nil {
			return fmt.Errorf("no project manifest found")
		}
		secret, ok = loaded.Project.Secrets[name]
		if !ok {
			return fmt.Errorf("%s is not declared in this project", name)
		}
	}
	ref, err := manifest.ParseRef(secret.Ref)
	if err != nil {
		return err
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
	value, found, err := v.Get(ref.Path)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s has no stored value", name)
	}
	if dir, err := config.Dir(); err == nil {
		_ = audit.Append(dir, audit.Entry{
			TS:      time.Now().UTC().Format(time.RFC3339),
			Session: audit.NewSession(),
			Action:  "reveal",
			Secrets: []string{name},
			Cmd:     "sm get",
			CWD:     cwd,
		})
	}
	fmt.Println(value)
	return nil
}
