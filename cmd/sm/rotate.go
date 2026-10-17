package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/generate"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("sm rotate", flag.ContinueOnError)
	generateFlag := fs.String("generate", "", "generate the new value instead of prompting: [profile/]length")

	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	const usage = "usage: sm rotate NAME [--generate postgres/32]"
	switch {
	case name == "" && fs.NArg() == 1:
		name = fs.Arg(0)
	case name == "" || fs.NArg() > 0:
		return fmt.Errorf("%s", usage)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}
	secret, ok := loaded.Merged().Secrets[name]
	if !ok {
		return fmt.Errorf("secret %s is not declared — use `sm add %s` first", name, name)
	}
	ref, err := manifest.ParseRef(secret.Ref)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if ref.Scheme != "vault" {
		return fmt.Errorf("secret %s: store scheme %q is not supported yet (connectors arrive in v0.3)", name, ref.Scheme)
	}

	var value string
	if *generateFlag != "" {
		value, err = generate.Value(*generateFlag)
		if err != nil {
			return err
		}
	} else {
		value, err = promptValue(name)
		if err != nil {
			return err
		}
	}
	if value == "" {
		return fmt.Errorf("empty value; nothing rotated")
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
	if err := v.Set(ref.Path, value); err != nil {
		return fmt.Errorf("write vault: %w", err)
	}

	auditDir, err := config.Dir()
	if err != nil {
		return err
	}
	entry := audit.Entry{
		TS:      time.Now().UTC().Format(time.RFC3339),
		Session: audit.NewSession(),
		Cmd:     "sm rotate " + name,
		Secrets: []string{name},
		Action:  "rotate",
		CWD:     cwd,
	}
	if err := audit.Append(auditDir, entry); err != nil {
		return fmt.Errorf("value rotated, but audit append failed: %w", err)
	}

	fmt.Printf("rotated %s (ref %s unchanged) — every surface picks it up on the next run\n", name, secret.Ref)
	return nil
}
