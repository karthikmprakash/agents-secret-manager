package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/karthikmprakash/agents-secret-manager/internal/generate"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("sm rotate", flag.ContinueOnError)
	generateFlag := fs.String("generate", "", "generate the new value instead of prompting: [profile/]length")

	const usage = "usage: sm rotate NAME [--generate postgres/32]"
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

	if err := secrets.Rotate(cwd, name, value); err != nil {
		return err
	}

	fmt.Printf("%s rotated %s\n", markOK(), bold(name))
	fmt.Println("  " + dim("value replaced · ref unchanged · every surface picks it up on the next run"))
	return nil
}
