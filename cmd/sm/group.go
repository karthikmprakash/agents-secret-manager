package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func cmdGroup(args []string) error {
	fs := flag.NewFlagSet("sm group", flag.ContinueOnError)
	serviceFlag := fs.String("service", "", "service name to assign, e.g. stripe")
	ungroupFlag := fs.Bool("ungroup", false, "remove the service grouping from this secret")
	const usage = "usage: sm group NAME --service stripe  (or --ungroup)"
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
	if !manifest.ValidName(name) {
		return fmt.Errorf("invalid secret name; use letters, digits and underscore")
	}
	if *ungroupFlag && *serviceFlag != "" {
		return fmt.Errorf("choose --service or --ungroup, not both")
	}
	if !*ungroupFlag && *serviceFlag == "" {
		return fmt.Errorf("%s", usage)
	}
	service := strings.TrimSpace(*serviceFlag)

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}
	var target string
	if loaded.Project != nil {
		if _, ok := loaded.Project.Secrets[name]; ok {
			target = loaded.ProjectPath
		}
	}
	if target == "" && loaded.Global != nil {
		if _, ok := loaded.Global.Secrets[name]; ok {
			target = loaded.GlobalPath
		}
	}
	if target == "" {
		return fmt.Errorf("%s is not declared — add it first with `sm add %s`", name, name)
	}

	if err := secrets.SetService(target, name, service); err != nil {
		return err
	}
	if service == "" {
		fmt.Printf("%s ungrouped %s\n", markOK(), bold(name))
	} else {
		fmt.Printf("%s moved %s %s\n", markOK(), bold(name), dim("→ group "+service))
	}
	fmt.Println("  " + dim("updated "+shortHome(target)+" · commit it"))
	return nil
}
