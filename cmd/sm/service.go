package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func cmdService(args []string) error {
	fs := flag.NewFlagSet("sm service", flag.ContinueOnError)
	rename := fs.String("rename", "", "new group name (existing destination groups are merged)")
	ungroup := fs.Bool("ungroup", false, "remove this group label without deleting values")
	scope := fs.String("scope", "global", "global or project manifest")
	const usage = "usage: sm service NAME --rename NEW|--ungroup [--scope global|project]"
	name, err := parseOnePositional(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if !manifest.ValidService(name) || (*rename == "" && !*ungroup) || (*rename != "" && *ungroup) {
		return fmt.Errorf("%s", usage)
	}
	var path string
	switch *scope {
	case "global":
		path, err = manifest.GlobalPath()
	case "project":
		cwd, e := os.Getwd()
		if e != nil {
			return e
		}
		var found bool
		path, found = manifest.FindProject(cwd)
		if !found {
			return fmt.Errorf("no project manifest found")
		}
	default:
		return fmt.Errorf("scope must be global or project")
	}
	if err != nil {
		return err
	}
	names, err := secrets.MoveService(path, name, *rename, nil)
	if err != nil {
		return err
	}
	if *ungroup {
		fmt.Printf("%s ungrouped %s %s\n", markOK(), bold(name), dim(fmt.Sprintf("· %d %s", len(names), pluralWord(len(names), "entry", "entries"))))
	} else {
		fmt.Printf("%s renamed group %s %s %s\n", markOK(), bold(name), dim("→ "+*rename), dim(fmt.Sprintf("· %d %s", len(names), pluralWord(len(names), "entry", "entries"))))
	}
	fmt.Println("  " + dim("no values or references changed · updated "+shortHome(path)+" · commit it"))
	return nil
}
