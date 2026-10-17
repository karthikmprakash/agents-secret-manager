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

func cmdService(args []string) error {
	fs := flag.NewFlagSet("sm service", flag.ContinueOnError)
	rename := fs.String("rename", "", "new group name (existing destination groups are merged)")
	ungroup := fs.Bool("ungroup", false, "remove this group label without deleting values")
	scope := fs.String("scope", "global", "global or project manifest")
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return fmt.Errorf("usage: sm service NAME --rename NEW|--ungroup [--scope global|project]")
	}
	if !manifest.ValidService(name) || (*rename == "" && !*ungroup) || (*rename != "" && *ungroup) {
		return fmt.Errorf("usage: sm service NAME --rename NEW|--ungroup [--scope global|project]")
	}
	var path string
	var err error
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
		fmt.Printf("Ungrouped %d entries; no values or references were deleted.\n", len(names))
	} else {
		fmt.Printf("Moved %d entries from %s to %s; no values or references changed.\n", len(names), name, *rename)
	}
	return nil
}
