package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
)

func cmdConfig(args []string) error {
	fs := flag.NewFlagSet("sm config", flag.ContinueOnError)
	agent := fs.String("agent", "", "print only one harness's snippet")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm config [--agent NAME]")
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}

	all := wireup.Snippets(exe)
	shown := all
	if *agent != "" {
		shown = nil
		for _, s := range all {
			for _, name := range s.Agents {
				if name == *agent {
					shown = append(shown, s)
					break
				}
			}
		}
		if len(shown) == 0 {
			var names []string
			for _, s := range all {
				names = append(names, s.Agents...)
			}
			return fmt.Errorf("unknown harness %q (try: %s)", *agent, strings.Join(names, ", "))
		}
	}

	fmt.Printf("%s %s\n\n", bold("sm config"), dim("· manual MCP wiring · sm setup wires detected harnesses automatically"))
	for _, s := range shown {
		fmt.Printf("%s (%s)\n", strings.Join(s.Agents, ", "), strings.ToUpper(s.Lang))
		for _, f := range s.Files {
			fmt.Printf("  %s\n", f)
		}
		fmt.Println()
		fmt.Println(s.Body)
		fmt.Println()
	}
	fmt.Println(dim("The command is this machine's absolute path to sm; use each machine's own path."))
	fmt.Println(dim("Restart the harness afterwards — agents then get secret_list / secret_run."))
	return nil
}
