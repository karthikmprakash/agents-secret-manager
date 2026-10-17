package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
)

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("sm setup", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "show what would be configured without changing anything")
	agent := fs.String("agent", "", "wire only this detected harness")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm setup [--dry-run] [--agent NAME]")
	}

	targets, err := detectAgentTargets()
	if err != nil {
		return err
	}
	if *agent != "" {
		var filtered []wireup.Target
		for _, target := range targets {
			if strings.EqualFold(target.Name, *agent) {
				filtered = append(filtered, target)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("harness %q is not installed or detected — run `sm agents` to see detected harnesses", *agent)
		}
		targets = filtered
	}

	mode := ""
	if *dryRun {
		mode = dim(" · dry run, nothing will change")
	}
	fmt.Printf("%s %s%s\n\n", bold("sm setup"), dim("· "+quantity(len(targets), "harness detected", "harnesses detected")), mode)
	if len(targets) == 0 {
		fmt.Println("  " + markWarn() + " no supported harnesses detected on this Mac")
		fmt.Println()
		fmt.Println(heading("next"))
		fmt.Println("  " + cyan("sm config") + dim("   copy-paste wiring for every supported harness"))
		fmt.Println("  " + dim("install a harness, then run sm setup again"))
		return nil
	}

	configured, failed := 0, 0
	for _, target := range targets {
		if *dryRun {
			fmt.Printf("  %s %-15s %s\n", dim("·"), target.Name, dim("would configure · "+target.Detail))
			continue
		}
		status, applyErr := target.Apply()
		if applyErr != nil {
			fmt.Printf("  %s %-15s %s\n", markErr(), target.Name, red(applyErr.Error()))
			failed++
			continue
		}
		configured++
		fmt.Printf("  %s %-15s %s\n", markOK(), target.Name, status)
	}

	fmt.Println()
	if *dryRun {
		fmt.Println("  " + dim(quantity(len(targets), "harness would be wired", "harnesses would be wired")))
		nextBlock("rerun without --dry-run to apply: "+cyan("sm setup"),
			"one at a time: "+cyan("sm setup --agent NAME"))
		return nil
	}

	fmt.Printf("  %s\n", fmt.Sprintf("%s %d configured · %s %d failed", markOK(), configured, markWarn(), failed))
	nextBlock("restart the apps so they load the MCP server",
		"add secrets once: "+cyan("sm add --global AWS_ACCESS_KEY_ID"),
		"check the whole setup: "+cyan("sm status"))
	if failed > 0 {
		return fmt.Errorf("%s — rerun `sm setup` to retry", quantity(failed, "harness configuration failed", "harness configurations failed"))
	}
	return nil
}
