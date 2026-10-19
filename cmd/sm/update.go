package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/update"
)

// cmdUpdate is an explicit network action. Nothing checks for updates in the
// background, preserving the no-telemetry default.
func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("sm update", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the check result as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm update [--json]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := update.Check(ctx, version)
	if err != nil {
		return err
	}
	if *asJSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	if !result.Available {
		if strings.Contains(version, "-") && update.Compare(result.Latest, version) <= 0 {
			fmt.Printf("%s development build %s · latest published release is %s\n", markOK(), bold(version), result.Latest)
		} else {
			fmt.Printf("%s up to date · %s (latest release %s)\n", markOK(), bold(version), result.Latest)
		}
		return nil
	}
	fmt.Printf("%s update available: %s → %s\n", markWarn(), version, bold(result.Latest))
	if viaHomebrew() {
		fmt.Println("  " + dim("Homebrew: ") + cyan("brew upgrade --cask sm"))
	} else {
		fmt.Println("  " + dim("Homebrew: ") + cyan("brew upgrade --cask sm"))
		fmt.Println("  " + dim("Download: ") + result.URL)
	}
	fmt.Println("  " + dim("checked "+result.CheckedAt.Local().Format("2006-01-02 15:04")))
	return nil
}

func viaHomebrew() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	return strings.Contains(resolved, "/Caskroom/sm/")
}
