package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
)

func cmdLog(args []string) error {
	fs := flag.NewFlagSet("sm log", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "show the most recent N entries (0 shows all)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *limit < 0 || fs.NArg() > 1 {
		return fmt.Errorf("usage: sm log [--limit N] [verify]")
	}
	verify := false
	if fs.NArg() == 1 {
		if fs.Arg(0) != "verify" {
			return fmt.Errorf("usage: sm log [--limit N] [verify]")
		}
		verify = true
	}

	dir, err := config.Dir()
	if err != nil {
		return err
	}
	if verify {
		n, err := audit.Verify(dir)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s %s\n", markOK(), green(fmt.Sprintf("%d audit entr%s", n, plural(n, "y", "ies"))), dim("· chain intact"))
		fmt.Println(dim("  " + shortHome(audit.Path(dir))))
		return nil
	}

	entries, err := audit.Read(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("no audit entries yet — run a command with " + cyan("sm exec"))
		return nil
	}
	shown := entries
	if *limit > 0 && len(entries) > *limit {
		shown = entries[len(entries)-*limit:]
	}

	fmt.Printf("%s %s\n\n", bold("sm log"), dim(fmt.Sprintf("· %d entr%s", len(entries), plural(len(entries), "y", "ies"))))
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tSESSION\tACTION\tSECRETS\tCMD")
	for _, entry := range shown {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			displayAuditTime(entry.TS), entry.Session, entry.Action, strings.Join(entry.Secrets, ","), entry.Cmd)
	}
	w.Flush()
	if len(shown) < len(entries) {
		fmt.Println(dim(fmt.Sprintf("\nshowing the last %d; use --limit 0 for all", len(shown))))
	}
	fmt.Println(dim("\nverify the chain with `sm log verify` · values are never recorded"))
	return nil
}

func displayAuditTime(ts string) string {
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return parsed.Local().Format("2006-01-02 15:04:05")
}
