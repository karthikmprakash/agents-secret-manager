package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
)

func cmdLog(args []string) error {
	dir, err := config.Dir()
	if err != nil {
		return err
	}

	if len(args) > 0 {
		if args[0] == "verify" && len(args) == 1 {
			n, err := audit.Verify(dir)
			if err != nil {
				return err
			}
			fmt.Printf("ok: %d entries, chain intact (%s)\n", n, audit.Path(dir))
			return nil
		}
		return fmt.Errorf("usage: sm log [verify]")
	}

	entries, err := audit.Read(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("no audit entries yet — run a command with `sm exec`")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tSESSION\tACTION\tSECRETS\tCMD")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.TS, e.Session, e.Action, strings.Join(e.Secrets, ","), e.Cmd)
	}
	return w.Flush()
}
