package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

type envRow struct {
	name      string
	service   string
	transport string
	ref       string
	status    string
	config    bool
	value     string
}

func cmdEnv(args []string) error {
	fs := flag.NewFlagSet("sm env", flag.ContinueOnError)
	verbose := fs.Bool("verbose", false, "include each entry's full vault reference")
	showConfig := fs.Bool("show-config", false, "print plain config values (sensitive values stay hidden)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm env [--verbose] [--show-config]")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadOptional(cwd)
	if err != nil {
		return err
	}
	if loaded.Global == nil && loaded.Project == nil {
		fmt.Println(bold("sm env") + dim(" · no secrets declared here"))
		nextBlock("create a project manifest: "+cyan("sm init"),
			"or add a global secret: "+cyan("sm add --global NAME"))
		return nil
	}
	merged := loaded.Merged()

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

	fmt.Printf("%s %s\n\n", bold("sm env"), dim("· sensitive values are never printed"))
	if loaded.GlobalPath != "" {
		field("global", shortHome(loaded.GlobalPath))
	}
	if loaded.ProjectPath != "" {
		field("project", shortHome(loaded.ProjectPath))
	}
	if merged.Project.Name != "" {
		field("app", merged.Project.Name)
	}

	names := make([]string, 0, len(merged.Secrets))
	for name := range merged.Secrets {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		si, sj := merged.Secrets[names[i]].Service, merged.Secrets[names[j]].Service
		if si != sj {
			if si == "" {
				return true
			}
			if sj == "" {
				return false
			}
			return si < sj
		}
		return names[i] < names[j]
	})
	if len(names) == 0 {
		fmt.Println("  " + markWarn() + " no secrets declared here")
		nextBlock("add one: " + cyan("sm add NAME"))
		return nil
	}

	rows := make([]envRow, 0, len(names))
	for _, name := range names {
		secret := merged.Secrets[name]
		row := envRow{
			name:      name,
			service:   secret.Service,
			transport: secret.Transport,
			ref:       secret.Ref,
			config:    !secret.IsSensitive(),
		}
		if row.transport == "" {
			row.transport = "-"
		}
		ref, parseErr := manifest.ParseRef(secret.Ref)
		switch {
		case parseErr != nil:
			row.status = "invalid ref"
		default:
			stored, found, getErr := v.Get(ref.Path)
			switch {
			case getErr != nil:
				row.status = "error"
			case !found:
				row.status = "missing"
			default:
				row.status = "present"
				if !secret.IsSensitive() {
					row.value = stored
				}
			}
		}
		rows = append(rows, row)
	}

	fmt.Println()
	present, missing, configCount := 0, 0, 0
	groups := map[string][]envRow{}
	var order []string
	for _, row := range rows {
		if row.status == "present" {
			present++
		} else {
			missing++
		}
		if row.config {
			configCount++
		}
		key := row.service
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], row)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i] == "" {
			return true
		}
		if order[j] == "" {
			return false
		}
		return order[i] < order[j]
	})

	for _, service := range order {
		label := service
		if label == "" {
			label = "ungrouped"
		}
		fmt.Printf("%s %s\n", bold(label), dim(fmt.Sprintf("· %d", len(groups[service]))))
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		columns := "  NAME\tTYPE\tTRANSPORT\tSTATUS"
		if *verbose {
			columns += "\tREF"
		}
		if *showConfig {
			columns += "\tVALUE"
		}
		fmt.Fprintln(w, columns)
		for _, row := range groups[service] {
			kind := "secret"
			if row.config {
				kind = "config"
			}
			line := fmt.Sprintf("  %s\t%s\t%s\t%s", row.name, kind, row.transport, row.status)
			if *verbose {
				line += "\t" + row.ref
			}
			if *showConfig {
				value := "-"
				if row.config {
					value = truncateValue(row.value)
				}
				line += "\t" + value
			}
			fmt.Fprintln(w, line)
		}
		w.Flush()
		fmt.Println()
	}

	summary := fmt.Sprintf("%d declared · %s present", len(rows), green(fmt.Sprint(present)))
	if missing > 0 {
		summary += " · " + yellow(fmt.Sprintf("%d missing", missing))
	}
	if configCount > 0 {
		summary += " · " + fmt.Sprintf("%d config", configCount)
	}
	if len(groups) > 1 || (len(groups) == 1 && order[0] != "") {
		n := len(groups)
		if _, ok := groups[""]; ok {
			n--
		}
		summary += " · " + quantity(n, "group", "groups")
	}
	fmt.Println(summary)
	if *showConfig {
		fmt.Println(dim("config values are shown; sensitive values stay hidden (use `sm get NAME` to reveal one)"))
	} else {
		fmt.Println(dim("values are never printed by sm env; add --show-config for plain config"))
	}
	if missing > 0 {
		nextBlock(markWarn() + " restore or rotate the missing entries; names above are safe to share")
	}
	return nil
}

func truncateValue(value string) string {
	if value == "" {
		return "-"
	}
	runes := []rune(value)
	if len(runes) > 48 {
		return string(runes[:45]) + "…"
	}
	return value
}
