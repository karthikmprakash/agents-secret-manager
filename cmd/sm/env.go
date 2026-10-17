package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func cmdEnv(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sm env takes no arguments")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}
	if loaded.GlobalPath != "" {
		fmt.Println("global :", loaded.GlobalPath)
	}
	if loaded.ProjectPath != "" {
		fmt.Println("project:", loaded.ProjectPath)
	}
	merged := loaded.Merged()
	if merged.Project.Name != "" {
		fmt.Printf("name   : %s (default_ttl %s)\n", merged.Project.Name, merged.Project.DefaultTTL)
	}

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

	names := make([]string, 0, len(merged.Secrets))
	for n := range merged.Secrets {
		names = append(names, n)
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

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSERVICE\tTRANSPORT\tREF\tSTATUS")
	configCount := 0
	for _, n := range names {
		s := merged.Secrets[n]
		service := s.Service
		if service == "" {
			service = "-"
		}
		if !s.IsSensitive() {
			configCount++
		}
		r, err := manifest.ParseRef(s.Ref)
		if err != nil {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", n, service, s.Transport, s.Ref, "invalid ref")
			continue
		}
		_, found, err := v.Get(r.Path)
		status := "present"
		switch {
		case err != nil:
			status = "error: " + err.Error()
		case !found:
			status = "missing"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", n, service, s.Transport, s.Ref, status)
	}
	w.Flush()

	fmt.Println("\nvalues are never printed")
	if configCount > 0 {
		fmt.Printf("%d config value(s) marked sensitive=false (not masked, not reported as leaks)\n", configCount)
	}
	return nil
}
