package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
)

// cmdStatus is the dashboard. It is also what plain `sm` runs.
func cmdStatus(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: sm status")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadOptional(cwd)
	if err != nil {
		return err
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}

	fmt.Printf("%s %s %s\n\n", bold("sm"), version, dim("· "+shortHome(dir)))

	targets, _ := detectAgentTargets()
	identity, identityErr := keys.Get()
	vaultPath, _ := keys.VaultPath()
	vaultExists := false
	if vaultPath != "" {
		if _, statErr := os.Stat(vaultPath); statErr == nil {
			vaultExists = true
		}
	}

	if !vaultExists {
		field("vault", yellow("not initialized"))
		if identityErr == nil {
			field("identity", green("✓ present"))
		} else {
			field("identity", yellow("not created"))
		}
		field("agents", agentOverview(targets))
		fmt.Println()
		fmt.Println(heading("get started"))
		fmt.Println("  " + cyan("sm onboard") + dim("   create the vault, add secrets, wire agents"))
		fmt.Println("  " + cyan("sm init") + dim("      project manifest only"))
		fmt.Println("  " + cyan("sm help") + dim("      all commands"))
		return nil
	}

	if identityErr != nil {
		field("vault", green("✓ found")+dim(" · "+shortHome(vaultPath)))
		field("identity", yellow("unavailable")+dim(" · "+identityErr.Error()))
		field("agents", agentOverview(targets))
		fmt.Println()
		fmt.Println(heading("next"))
		fmt.Println("  " + markWarn() + " restore the Keychain identity or restore an archive on a fresh setup")
		fmt.Println("  " + cyan("sm restore --file FILE --verify") + dim(" checks an archive without changing anything"))
		fmt.Println("  " + dim("docs: docs/RECOVERY.md"))
		return nil
	}

	v, vaultErr := vaultfile.Open(vaultPath, identity)
	if vaultErr != nil {
		field("vault", yellow("unavailable")+dim(" · "+vaultErr.Error()))
		field("identity", green("✓ present"))
		field("agents", agentOverview(targets))
		fmt.Println()
		fmt.Println(heading("next"))
		fmt.Println("  " + markWarn() + " the vault could not be decrypted; restore from an encrypted archive if needed")
		return nil
	}

	merged := loaded.Merged()
	addHint := "sm add --global NAME"
	if loaded.Project != nil {
		addHint = "sm add NAME"
	}
	total, present, missing, configCount := 0, 0, 0, 0
	groups := map[string]bool{}
	for _, secret := range merged.Secrets {
		total++
		if !secret.IsSensitive() {
			configCount++
		}
		if secret.Service != "" {
			groups[secret.Service] = true
		}
		ref, err := manifest.ParseRef(secret.Ref)
		if err != nil {
			missing++
			continue
		}
		if _, found, getErr := v.Get(ref.Path); getErr == nil && found {
			present++
		} else {
			missing++
		}
	}
	field("vault", green("✓ ready")+dim(" · "+shortHome(vaultPath)))
	if os.Getenv("SM_IDENTITY") != "" {
		field("identity", yellow("env override")+dim(" · testing only"))
	} else {
		field("identity", green("✓ system keychain"))
	}

	if total == 0 {
		field("secrets", yellow("none declared")+dim(" · "+addHint))
	} else if missing > 0 {
		summary := fmt.Sprintf("%d declared · %d present · ", total, present)
		summary += yellow(fmt.Sprintf("%d missing", missing))
		if configCount > 0 {
			summary += dim(fmt.Sprintf(" · %d config", configCount))
		}
		if len(groups) > 0 {
			summary += dim(" · " + quantity(len(groups), "group", "groups"))
		}
		field("secrets", summary)
	} else {
		summary := fmt.Sprintf("%d declared · ", total) + green("all present")
		if configCount > 0 {
			summary += dim(fmt.Sprintf(" · %d config", configCount))
		}
		if len(groups) > 0 {
			summary += dim(" · " + quantity(len(groups), "group", "groups"))
		}
		field("secrets", summary)
	}

	if loaded.Project != nil {
		name := loaded.Project.Project.Name
		if name == "" {
			name = filepath.Base(filepath.Dir(loaded.ProjectPath))
		}
		field("project", bold(name)+dim(" · "+shortHome(loaded.ProjectPath)))
	} else {
		field("project", dim("none here · global only"))
	}
	field("agents", agentOverview(targets))

	entries, auditErr := audit.Read(dir)
	var lastBackup time.Time
	if auditErr != nil {
		field("audit", yellow("unavailable")+dim(" · "+auditErr.Error()))
	} else if len(entries) == 0 {
		field("audit", dim("no entries yet"))
	} else if _, verr := audit.Verify(dir); verr != nil {
		field("audit", yellow("chain broken")+dim(" · "+verr.Error()))
	} else {
		field("audit", green(fmt.Sprintf("✓ %d entr%s", len(entries), plural(len(entries), "y", "ies")))+dim(" · chain intact"))
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Action == "backup" {
			if ts, err := time.Parse(time.RFC3339, entries[i].TS); err == nil {
				lastBackup = ts
			}
			break
		}
	}
	if lastBackup.IsZero() {
		field("backup", yellow("no archive recorded"))
	} else {
		field("backup", green("✓ "+lastBackup.Local().Format("2006-01-02 15:04")))
	}

	var next []string
	if total == 0 {
		next = append(next, dim("add your first secret: ")+cyan(addHint))
	}
	if missing > 0 {
		next = append(next, markWarn()+" "+fmt.Sprintf("%d %s missing", missing, pluralWord(missing, "declared value is", "declared values are"))+" — "+cyan("sm env")+dim(" lists them"))
	}
	if len(targets) > 0 {
		configured := configuredAgents(targets)
		if configured < len(targets) {
			next = append(next, markWarn()+" "+fmt.Sprintf("%d %s not wired", len(targets)-configured, pluralWord(len(targets)-configured, "harness is", "harnesses are"))+" — "+cyan("sm setup"))
		}
	} else if len(merged.Secrets) > 0 {
		next = append(next, markWarn()+" no supported harness detected — "+cyan("sm config")+dim(" has manual snippets"))
	}
	if lastBackup.IsZero() && total > 0 {
		next = append(next, markWarn()+" no recovery archive recorded — "+cyan("sm backup --out FILE"))
	} else if !lastBackup.IsZero() && time.Since(lastBackup) > 30*24*time.Hour {
		next = append(next, markWarn()+" last recovery archive is over 30 days old — "+cyan("sm backup --out FILE"))
	}
	if len(next) == 0 {
		fmt.Println()
		fmt.Println("  " + markOK() + dim(" nothing needs attention"))
		return nil
	}
	nextBlock(next...)
	return nil
}

func cmdAgents(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: sm agents")
	}
	targets, err := detectAgentTargets()
	if err != nil {
		return err
	}

	fmt.Printf("%s %s\n\n", bold("sm agents"), dim("· configuration on disk, not a live connection"))
	if len(targets) == 0 {
		fmt.Println("  " + markWarn() + " no supported harnesses detected on this Mac")
		fmt.Println()
		fmt.Println(heading("next"))
		fmt.Println("  " + cyan("sm config") + dim("   copy-paste wiring for every supported harness"))
		return nil
	}
	for _, target := range targets {
		status := target.Status()
		display := displayAgentStatus(status)
		state := display
		switch status {
		case "configured":
			state = green(display)
		case "not configured", "different command", "disabled", "partially configured":
			state = yellow(display)
		default:
			state = dim(display)
		}
		pad := 22 - len(display)
		if pad < 2 {
			pad = 2
		}
		fmt.Printf("  %s %-15s %s%s%s\n", agentMark(status), target.Name, state, strings.Repeat(" ", pad), dim(target.Detail))
	}

	configured := configuredAgents(targets)
	fmt.Println()
	if configured < len(targets) {
		nextBlock(markWarn()+" "+fmt.Sprintf("%d of %d %s not wired", len(targets)-configured, len(targets), pluralWord(len(targets), "harness is", "harnesses are"))+" — "+cyan("sm setup"),
			dim("one at a time: ")+cyan("sm setup --agent NAME"),
			dim("remove an entry: ")+cyan("sm setup --remove --agent NAME"))
	} else {
		fmt.Println("  " + markOK() + dim(" all detected harnesses are wired · restart apps after config changes"))
	}
	return nil
}

func detectAgentTargets() ([]wireup.Target, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return wireup.Detect(exe, home), nil
}

func configuredAgents(targets []wireup.Target) int {
	n := 0
	for _, target := range targets {
		if target.Status() == "configured" {
			n++
		}
	}
	return n
}

func agentOverview(targets []wireup.Target) string {
	if len(targets) == 0 {
		return yellow("none detected") + dim(" · sm config for manual wiring")
	}
	configured := configuredAgents(targets)
	text := fmt.Sprintf("%d/%d wired", configured, len(targets))
	if configured == len(targets) {
		return green(text)
	}
	return yellow(text)
}

func displayAgentStatus(status string) string {
	switch status {
	case "configured":
		return "wired"
	case "not configured":
		return "not wired"
	case "different command":
		return "different path"
	case "partially configured":
		return "partially wired"
	default:
		return status
	}
}

func agentMark(status string) string {
	switch status {
	case "configured":
		return markOK()
	case "not configured", "different command", "disabled", "partially configured":
		return markWarn()
	default:
		return dim("·")
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
