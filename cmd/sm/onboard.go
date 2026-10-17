package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

// cmdOnboard is the first-run wizard: vault, secrets, agent wiring, next steps.
func cmdOnboard(args []string) error {
	fs := flag.NewFlagSet("sm onboard", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "non-interactive: create the vault and wire detected agents, skip secret prompts")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm onboard [--yes]")
	}

	interactive := term.IsTerminal(int(os.Stdin.Fd())) && !*yes
	if !interactive && !*yes {
		return fmt.Errorf("no TTY: run `sm onboard --yes` for non-interactive setup")
	}
	reader := bufio.NewReader(os.Stdin)

	fmt.Println(bold("sm onboard") + dim(" — one-time setup, all local"))
	fmt.Println()

	fmt.Println(heading("[1/4] vault"))
	if err := secrets.Initialize(); err != nil {
		return err
	}
	vaultPath, _ := keys.VaultPath()
	fmt.Printf("  %s ready%s\n", markOK(), dim(" · "+shortHome(vaultPath)))

	fmt.Println()
	fmt.Println(heading("[2/4] global manifest"))
	gp, created, err := manifest.EnsureGlobal()
	if err != nil {
		return err
	}
	note := ""
	if created {
		note = " (created)"
	}
	fmt.Printf("  %s %s%s\n", markOK(), shortHome(gp), dim(note))

	global, err := manifest.Load(gp)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	var names []string
	for name := range global.Secrets {
		existing[name] = true
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Println()
	fmt.Println(heading("[3/4] secrets"))
	fmt.Println(dim("  stored once, available in every folder"))
	if len(names) > 0 {
		fmt.Printf("  %s %s\n", dim("already declared:"), strings.Join(names, ", "))
	}
	if !interactive {
		fmt.Println("  " + dim("skipped — add later with `sm add --global NAME`"))
	} else {
		added := 0
		for {
			fmt.Print("  name " + dim("(blank to finish, e.g. AWS_ACCESS_KEY_ID)") + ": ")
			line, err := reader.ReadString('\n')
			if err != nil && len(line) == 0 {
				break
			}
			name := strings.TrimSpace(line)
			if name == "" {
				break
			}
			if !envNameOK(name) {
				fmt.Println("  " + markWarn() + " use letters, digits and underscore, starting with a letter or underscore")
				continue
			}
			if existing[name] {
				fmt.Printf("  %s %s is already declared — use `sm rotate %s` to change it\n", markWarn(), name, name)
				continue
			}
			fmt.Printf("  value for %s %s: ", bold(name), dim("(hidden)"))
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			value := string(raw)
			if value == "" {
				fmt.Println("  " + dim("skipped (empty value)"))
				continue
			}
			ref := manifest.DefaultRef(gp, name)
			if err := secrets.AddBatch(gp, []secrets.Input{{Name: name, Value: value}}, false); err != nil {
				return err
			}
			existing[name] = true
			added++
			fmt.Printf("  %s stored %s %s\n", markOK(), bold(name), dim("→ "+ref))
		}
		if added == 0 {
			fmt.Println("  " + dim("no secrets added — add later with `sm add --global NAME`"))
		}
	}

	fmt.Println()
	fmt.Println(heading("[4/4] agents"))
	targets, err := detectAgentTargets()
	if err != nil {
		return err
	}
	failed := 0
	if len(targets) == 0 {
		fmt.Println("  " + markWarn() + " no supported harnesses detected")
		fmt.Println("  " + dim("manual wiring: sm config"))
	} else {
		label := make([]string, len(targets))
		for i, target := range targets {
			label[i] = target.Name
		}
		fmt.Printf("  %s %s\n", dim("detected:"), strings.Join(label, ", "))
		configure := true
		if interactive {
			fmt.Print("  configure all? [Y/n] ")
			answer, _ := reader.ReadString('\n')
			configure = !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "n")
		}
		if !configure {
			fmt.Println("  " + dim("skipped — run `sm setup` any time"))
		} else {
			for _, target := range targets {
				status, applyErr := target.Apply()
				if applyErr != nil {
					fmt.Printf("  %s %-13s %s\n", markErr(), target.Name, red(applyErr.Error()))
					failed++
					continue
				}
				fmt.Printf("  %s %-13s %s\n", markOK(), target.Name, status)
			}
		}
	}

	fmt.Println()
	if failed > 0 {
		fmt.Println("  " + markWarn() + " the vault is ready, but some harness configurations failed")
		return fmt.Errorf("%s — run `sm setup` to retry", quantity(failed, "harness configuration failed", "harness configurations failed"))
	}
	fmt.Println("  " + markOK() + " " + bold("done") + dim(" — reconnect or restart your agents"))
	lines := []string{
		dim("ask any agent: ") + `"what secrets do you have?"`,
		dim("ask: ") + `"run aws s3 ls"`,
		dim("shell: ") + cyan("sm exec -- <command>"),
	}
	if len(existing) == 0 {
		lines = append([]string{dim("add secrets once: ") + cyan("sm add --global NAME")}, lines...)
	}
	lines = append(lines, dim("see what needs attention: ")+cyan("sm status"))
	nextBlock(lines...)
	return nil
}

func envNameOK(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
