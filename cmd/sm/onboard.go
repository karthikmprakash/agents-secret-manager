package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
	"github.com/karthikmprakash/agents-secret-manager/internal/wireup"
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

	fmt.Println("sm onboard — one-time setup")
	fmt.Println()

	if err := secrets.Initialize(); err != nil {
		return err
	}
	fmt.Println("vault verified")

	// 2. Global manifest.
	gp, created, err := manifest.EnsureGlobal()
	if err != nil {
		return err
	}
	if created {
		fmt.Println("  ✓ created global manifest", gp)
	} else {
		fmt.Println("  ✓ global manifest", gp)
	}

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

	// 3. Secrets.
	fmt.Println()
	fmt.Println("secrets (stored once, available in every folder)")
	if len(names) > 0 {
		fmt.Printf("  already declared: %s\n", strings.Join(names, ", "))
	}
	if !interactive {
		fmt.Println("  skipped — add later with `sm add --global NAME`")
	} else {
		added := 0
		for {
			fmt.Print("  name (blank to finish, e.g. AWS_ACCESS_KEY_ID): ")
			line, err := reader.ReadString('\n')
			if err != nil && len(line) == 0 {
				break
			}
			name := strings.TrimSpace(line)
			if name == "" {
				break
			}
			if !envNameOK(name) {
				fmt.Println("  ! use letters, digits and underscore, starting with a letter or underscore")
				continue
			}
			if existing[name] {
				fmt.Printf("  ! %s is already declared — use `sm rotate %s` to change it\n", name, name)
				continue
			}
			fmt.Printf("  value for %s (hidden): ", name)
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			value := string(raw)
			if value == "" {
				fmt.Println("  skipped (empty value)")
				continue
			}
			ref := manifest.DefaultRef(gp, name)
			if err := secrets.AddBatch(gp, []secrets.Input{{Name: name, Value: value}}, false); err != nil {
				return err
			}
			existing[name] = true
			added++
			fmt.Printf("  ✓ stored %s → %s\n", name, ref)
		}
		if added == 0 {
			fmt.Println("  no secrets added — add later with `sm add --global NAME`")
		}
	}

	// 4. Agents.
	fmt.Println()
	fmt.Println("agents")
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	targets := wireup.Detect(exe, home)
	failed := 0
	if len(targets) == 0 {
		fmt.Println("  no supported agents detected")
	} else {
		label := make([]string, len(targets))
		for i, t := range targets {
			label[i] = t.Name
		}
		fmt.Printf("  detected: %s\n", strings.Join(label, ", "))
		configure := true
		if interactive {
			fmt.Print("  configure all? [Y/n] ")
			answer, _ := reader.ReadString('\n')
			configure = !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "n")
		}
		if !configure {
			fmt.Println("  skipped — run `sm setup` any time")
		} else {
			for _, t := range targets {
				status, err := t.Apply()
				if err != nil {
					fmt.Printf("  !! %-14s %v\n", t.Name, err)
					failed++
					continue
				}
				fmt.Printf("  ✓ %-14s %s\n", t.Name, status)
			}
		}
	}

	// 5. Next steps.
	fmt.Println()
	if len(existing) == 0 {
		fmt.Println("add secrets once, then every agent can use them:")
		fmt.Println("  sm add --global AWS_ACCESS_KEY_ID")
		fmt.Println("  sm add --global AWS_SECRET_ACCESS_KEY")
		fmt.Println()
	}
	if failed > 0 {
		return fmt.Errorf("vault is ready, but %d harness configurations failed; run sm setup to retry", failed)
	}
	fmt.Println("done. reconnect or restart your agents, then try:")
	fmt.Println("  ask any agent: \"what secrets do you have?\"")
	fmt.Println("  ask: \"run aws s3 ls\"")
	fmt.Println("  shell: sm exec -- <command>")
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
