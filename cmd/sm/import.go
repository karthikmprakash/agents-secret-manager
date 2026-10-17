package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/resolve"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("sm import", flag.ContinueOnError)
	file := fs.String("file", ".env", "dotenv file to migrate (relative to the project root, or the current directory with --global)")
	all := fs.Bool("all", false, "import every plaintext entry without prompting")
	dryRun := fs.Bool("dry-run", false, "print the plan without changing anything")
	globalFlag := fs.Bool("global", false, "declare in the global manifest (~/.config/sm/manifest.toml) instead of the project")
	serviceFlag := fs.String("service", "", "group the imported entries under a service name, e.g. stripe")
	groupFlag := fs.String("group", "", "alias for --service")
	configFlag := fs.Bool("config", false, "mark imported values as plain config (alias for --sensitive=false)")
	sensitiveFlag := fs.Bool("sensitive", true, "false marks the imported entries as plain config (not masked, not reported as leaks)")
	keyArgs, err := parseFlagsAndArgs(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	service := strings.TrimSpace(*serviceFlag)
	group := strings.TrimSpace(*groupFlag)
	if service != "" && group != "" && service != group {
		return fmt.Errorf("--service and --group disagree; use one group name")
	}
	if service == "" {
		service = group
	}
	if service != "" && !manifest.ValidService(service) {
		return fmt.Errorf("invalid group name %q (letters, digits, dot, dash, underscore; max 32)", service)
	}
	sensitive := *sensitiveFlag
	if *configFlag {
		sensitive = false
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadOptional(cwd)
	if err != nil {
		return err
	}

	baseDir := cwd
	if !*globalFlag && loaded.ProjectPath != "" {
		baseDir = filepath.Dir(loaded.ProjectPath)
	}
	path := *file
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	parsed, err := resolve.ParseDotenv(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	var targetPath string
	if *globalFlag {
		gp, err := manifest.GlobalPath()
		if err != nil {
			return err
		}
		targetPath = gp
	} else {
		if loaded.Project == nil {
			return fmt.Errorf("no project manifest found — run `sm init` first (or use --global)")
		}
		targetPath = loaded.ProjectPath
	}

	var selected []string
	switch {
	case len(keyArgs) > 0:
		for _, k := range keyArgs {
			if _, ok := parsed[k]; !ok {
				return fmt.Errorf("%s: no key %q", path, k)
			}
			selected = append(selected, k)
		}
	case *all:
		selected = resolve.Keys(data)
	default:
		if *dryRun {
			selected = resolve.Keys(data)
			break
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("no TTY: pass --all or name the keys to import")
		}
		reader := bufio.NewReader(os.Stdin)
		for _, k := range resolve.Keys(data) {
			v := parsed[k]
			if v == "" || isRefValue(v) {
				continue
			}
			fmt.Printf("import %s (%s)? [y/N] ", k, fingerprint(v))
			answer, _ := reader.ReadString('\n')
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y") {
				selected = append(selected, k)
			}
		}
	}

	var toImport []string
	seen := map[string]bool{}
	for _, k := range selected {
		if seen[k] {
			continue
		}
		seen[k] = true
		v := parsed[k]
		if v == "" || isRefValue(v) {
			continue
		}
		toImport = append(toImport, k)
	}
	if len(toImport) == 0 {
		fmt.Println("nothing to import")
		return nil
	}

	if *dryRun {
		for _, k := range toImport {
			fmt.Printf("would import %s → sm://%s (%s)\n", k, k, fingerprint(parsed[k]))
		}
		return nil
	}

	if *globalFlag {
		if _, _, err := manifest.EnsureGlobal(); err != nil {
			return err
		}
	}
	var sensitivePtr *bool
	if !sensitive {
		no := false
		sensitivePtr = &no
	}
	refs := map[string]string{}
	inputs := make([]secrets.Input, 0, len(toImport))
	for _, k := range toImport {
		inputs = append(inputs, secrets.Input{
			Name:   k,
			Value:  parsed[k],
			Secret: manifest.Secret{Service: service, Sensitive: sensitivePtr},
		})
		refs[k] = "sm://" + k
	}
	if err := secrets.AddBatch(targetPath, inputs, true); err != nil {
		return err
	}
	if err := safeio.Write(path, resolve.ReplaceValues(data, refs), 0o600); err != nil {
		return err
	}

	fmt.Printf("%s imported %s into the vault\n", markOK(), bold(fmt.Sprintf("%d %s", len(toImport), pluralWord(len(toImport), "value", "values"))))
	fmt.Printf("  %s\n", dim(shortHome(path)+" now holds sm:// refs"))
	if *globalFlag {
		fmt.Printf("  %s\n", dim("global manifest: "+shortHome(targetPath)))
	} else {
		fmt.Printf("  %s\n", dim("project manifest: "+shortHome(targetPath)+" · commit it"))
	}
	nextBlock("use them: "+cyan("sm exec -- <command>"),
		dim("check the declared entries: ")+cyan("sm env"))
	return nil
}

func isRefValue(v string) bool {
	return strings.HasPrefix(v, "sm://") || strings.HasPrefix(v, "vault://")
}

// fingerprint identifies a value for interactive prompts without revealing it.
func fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("len %d, sha256:%x", len(v), sum[:4])
}
