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

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/resolve"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("sm import", flag.ContinueOnError)
	file := fs.String("file", ".env", "dotenv file to migrate (relative to the project root)")
	all := fs.Bool("all", false, "import every plaintext entry without prompting")
	dryRun := fs.Bool("dry-run", false, "print the plan without changing anything")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	keyArgs := fs.Args()

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		return err
	}
	if loaded.Project == nil {
		return fmt.Errorf("no project manifest found — run `sm init` first")
	}
	projectDir := filepath.Dir(loaded.ProjectPath)

	path := *file
	if !filepath.IsAbs(path) {
		path = filepath.Join(projectDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	parsed, err := resolve.ParseDotenv(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	merged := loaded.Merged()

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
	for _, k := range selected {
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

	refs := map[string]string{}
	for _, k := range toImport {
		value := parsed[k]
		ref := "vault://" + strings.ToLower(k)
		declared, isDeclared := merged.Secrets[k]
		if isDeclared {
			ref = declared.Ref
		}
		r, err := manifest.ParseRef(ref)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}

		if isDeclared {
			if existing, found, _ := v.Get(r.Path); found {
				if existing != value {
					fmt.Fprintf(os.Stderr, "sm: warning: vault value for %s differs from %s — kept the vault value\n", k, path)
				}
			} else if err := v.Set(r.Path, value); err != nil {
				return err
			}
		} else {
			if err := v.Set(r.Path, value); err != nil {
				return err
			}
			if err := manifest.AppendSecret(loaded.ProjectPath, k, manifest.Secret{Ref: ref, Transport: manifest.TransportEnv}); err != nil {
				return err
			}
		}
		refs[k] = "sm://" + k
	}

	if err := os.WriteFile(path, resolve.ReplaceValues(data, refs), 0o644); err != nil {
		return err
	}

	fmt.Printf("imported %d secret(s) into the vault — %s now holds sm:// refs\n", len(toImport), path)
	fmt.Println("commit the manifest change:", loaded.ProjectPath)
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
