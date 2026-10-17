package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func cmdInit(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sm init takes no arguments")
	}

	fmt.Printf("%s %s\n\n", bold("sm init"), dim("· project setup"))

	if err := secrets.Initialize(); err != nil {
		return err
	}
	vaultPath, _ := keys.VaultPath()
	fmt.Printf("  %s vault ready %s\n", markOK(), dim("· "+shortHome(vaultPath)))

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	mp := filepath.Join(cwd, ".agentsecrets.toml")
	if _, err := os.Stat(mp); err == nil {
		fmt.Printf("  %s manifest already exists %s\n", markOK(), dim("· "+shortHome(mp)))
	} else {
		if err := os.WriteFile(mp, []byte(manifest.Template(filepath.Base(cwd))), 0o644); err != nil {
			return err
		}
		fmt.Printf("  %s created manifest %s\n", markOK(), dim("· "+shortHome(mp)))
	}

	added, err := ensureGitignore(cwd)
	if err != nil {
		return err
	}
	if added {
		fmt.Printf("  %s updated .gitignore %s\n", markOK(), dim("· .env.local"))
	} else {
		fmt.Printf("  %s .gitignore already covers %s\n", markOK(), dim(".env.local"))
	}

	nextBlock("store a secret: "+cyan("sm add GITHUB_TOKEN"),
		"declare an existing .env: "+cyan("sm import --file .env"),
		"run with it: "+cyan("sm exec -- <command>"))
	return nil
}

func ensureGitignore(dir string) (bool, error) {
	path := filepath.Join(dir, ".gitignore")
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == ".env.local" {
			return false, nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	prefix := ""
	if len(content) > 0 && !strings.HasSuffix(string(content), "\n") {
		prefix = "\n"
	}
	if _, err := f.WriteString(prefix + ".env.local\n"); err != nil {
		return false, err
	}
	return true, nil
}
