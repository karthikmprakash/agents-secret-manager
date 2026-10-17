package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func cmdInit(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sm init takes no arguments")
	}

	// 1. Vault identity: Keychain-backed, or supplied via SM_IDENTITY.
	switch {
	case os.Getenv("SM_IDENTITY") != "":
		fmt.Println("using identity from SM_IDENTITY (Keychain skipped)")
	case keys.Exists():
		fmt.Println("vault identity already exists in Keychain")
	default:
		if _, err := keys.Create(); err != nil {
			return err
		}
		fmt.Println("created vault identity in Keychain (service \"sm\")")
	}

	identity, err := keys.Get()
	if err != nil {
		return err
	}

	// 2. Vault file: materialize it (empty) if missing.
	vaultPath, err := keys.VaultPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		v, err := vaultfile.Open(vaultPath, identity)
		if err != nil {
			return err
		}
		if err := v.Save(); err != nil {
			return err
		}
		fmt.Println("created empty vault:", vaultPath)
	} else {
		// Fail fast if the vault cannot be opened (wrong identity, corruption).
		if _, err := vaultfile.Open(vaultPath, identity); err != nil {
			return err
		}
		fmt.Println("vault ok:", vaultPath)
	}

	// 3. Project manifest in the current directory.
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	mp := filepath.Join(cwd, ".agentsecrets.toml")
	if _, err := os.Stat(mp); err == nil {
		fmt.Println("manifest already exists:", mp)
	} else {
		if err := os.WriteFile(mp, []byte(manifest.Template(filepath.Base(cwd))), 0o644); err != nil {
			return err
		}
		fmt.Println("created manifest:", mp)
	}

	// 4. Keep .env.local out of git.
	if err := ensureGitignore(cwd); err != nil {
		return err
	}

	cfgDir, _ := config.Dir()
	fmt.Printf("\nconfig dir: %s\n", cfgDir)
	fmt.Println("\nnext:")
	fmt.Println("  sm add GITHUB_TOKEN     # prompted; stored encrypted, never on disk in plaintext")
	fmt.Println("  sm env                  # declared secrets and status — never values")
	return nil
}

func ensureGitignore(dir string) error {
	path := filepath.Join(dir, ".gitignore")
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == ".env.local" {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	prefix := ""
	if len(content) > 0 && !strings.HasSuffix(string(content), "\n") {
		prefix = "\n"
	}
	if _, err := f.WriteString(prefix + ".env.local\n"); err != nil {
		return err
	}
	fmt.Println("updated .gitignore (.env.local)")
	return nil
}
