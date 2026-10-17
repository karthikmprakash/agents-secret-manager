package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/karthikmprakash/agents-secret-manager/internal/generate"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("sm add", flag.ContinueOnError)
	refFlag := fs.String("ref", "", "store reference (default vault://<name lowercased>)")
	transportFlag := fs.String("transport", manifest.TransportEnv, "delivery transport: env, file, proxy or generated")
	generateFlag := fs.String("generate", "", "generate the value instead of prompting: [profile/]length, e.g. postgres/32")
	scopeFlag := fs.String("scope", "", "comma-separated local scopes (e.g. cmd:gh,cmd:git)")
	globalFlag := fs.Bool("global", false, "declare in the global manifest (~/.config/sm/manifest.toml) instead of the project")
	// Accept the name before or after flags: stdlib flag stops parsing at the
	// first positional argument, so pull a leading name out first.
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	const usage = "usage: sm add NAME [--ref vault://path] [--transport env] [--generate postgres/32] [--scope cmd:gh]"
	switch {
	case name == "" && fs.NArg() == 1:
		name = fs.Arg(0)
	case name == "" || fs.NArg() > 0:
		return fmt.Errorf("%s", usage)
	}
	if strings.ContainsAny(name, " \t\n") {
		return fmt.Errorf("secret name must not contain whitespace")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadLayers(cwd)
	if err != nil {
		if !*globalFlag {
			return err
		}
		loaded = &manifest.Loaded{}
	}
	if _, exists := loaded.Merged().Secrets[name]; exists {
		return fmt.Errorf("secret %s is already declared — use `sm rotate %s`", name, name)
	}

	var targetPath string
	if *globalFlag {
		gp, _, err := manifest.EnsureGlobal()
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

	ref := *refFlag
	if ref == "" {
		ref = "vault://" + strings.ToLower(name)
	}
	r, err := manifest.ParseRef(ref)
	if err != nil {
		return err
	}
	if r.Scheme != "vault" {
		return fmt.Errorf("only vault:// refs are supported in v0.1 (connectors arrive in v0.3)")
	}

	secret := manifest.Secret{
		Ref:       ref,
		Transport: *transportFlag,
		Generate:  *generateFlag,
	}
	for _, s := range strings.Split(*scopeFlag, ",") {
		if s = strings.TrimSpace(s); s != "" {
			secret.Scope = append(secret.Scope, s)
		}
	}

	var value string
	if *generateFlag != "" {
		value, err = generate.Value(*generateFlag)
		if err != nil {
			return err
		}
	} else {
		value, err = promptValue(name)
		if err != nil {
			return err
		}
	}
	if value == "" {
		return fmt.Errorf("empty value; nothing stored")
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
	if err := v.Set(r.Path, value); err != nil {
		return fmt.Errorf("write vault: %w", err)
	}

	if err := manifest.AppendSecret(targetPath, name, secret); err != nil {
		return fmt.Errorf("value stored at %s but manifest update failed: %w", ref, err)
	}

	fmt.Printf("stored %s → %s (transport %s)\n", name, ref, secret.Transport)
	if *globalFlag {
		fmt.Println("updated global manifest:", targetPath)
	} else {
		fmt.Println("commit the manifest change:", targetPath)
	}
	return nil
}

// promptValue reads the secret from the terminal (hidden) or from piped stdin.
func promptValue(name string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprintf(os.Stderr, "value for %s: ", name)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
