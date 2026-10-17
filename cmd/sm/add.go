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
	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("sm add", flag.ContinueOnError)
	refFlag := fs.String("ref", "", "store reference (default: isolated global/project namespace)")
	transportFlag := fs.String("transport", manifest.TransportEnv, "delivery transport: env, file, proxy or generated")
	generateFlag := fs.String("generate", "", "generate the value instead of prompting: [profile/]length, e.g. postgres/32")
	scopeFlag := fs.String("scope", "", "comma-separated local scopes (e.g. cmd:gh,cmd:git)")
	globalFlag := fs.Bool("global", false, "declare in the global manifest (~/.config/sm/manifest.toml) instead of the project")
	serviceFlag := fs.String("service", "", "group this entry under a service name, e.g. stripe")
	sensitiveFlag := fs.Bool("sensitive", true, "false marks plain config (base URLs, model names): stored and injected, not masked or reported as leaks")
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
	const usage = "usage: sm add NAME [--ref vault://path] [--transport env] [--generate postgres/32] [--scope cmd:gh] [--service stripe] [--sensitive=false]"
	switch {
	case name == "" && fs.NArg() == 1:
		name = fs.Arg(0)
	case name == "" || fs.NArg() > 0:
		return fmt.Errorf("%s", usage)
	}
	if !manifest.ValidName(name) {
		return fmt.Errorf("invalid secret name; use letters, digits and underscore")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	loaded, err := manifest.LoadOptional(cwd)
	if err != nil {
		return err
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
		ref = manifest.DefaultRef(targetPath, name)
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
		Service:   strings.TrimSpace(*serviceFlag),
	}
	if secret.Service != "" && !manifest.ValidService(secret.Service) {
		return fmt.Errorf("invalid service name %q (letters, digits, dot, dash, underscore; max 32)", secret.Service)
	}
	if !*sensitiveFlag {
		no := false
		secret.Sensitive = &no
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

	if err := secrets.AddBatch(targetPath, []secrets.Input{{Name: name, Value: value, Secret: secret}}, false); err != nil {
		return err
	}

	extra := ""
	if secret.Service != "" {
		extra = ", service " + secret.Service
	}
	if !secret.IsSensitive() {
		extra += ", config (not sensitive)"
	}
	fmt.Printf("stored %s → %s (transport %s%s)\n", name, ref, secret.Transport, extra)
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
