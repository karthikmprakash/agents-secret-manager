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
	groupFlag := fs.String("group", "", "alias for --service")
	configFlag := fs.Bool("config", false, "mark plain config (base URLs, model names): stored and injected, not masked or reported as leaks")
	sensitiveFlag := fs.Bool("sensitive", true, "false marks plain config (base URLs, model names): stored and injected, not masked or reported as leaks")
	const usage = "usage: sm add NAME [--global] [--group NAME] [--config] [--generate SPEC]"
	name, err := parseOnePositional(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if name == "" {
		return fmt.Errorf("%s", usage)
	}
	if !manifest.ValidName(name) {
		return fmt.Errorf("invalid secret name; use letters, digits and underscore")
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
		Service:   service,
	}
	if !sensitive {
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

	details := []string{"transport " + secret.Transport}
	if secret.Service != "" {
		details = append(details, "group "+secret.Service)
	}
	if !secret.IsSensitive() {
		details = append(details, "config (not sensitive)")
	}
	fmt.Printf("%s stored %s %s\n", markOK(), bold(name), dim("→ "+ref))
	fmt.Printf("  %s\n", dim(strings.Join(details, " · ")))
	if *globalFlag {
		fmt.Printf("  %s\n", dim("global manifest: "+shortHome(targetPath)+" · available in every folder"))
	} else {
		fmt.Printf("  %s\n", dim("project manifest: "+shortHome(targetPath)+" · commit it"))
	}
	nextBlock("use it: "+cyan("sm exec --only "+name+" -- <command>"),
		dim("or ask an agent to run a command that needs it"))
	return nil
}

// promptValue reads the secret from the terminal (hidden) or from piped stdin.
func promptValue(name string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprintf(os.Stderr, "value for %s: ", bold(name))
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
