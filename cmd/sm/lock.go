package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/karthikmprakash/agents-secret-manager/internal/applock"
)

// cmdLock manages the desktop app passphrase. It is an app-level lock: the
// vault identity stays in the OS keychain, and CLI/MCP are not gated by it.
func cmdLock(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sm lock status|set|verify|clear")
	}
	switch args[0] {
	case "status":
		return lockStatus(args[1:])
	case "set":
		return lockSet(args[1:])
	case "verify":
		return lockVerify(args[1:])
	case "clear":
		return lockClear(args[1:])
	default:
		return fmt.Errorf("unknown lock command %q — use status, set, verify or clear", args[0])
	}
}

func lockStatus(args []string) error {
	fs := flag.NewFlagSet("sm lock status", flag.ContinueOnError)
	quiet := fs.Bool("quiet", false, "print nothing; exit 1 when no passphrase is set")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm lock status [--quiet]")
	}
	configured, err := applock.Configured()
	if err != nil {
		return err
	}
	if *quiet {
		if !configured {
			return &exitCodeError{code: 1}
		}
		return nil
	}
	if configured {
		fmt.Printf("%s desktop passphrase is set\n", markOK())
	} else {
		fmt.Printf("%s no desktop passphrase — run %s\n", markWarn(), cyan("sm lock set"))
	}
	fmt.Println("  " + dim("gates the desktop app only; CLI and MCP are unchanged"))
	return nil
}

func lockSet(args []string) error {
	fs := flag.NewFlagSet("sm lock set", flag.ContinueOnError)
	stdin := fs.Bool("stdin", false, "read one passphrase line from stdin (desktop shells)")
	force := fs.Bool("force", false, "replace an existing passphrase")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm lock set [--stdin] [--force]")
	}

	passphrase, err := readPassphrase(*stdin, true)
	if err != nil {
		return err
	}
	if err := applock.Set(passphrase, *force); err != nil {
		return err
	}
	fmt.Printf("%s desktop passphrase set\n", markOK())
	fmt.Println("  " + dim("Touch ID unlocks it on supported Macs; otherwise the app asks for this passphrase"))
	return nil
}

func lockVerify(args []string) error {
	fs := flag.NewFlagSet("sm lock verify", flag.ContinueOnError)
	stdin := fs.Bool("stdin", false, "read one passphrase line from stdin (desktop shells)")
	quiet := fs.Bool("quiet", false, "print nothing; use the exit code")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm lock verify [--stdin] [--quiet]")
	}

	passphrase, err := readPassphrase(*stdin, false)
	if err != nil {
		return err
	}
	ok, err := applock.Verify(passphrase)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("invalid passphrase")
	}
	if !*quiet {
		fmt.Printf("%s unlocked\n", markOK())
	}
	return nil
}

func lockClear(args []string) error {
	fs := flag.NewFlagSet("sm lock clear", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "remove without prompting")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm lock clear [--yes]")
	}
	if !*yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("no TTY: pass --yes to remove the desktop passphrase")
		}
		fmt.Print("Remove the desktop passphrase? [y/N] ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
			fmt.Println("unchanged")
			return nil
		}
	}
	if err := applock.Clear(); err != nil {
		return err
	}
	fmt.Printf("%s desktop passphrase removed\n", markOK())
	return nil
}

// readPassphrase reads from stdin for desktop shells, or prompts on a TTY.
// confirm prompts twice and requires a match when setting a new passphrase.
func readPassphrase(stdin, confirm bool) (string, error) {
	if stdin {
		line, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(line), "\r\n"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no TTY: use --stdin")
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if !confirm {
		return string(first), nil
	}
	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passphrases do not match")
	}
	return string(first), nil
}
