// Package-level presentation helpers for the sm CLI. Color is used only on a
// TTY and can be disabled with NO_COLOR or SM_NO_COLOR.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

var colorEnabled = os.Getenv("NO_COLOR") == "" && os.Getenv("SM_NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))

func paint(code, text string) string {
	if !colorEnabled {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func bold(text string) string   { return paint("1", text) }
func dim(text string) string    { return paint("2", text) }
func red(text string) string    { return paint("31", text) }
func green(text string) string  { return paint("32", text) }
func yellow(text string) string { return paint("33", text) }
func cyan(text string) string   { return paint("36", text) }

func markOK() string   { return green("✓") }
func markWarn() string { return yellow("!") }
func markErr() string  { return red("✗") }

func heading(title string) string { return bold(title) }

func nextBlock(lines ...string) {
	if len(lines) == 0 {
		return
	}
	fmt.Println()
	fmt.Println(dim("next"))
	for _, line := range lines {
		fmt.Println("  " + line)
	}
}

func shortHome(path string) string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func quantity(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, pluralWord(n, one, many))
}

// parseFlagsAndArgs parses flags even when they are interspersed with
// positional arguments, so `sm add --global NAME --config` and
// `sm add NAME --global --config` both work. The stdlib flag package otherwise
// stops at the first positional argument.
func parseFlagsAndArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional, flags []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			flagName := strings.TrimLeft(arg, "-")
			if strings.ContainsRune(flagName, '=') {
				continue
			}
			f := fs.Lookup(flagName)
			if f == nil {
				continue
			}
			if boolFlag, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && boolFlag.IsBoolFlag() {
				continue
			}
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, arg)
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return positional, nil
}

func parseOnePositional(fs *flag.FlagSet, args []string) (string, error) {
	positional, err := parseFlagsAndArgs(fs, args)
	if err != nil {
		return "", err
	}
	if len(positional) > 1 {
		return "", fmt.Errorf("unexpected argument %q", positional[1])
	}
	if len(positional) == 0 {
		return "", nil
	}
	return positional[0], nil
}

// field prints an aligned "label   value" row used by the status dashboard.
func field(label, value string) {
	fmt.Printf("  %s %s\n", dim(fmt.Sprintf("%-10s", label)), value)
}
