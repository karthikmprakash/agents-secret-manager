package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
	"github.com/karthikmprakash/agents-secret-manager/internal/recovery"
	"golang.org/x/term"
)

func recoveryPassphrase(confirm bool) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("use a terminal to enter the recovery passphrase (never a command-line argument)")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Recovery passphrase (at least 12 characters): ")
	} else {
		fmt.Fprint(os.Stderr, "Recovery passphrase: ")
	}
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", fmt.Errorf("passphrases do not match")
		}
	}
	return string(first), nil
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("sm backup", flag.ContinueOnError)
	out := fs.String("out", "", "new local encrypted recovery archive (.age)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: sm backup --out recovery.age")
	}
	if _, err := os.Lstat(*out); !os.IsNotExist(err) {
		return fmt.Errorf("choose a new output file; backups are never overwritten")
	}
	passphrase, err := recoveryPassphrase(true)
	if err != nil {
		return err
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	id, err := keys.Get()
	if err != nil {
		return err
	}
	data, err := recovery.Export(dir, id, passphrase)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(*out)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	ok = true
	recordLocalRecovery(dir, "backup")
	fmt.Printf("%s encrypted recovery archive saved\n", markOK())
	fmt.Printf("  %s\n", dim(shortHome(*out)+" · 0600 · only encrypted bytes"))
	fmt.Printf("  %s\n", dim("keep the passphrase separately; project manifests remain in their repositories"))
	nextBlock("verify it now: "+cyan("sm restore --file "+*out+" --verify"),
		"store a copy off this Mac")
	return nil
}

// recordLocalRecovery links a CLI backup/restore into the same audit trail as
// the UI. Audit failures never invalidate a completed recovery operation.
func recordLocalRecovery(dir, action string) {
	_ = audit.Append(dir, audit.Entry{
		TS:      time.Now().UTC().Format(time.RFC3339),
		Session: audit.NewSession(),
		Action:  action,
		Cmd:     "sm " + action,
	})
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("sm restore", flag.ContinueOnError)
	file := fs.String("file", "", "local encrypted recovery archive")
	verify := fs.Bool("verify", false, "check the archive without changing anything")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *file == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: sm restore --file recovery.age [--verify]")
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, recovery.MaxArchive+1))
	if err != nil {
		return err
	}
	passphrase, err := recoveryPassphrase(false)
	if err != nil {
		return err
	}
	contents, err := recovery.Open(data, passphrase)
	if err != nil {
		return err
	}
	if *verify {
		summary := contents.Summary()
		fmt.Printf("%s archive verified %s\n", markOK(), dim(fmt.Sprintf("· %d global entries · %d stored values", summary.Entries, summary.StoredValues)))
		fmt.Println("  " + dim("nothing changed"))
		return nil
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	// Check before creating a destination identity.
	for _, name := range []string{"vault.age", "manifest.toml"} {
		if _, err := os.Lstat(dir + "/" + name); !os.IsNotExist(err) {
			return fmt.Errorf("restore requires an empty vault directory; existing data was not changed")
		}
	}
	id, err := keys.Get()
	if errors.Is(err, keys.ErrNotFound) {
		id, err = keys.Create()
	}
	if err != nil {
		return err
	}
	if err := contents.Restore(dir, id); err != nil {
		return err
	}
	recordLocalRecovery(dir, "restore")
	fmt.Printf("%s recovery complete\n", markOK())
	fmt.Printf("  %s\n", dim("values are encrypted with this machine's identity"))
	nextBlock("project reference manifests restore separately from their repositories",
		"check the result: "+cyan("sm status"),
		"run the app: "+cyan("sm ui"))
	return nil
}
