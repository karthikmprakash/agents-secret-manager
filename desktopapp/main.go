// Command sm-desktop is the Linux desktop shell for sm.
//
// It is a small GTK + WebKitGTK window (and a Cocoa window when built on
// macOS for development) that starts with an app lock and then loads the same
// loopback UI as `sm ui`. The lock is app-level: the CLI and MCP are not
// gated by it.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	webview "github.com/webview/webview_go"
)

//go:embed lock.html
var lockHTML string

//go:embed icon-light.svg
var iconSVG string

var urlPattern = regexp.MustCompile(`http://127\.0\.0\.1:[0-9]+/\?token=[a-f0-9]+`)

// Fifteen minutes without input returns to the lock screen.
const idleScript = `(function () {
  let timer;
  function reset() {
    clearTimeout(timer);
    timer = setTimeout(function () {
      try { window.lock && window.lock(); } catch (error) {}
    }, 15 * 60 * 1000);
  }
  ["pointerdown", "keydown", "wheel", "touchstart", "mousemove"].forEach(function (name) {
    addEventListener(name, reset, { passive: true });
  });
  addEventListener("keydown", function (event) {
    if ((event.metaKey || event.ctrlKey) && event.shiftKey && event.key.toLowerCase() === "l") {
      event.preventDefault();
      try { window.lock && window.lock(); } catch (error) {}
    }
  });
  reset();
})();`

type lockState struct {
	Configured  bool `json:"configured"`
	Fingerprint bool `json:"fingerprint"`
}

var (
	mu   sync.Mutex
	ui   *exec.Cmd
	view webview.WebView
	sm   string
)

func main() {
	var err error
	sm, err = findSM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sm-desktop:", err)
		os.Exit(1)
	}
	view = webview.New(false)
	defer view.Destroy()
	view.SetTitle("sm — secrets for agents")
	view.SetSize(1040, 720, webview.HintNone)
	if err := bind(); err != nil {
		fmt.Fprintln(os.Stderr, "sm-desktop:", err)
		os.Exit(1)
	}
	view.Init(idleScript)
	view.SetHtml(lockPage())
	view.Run()
	stopUI()
}

func lockPage() string {
	return strings.Replace(lockHTML, "{{ICON}}", iconSVG, 1)
}

func bind() error {
	if err := view.Bind("lockState", func() (lockState, error) {
		return lockState{
			Configured:  runSM([]string{"lock", "status", "--quiet"}, "") == 0,
			Fingerprint: fingerprintAvailable(),
		}, nil
	}); err != nil {
		return err
	}
	if err := view.Bind("unlock", func(passphrase string) (string, error) {
		if runSM([]string{"lock", "verify", "--stdin", "--quiet"}, passphrase+"\n") != 0 {
			return "Incorrect passphrase.", nil
		}
		if err := startUI(); err != nil {
			return err.Error(), nil
		}
		return "", nil
	}); err != nil {
		return err
	}
	if err := view.Bind("setup", func(passphrase, confirm string) (string, error) {
		if len([]rune(passphrase)) < 8 {
			return "Use at least 8 characters.", nil
		}
		if passphrase != confirm {
			return "Passphrases do not match.", nil
		}
		if runSM([]string{"lock", "set", "--stdin"}, passphrase+"\n") != 0 {
			return "Could not save the desktop passphrase.", nil
		}
		if err := startUI(); err != nil {
			return err.Error(), nil
		}
		return "", nil
	}); err != nil {
		return err
	}
	if err := view.Bind("fingerprint", func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "fprintd-verify")
		cmd.Stdout, cmd.Stderr = nil, nil
		if err := cmd.Run(); err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return "Fingerprint timed out.", nil
			}
			return "Fingerprint did not match.", nil
		}
		if err := startUI(); err != nil {
			return err.Error(), nil
		}
		return "", nil
	}); err != nil {
		return err
	}
	return view.Bind("lock", func() (string, error) {
		lock()
		return "", nil
	})
}

func fingerprintAvailable() bool {
	_, err := exec.LookPath("fprintd-verify")
	return err == nil
}

func startUI() error {
	mu.Lock()
	defer mu.Unlock()
	if ui != nil {
		return nil
	}
	cmd := exec.Command(sm, "ui", "--no-open")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start sm ui: %w", err)
	}
	url, err := readURL(stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	ui = cmd
	view.Dispatch(func() { view.Navigate(url) })
	go func() {
		_ = cmd.Wait()
		mu.Lock()
		if ui == cmd {
			ui = nil
		}
		mu.Unlock()
	}()
	return nil
}

func readURL(stdout io.Reader) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	reader := bufio.NewReader(stdout)
	for time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if match := urlPattern.FindString(line); match != "" {
			return match, nil
		}
		if err != nil {
			return "", fmt.Errorf("sm ui did not print a loopback URL")
		}
	}
	return "", fmt.Errorf("timed out waiting for sm ui")
}

func stopUI() {
	mu.Lock()
	defer mu.Unlock()
	if ui == nil {
		return
	}
	_ = ui.Process.Kill()
	_ = ui.Wait()
	ui = nil
}

func lock() {
	stopUI()
	view.Dispatch(func() { view.SetHtml(lockPage()) })
}

// runSM runs the bundled CLI. A passphrase only travels on stdin.
func runSM(arguments []string, stdin string) int {
	cmd := exec.Command(sm, arguments...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		return 127
	}
	return 0
}

// findSM prefers an explicit SM_BIN, then a sibling of this executable, then
// the PATH. Release bundles ship both binaries in the same directory.
func findSM() (string, error) {
	if explicit := os.Getenv("SM_BIN"); explicit != "" {
		return explicit, nil
	}
	if executable, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(executable), "sm")
		if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
			return sibling, nil
		}
	}
	if path, err := exec.LookPath("sm"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("could not find the sm binary; put it beside this app or set SM_BIN")
}
