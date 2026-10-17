// Package runner handles subprocess cancellation without leaking vault controls.
package runner

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func Environment(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "SM_IDENTITY=") {
			out = append(out, kv)
		}
	}
	return out
}

// Command resolves the executable using the child's PATH, not the GUI parent's.
func Command(args, env []string) *exec.Cmd {
	name := args[0]
	if !strings.ContainsRune(name, os.PathSeparator) {
		for _, kv := range env {
			if !strings.HasPrefix(kv, "PATH=") {
				continue
			}
			for _, dir := range filepath.SplitList(strings.TrimPrefix(kv, "PATH=")) {
				if dir == "" || dir == "." {
					continue
				}
				p := filepath.Join(dir, name)
				if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
					name = p
					break
				}
			}
			break
		}
	}
	cmd := exec.Command(name, args[1:]...)
	cmd.Env = Environment(env)
	return cmd
}

// Run relays signals only after Start has published a Process, and joins the
// signal goroutine before returning. No goroutine races with Start/Wait.
func Run(cmd *exec.Cmd) error {
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return err
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	<-stopped
	return err
}

// Shell isolates MCP commands in a process group so cancellation kills spawned
// descendants as well as the shell. WaitDelay bounds inherited output pipes.
func Shell(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	return cmd
}
