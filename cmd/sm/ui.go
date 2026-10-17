package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/karthikmprakash/agents-secret-manager/internal/uiserver"
)

func cmdUi(args []string) error {
	fs := flag.NewFlagSet("sm ui", flag.ContinueOnError)
	port := fs.Int("port", 0, "loopback port (0 picks a free port)")
	noOpen := fs.Bool("no-open", false, "do not open the browser")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: sm ui [--port N] [--no-open]")
	}

	srv, err := uiserver.Start(*port)
	if err != nil {
		return err
	}
	defer srv.Close()

	// Printed for wrappers (the Mac app parses this line).
	fmt.Println(srv.URL)

	if !*noOpen {
		_ = exec.Command("open", srv.URL).Start()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return nil
}
