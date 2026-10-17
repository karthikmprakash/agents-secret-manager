// Command sm is the agent secrets manager CLI.
package main

import (
	"errors"
	"fmt"
	"os"
)

const version = "0.1.0-dev (M2)"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "add":
		err = cmdAdd(os.Args[2:])
	case "env":
		err = cmdEnv(os.Args[2:])
	case "exec":
		err = cmdExec(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("sm", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "sm: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		var ec *exitCodeError
		if errors.As(err, &ec) {
			os.Exit(ec.code)
		}
		fmt.Fprintln(os.Stderr, "sm:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`sm — secrets and environment manager for agents

usage:
  sm init                 create the vault identity, config dir and a project manifest
  sm add NAME [flags]     store a secret and declare it in .agentsecrets.toml
  sm env                  show declared secrets, transports and status (never values)
  sm exec [flags] -- CMD  run CMD with manifest secrets and .env refs resolved
  sm version              print version

flags for add:
  --ref vault://path      store reference (default vault://<name lowercased>)
  --transport T           env | file | proxy | generated (default env)
  --generate SPEC         generate the value instead of prompting: [profile/]length
  --scope LIST            comma-separated local scopes, e.g. cmd:gh,cmd:git

flags for exec:
  --profile NAME          load .env.<profile> between .env and .env.local
  -v, --verbose           print what was resolved (names only)
`)
}
