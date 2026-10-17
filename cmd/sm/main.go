// Command sm is the agent secrets manager CLI.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
)

var version = "0.3.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "onboard":
		err = cmdOnboard(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "add":
		err = cmdAdd(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
	case "env":
		err = cmdEnv(os.Args[2:])
	case "exec":
		err = cmdExec(os.Args[2:])
	case "inject":
		err = cmdInject(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "mcp":
		err = cmdMcp(os.Args[2:])
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "group":
		err = cmdGroup(os.Args[2:])
	case "ui":
		err = cmdUi(os.Args[2:])
	case "log":
		err = cmdLog(os.Args[2:])
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
	if !keys.Exists() {
		fmt.Println("First time here? Run `sm onboard` — it creates the vault, offers to store")
		fmt.Println("secrets, and connects every agent harness it finds.")
		fmt.Println()
	}
	fmt.Print(`sm — secrets and environment manager for agents

usage:
  sm onboard [--yes]      first-run wizard: vault, secrets, agent wiring
  sm init                 create the vault identity, config dir and a project manifest
  sm add NAME [flags]     store a secret and declare it in .agentsecrets.toml
  sm import [flags]       move plaintext .env values into the vault, leave sm:// refs
  sm env                  show declared secrets, transports and status (never values)
  sm exec [flags] -- CMD  run CMD with manifest secrets and .env refs resolved
  sm inject [flags] -- CMD
                          render a template to a 0600 file, run CMD, shred on exit
  sm doctor [flags]       scan rc files, transcripts, MCP configs and git history for leaks
  sm rotate NAME [flags]  replace a stored value; every ref keeps working
  sm mcp                  run the MCP server over stdio (agent clients start this)
  sm setup [--dry-run]    detect installed agents and wire the MCP server into them
  sm config [--agent NAME]
                          print MCP config snippets for manual wiring
  sm group NAME --service S
                          move a secret into a service group (or --ungroup)
  sm ui [--port N]        open the local desktop UI (loopback, token required)
  sm log [verify]         show the audit trail, or verify its hash chain
  sm version              print version

flags for add:
  --ref vault://path      store reference (default: isolated global/project namespace)
  --transport T           env | file | proxy | generated (default env)
  --generate SPEC         generate the value instead of prompting: [profile/]length
  --scope LIST            comma-separated local scopes, e.g. cmd:gh,cmd:git
  --global                declare in the global manifest (~/.config/sm/manifest.toml)
                          instead of the project — available to every project

flags for import:
  --file PATH             dotenv file to migrate (default .env)
  --global                declare in the global manifest instead of the project
  --all                   import every plaintext entry without prompting
  --dry-run               print the plan without changing anything
  (positional KEYs import just those entries)

flags for exec:
  --only NAMES            inject only these comma-separated secret names
  --profile NAME          load .env.<profile> between .env and .env.local
  --redact MODE           redact secret values in child output: auto | always | never
                          (auto: on when output is not a terminal)
  -v, --verbose           print what was resolved (names only)

flags for inject:
  --tpl PATH              template with {{sm:NAME}} placeholders
  --out PATH              output file (0600, shredded when the command exits)
  -v, --verbose           print what was materialized (names only)

flags for doctor:
  --no-history            skip git history
  --depth N               max commits to scan (default 500)

flags for rotate:
  --generate SPEC         generate the new value: [profile/]length
`)
}
