// Command sm is the agent secrets manager CLI.
package main

import (
	"errors"
	"fmt"
	"os"
)

var version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		if err := cmdStatus(nil); err != nil {
			fmt.Fprintln(os.Stderr, "sm:", err)
			os.Exit(1)
		}
		return
	}

	command := os.Args[1]
	args := os.Args[2:]

	if command == "help" {
		switch len(args) {
		case 0:
			usage()
		case 1:
			if args[0] == "-h" || args[0] == "--help" {
				usage()
				return
			}
			if err := printCommandHelp(args[0]); err != nil {
				fmt.Fprintln(os.Stderr, "sm:", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintln(os.Stderr, "sm: usage: sm help [command]")
			os.Exit(2)
		}
		return
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") && knownCommand(command) {
		if err := printCommandHelp(command); err != nil {
			fmt.Fprintln(os.Stderr, "sm:", err)
			os.Exit(1)
		}
		return
	}

	var err error
	switch command {
	case "onboard":
		err = cmdOnboard(args)
	case "status":
		err = cmdStatus(args)
	case "agents":
		err = cmdAgents(args)
	case "lock":
		err = cmdLock(args)
	case "init":
		err = cmdInit(args)
	case "add":
		err = cmdAdd(args)
	case "import":
		err = cmdImport(args)
	case "env":
		err = cmdEnv(args)
	case "exec":
		err = cmdExec(args)
	case "inject":
		err = cmdInject(args)
	case "doctor":
		err = cmdDoctor(args)
	case "rotate":
		err = cmdRotate(args)
	case "mcp":
		err = cmdMcp(args)
	case "setup":
		err = cmdSetup(args)
	case "config":
		err = cmdConfig(args)
	case "group":
		err = cmdGroup(args)
	case "service":
		err = cmdService(args)
	case "backup":
		err = cmdBackup(args)
	case "restore":
		err = cmdRestore(args)
	case "ui":
		err = cmdUi(args)
	case "log":
		err = cmdLog(args)
	case "completion":
		err = cmdCompletion(args)
	case "version", "--version", "-v":
		fmt.Println("sm", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "sm: unknown command %q\n\n", command)
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

func knownCommand(name string) bool {
	for _, command := range commandOrder {
		if command == name {
			return true
		}
	}
	return false
}
