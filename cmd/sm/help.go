package main

import (
	"fmt"
	"strings"

	"github.com/karthikmprakash/agents-secret-manager/internal/keys"
)

type commandDoc struct {
	summary  string
	usage    string
	options  []string
	examples []string
}

var commandOrder = []string{
	"onboard", "status", "agents",
	"add", "import", "env", "exec", "inject", "rotate",
	"group", "service",
	"setup", "config", "mcp",
	"init", "doctor", "log",
	"backup", "restore",
	"ui",
	"help", "completion", "version",
}

var helpGroups = []struct {
	title    string
	commands []string
}{
	{"getting started", []string{"onboard", "status", "agents"}},
	{"secrets", []string{"add", "import", "env", "exec", "inject", "rotate"}},
	{"groups", []string{"group", "service"}},
	{"agent wiring", []string{"setup", "config", "mcp"}},
	{"project & health", []string{"init", "doctor", "log"}},
	{"recovery", []string{"backup", "restore"}},
	{"local ui", []string{"ui"}},
	{"reference", []string{"help", "completion", "version"}},
}

var commandDocs = map[string]commandDoc{
	"onboard": {
		summary: "first-run setup: vault, secrets, agent wiring",
		usage:   "sm onboard [--yes]",
		options: []string{"--yes   non-interactive: create the vault and wire detected harnesses, skip secret prompts"},
		examples: []string{
			"sm onboard",
			"sm onboard --yes",
		},
	},
	"status": {
		summary: "show what is configured and what needs attention",
		usage:   "sm status",
		examples: []string{
			"sm status",
			"sm",
		},
	},
	"agents": {
		summary: "list detected harnesses and whether sm is wired",
		usage:   "sm agents",
		examples: []string{
			"sm agents",
		},
	},
	"init": {
		summary: "create the vault identity and a project manifest here",
		usage:   "sm init",
		examples: []string{
			"sm init",
			"sm add GITHUB_TOKEN",
		},
	},
	"add": {
		summary: "store a secret and declare it for agents",
		usage:   "sm add NAME [flags]",
		options: []string{
			"--global             declare in the global manifest, available in every folder",
			"--service NAME       group related values (alias: --group)",
			"--config             mark plain config: stored and injected, not masked (alias: --sensitive=false)",
			"--generate SPEC      generate instead of prompting: [profile/]length, e.g. postgres/32",
			"--transport T        env (default), file, proxy or generated",
			"--scope LIST         limit injection to local commands, e.g. cmd:gh,cmd:git",
			"--ref vault://path   advanced: use an explicit vault reference",
		},
		examples: []string{
			"sm add --global OPENAI_API_KEY",
			"sm add STRIPE_SECRET_KEY --service stripe",
			"sm add STRIPE_BASE_URL --service stripe --config",
			`printf %s "$TOKEN" | sm add GITHUB_TOKEN`,
		},
	},
	"import": {
		summary: "move plaintext .env values into the vault, leaving sm:// refs",
		usage:   "sm import [flags] [KEY...]",
		options: []string{
			"--file PATH     source file (default .env)",
			"--global        declare in the global manifest instead of the project",
			"--group NAME    group the imported entries (alias: --service)",
			"--config        mark imported values as plain config (alias: --sensitive=false)",
			"--all           import every entry without prompting",
			"--dry-run       print the plan without changing anything",
		},
		examples: []string{
			"sm import --file .env.local --dry-run",
			"sm import --global --file ~/old.env --all",
			"sm import OPENAI_API_KEY STRIPE_SECRET_KEY",
		},
	},
	"env": {
		summary: "list declared secrets, groups and status (never values)",
		usage:   "sm env [--verbose]",
		options: []string{"--verbose   include each entry's full vault reference"},
		examples: []string{
			"sm env",
			"sm env --verbose",
		},
	},
	"exec": {
		summary: "run a command with declared secrets injected",
		usage:   "sm exec [flags] -- CMD [ARGS...]",
		options: []string{
			"--only NAMES     inject only these comma-separated names or services",
			"--profile NAME   load .env.<profile> between .env and .env.local",
			"--redact MODE    auto (default), always or never",
			"-v, --verbose    print what was resolved (names only)",
		},
		examples: []string{
			"sm exec -- npm test",
			"sm exec --only STRIPE_SECRET_KEY -- curl https://api.stripe.com",
			"sm exec --profile staging -- ./deploy.sh",
		},
	},
	"inject": {
		summary: "render a template, run a command, then shred the file",
		usage:   "sm inject [flags] -- CMD [ARGS...]",
		options: []string{
			"--tpl PATH   template containing {{sm:NAME}} placeholders",
			"--out PATH   output file (0600), removed when the command exits",
			"-v           print what was materialized (names only)",
		},
		examples: []string{
			"sm inject --tpl config.tpl --out /tmp/config.yaml -- ./run.sh",
		},
	},
	"rotate": {
		summary: "replace a stored value; every reference keeps working",
		usage:   "sm rotate NAME [--generate SPEC]",
		options: []string{"--generate SPEC   generate the new value: [profile/]length"},
		examples: []string{
			"sm rotate OPENAI_API_KEY",
			"sm rotate POSTGRES_PASSWORD --generate postgres/32",
		},
	},
	"group": {
		summary: "move one secret into or out of a group",
		usage:   "sm group NAME [--service S | --ungroup]",
		options: []string{
			"--service NAME   assign the secret to a group",
			"--ungroup        remove the group label",
		},
		examples: []string{
			"sm group STRIPE_BASE_URL --service stripe",
			"sm group STRIPE_BASE_URL --ungroup",
		},
	},
	"service": {
		summary: "rename or ungroup a whole group without deleting values",
		usage:   "sm service NAME [--rename NEW | --ungroup]",
		options: []string{
			"--rename NEW              rename the group for every entry",
			"--ungroup                 remove the group label from every entry",
			"--scope global|project    which manifest to edit (default global)",
		},
		examples: []string{
			"sm service stripe --rename payments",
			"sm service payments --ungroup",
		},
	},
	"setup": {
		summary: "wire detected harnesses to this sm binary",
		usage:   "sm setup [--dry-run] [--agent NAME]",
		options: []string{
			"--dry-run       show what would change without writing",
			"--agent NAME    wire only one detected harness",
		},
		examples: []string{
			"sm setup",
			"sm setup --dry-run",
			"sm setup --agent claude",
		},
	},
	"config": {
		summary: "print MCP wiring snippets for manual setup",
		usage:   "sm config [--agent NAME]",
		options: []string{"--agent NAME   print only one harness's snippet"},
		examples: []string{
			"sm config",
			"sm config --agent cursor",
		},
	},
	"mcp": {
		summary:  "run the MCP server over stdio (agents start this)",
		usage:    "sm mcp",
		examples: []string{"sm mcp"},
	},
	"doctor": {
		summary: "scan for plaintext copies of registered secrets",
		usage:   "sm doctor [--no-history] [--depth N]",
		options: []string{
			"--no-history   skip git history",
			"--depth N      max commits to scan (default 500)",
		},
		examples: []string{
			"sm doctor",
			"sm doctor --no-history",
		},
	},
	"log": {
		summary: "show the audit trail, or verify its hash chain",
		usage:   "sm log [--limit N] [verify]",
		options: []string{"--limit N   show the most recent N entries (default 50)"},
		examples: []string{
			"sm log",
			"sm log --limit 10",
			"sm log verify",
		},
	},
	"backup": {
		summary: "create a passphrase-encrypted local recovery archive",
		usage:   "sm backup --out FILE",
		options: []string{"--out FILE   new archive path; existing files are never overwritten"},
		examples: []string{
			"sm backup --out ~/sm-recovery.age",
		},
	},
	"restore": {
		summary: "verify or restore an archive into an empty vault",
		usage:   "sm restore --file FILE [--verify]",
		options: []string{"--verify   check the archive without changing anything"},
		examples: []string{
			"sm restore --file ~/sm-recovery.age --verify",
			"sm restore --file ~/sm-recovery.age",
		},
	},
	"ui": {
		summary: "open the local browser UI (loopback only)",
		usage:   "sm ui [--port N]",
		options: []string{
			"--port N     fixed loopback port (default: an ephemeral port)",
			"--no-open    print the URL without opening a browser",
		},
		examples: []string{
			"sm ui",
			"sm ui --port 8787",
		},
	},
	"completion": {
		summary: "print a shell completion script",
		usage:   "sm completion bash|zsh|fish",
		examples: []string{
			"sm completion zsh",
			"sm completion bash > /usr/local/etc/bash_completion.d/sm",
		},
	},
	"help": {
		summary: "show all commands or detailed help for one",
		usage:   "sm help [command]",
		examples: []string{
			"sm help",
			"sm help add",
		},
	},
	"version": {
		summary:  "print the sm version",
		usage:    "sm version",
		examples: []string{"sm version"},
	},
}

func usage() {
	if !keys.Exists() {
		fmt.Println(bold("First time here?") + "  " + cyan("sm onboard") + " " + dim("creates the vault, adds secrets and wires your agents."))
		fmt.Println()
	}

	fmt.Printf("%s %s %s\n", bold("sm"), version, dim("· secrets for agents on this Mac"))
	fmt.Println(dim("  One encrypted vault. Values never enter model context. Works with every harness over MCP."))
	fmt.Println()

	for _, group := range helpGroups {
		fmt.Println(heading(group.title))
		for _, name := range group.commands {
			printHelpLine(name, commandDocs[name].summary)
		}
		fmt.Println()
	}
	fmt.Println(dim("  sm help <command> for details · sm completion <shell> for tab completion"))
}

func printHelpLine(cmd, summary string) {
	pad := 18 - len(cmd)
	if pad < 2 {
		pad = 2
	}
	fmt.Printf("  %s%s%s\n", cyan(cmd), strings.Repeat(" ", pad), summary)
}

func printCommandHelp(name string) error {
	doc, ok := commandDocs[name]
	if !ok {
		return fmt.Errorf("unknown command %q — run `sm help` to list commands", name)
	}
	fmt.Printf("%s %s\n", bold("sm "+name), dim("— "+doc.summary))
	fmt.Println()
	fmt.Println(heading("usage"))
	fmt.Printf("  %s\n", cyan(doc.usage))
	if len(doc.options) > 0 {
		fmt.Println()
		fmt.Println(heading("options"))
		for _, option := range doc.options {
			fmt.Printf("  %s\n", option)
		}
	}
	if len(doc.examples) > 0 {
		fmt.Println()
		fmt.Println(heading("examples"))
		for _, example := range doc.examples {
			fmt.Printf("  %s\n", example)
		}
	}
	return nil
}
