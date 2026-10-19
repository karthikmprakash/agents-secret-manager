package main

import (
	"fmt"
	"strings"
)

func cmdCompletion(args []string) error {
	if len(args) == 0 {
		fmt.Println("usage: sm completion bash|zsh|fish")
		fmt.Println()
		fmt.Println("examples:")
		fmt.Println("  eval \"$(sm completion bash)\"")
		fmt.Println("  eval \"$(sm completion zsh)\"")
		fmt.Println("  sm completion fish > ~/.config/fish/completions/sm.fish")
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: sm completion bash|zsh|fish")
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	default:
		return fmt.Errorf("unknown shell %q (choose bash, zsh or fish)", args[0])
	}
	return nil
}

var completionFlagWords = map[string][]string{
	"onboard":    {"--yes", "--help"},
	"status":     {"--help"},
	"agents":     {"--help"},
	"init":       {"--help"},
	"add":        {"--global", "--service", "--group", "--config", "--sensitive", "--generate", "--transport", "--scope", "--ref", "--help"},
	"import":     {"--file", "--global", "--group", "--service", "--config", "--all", "--dry-run", "--help"},
	"env":        {"--verbose", "--show-config", "--help"},
	"get":        {"--scope", "--help"},
	"exec":       {"--only", "--profile", "--redact", "--verbose", "--help"},
	"inject":     {"--tpl", "--out", "--verbose", "--help"},
	"rotate":     {"--generate", "--help"},
	"group":      {"--service", "--ungroup", "--help"},
	"service":    {"--rename", "--ungroup", "--scope", "--help"},
	"setup":      {"--dry-run", "--agent", "--remove", "--all", "--help"},
	"config":     {"--agent", "--help"},
	"mcp":        {"--help"},
	"doctor":     {"--no-history", "--depth", "--help"},
	"log":        {"--limit", "verify", "--help"},
	"backup":     {"--out", "--help"},
	"restore":    {"--file", "--verify", "--help"},
	"ui":         {"--port", "--no-open", "--help"},
	"lock":       {"status", "set", "verify", "clear", "--stdin", "--force", "--quiet", "--yes", "--help"},
	"completion": {"bash", "zsh", "fish", "--help"},
	"version":    {"--help"},
	"help":       commandOrder,
}

func completionWords(name string) string {
	return strings.Join(completionFlagWords[name], " ")
}

var bashCompletion = `# bash completion for sm — enable with: eval "$(sm completion bash)"
_sm_complete() {
    local cur cmd
    cur="${COMP_WORDS[COMP_CWORD]}"
    cmd="${COMP_WORDS[1]}"
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "` + strings.Join(commandOrder, " ") + `" -- "${cur}") )
        return 0
    fi
    case "${cmd}" in
        add) COMPREPLY=( $(compgen -W "` + completionWords("add") + `" -- "${cur}") ) ;;
        import) COMPREPLY=( $(compgen -W "` + completionWords("import") + `" -- "${cur}") ) ;;
        group) COMPREPLY=( $(compgen -W "` + completionWords("group") + `" -- "${cur}") ) ;;
        service) COMPREPLY=( $(compgen -W "` + completionWords("service") + `" -- "${cur}") ) ;;
        env) COMPREPLY=( $(compgen -W "` + completionWords("env") + `" -- "${cur}") ) ;;
        get) COMPREPLY=( $(compgen -W "` + completionWords("get") + `" -- "${cur}") ) ;;
        rotate) COMPREPLY=( $(compgen -W "` + completionWords("rotate") + `" -- "${cur}") ) ;;
        doctor) COMPREPLY=( $(compgen -W "` + completionWords("doctor") + `" -- "${cur}") ) ;;
        setup) COMPREPLY=( $(compgen -W "` + completionWords("setup") + `" -- "${cur}") ) ;;
        config) COMPREPLY=( $(compgen -W "` + completionWords("config") + `" -- "${cur}") ) ;;
        onboard) COMPREPLY=( $(compgen -W "` + completionWords("onboard") + `" -- "${cur}") ) ;;
        ui) COMPREPLY=( $(compgen -W "` + completionWords("ui") + `" -- "${cur}") ) ;;
        exec|inject)
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=( $(compgen -W "` + completionWords("exec") + `" -- "${cur}") )
            else
                COMPREPLY=( $(compgen -c -- "${cur}") )
            fi
            ;;
        log) COMPREPLY=( $(compgen -W "` + completionWords("log") + `" -- "${cur}") ) ;;
        backup|restore)
            COMPREPLY=( $(compgen -W "` + completionWords("backup") + `" -- "${cur}") )
            if [[ "${cur}" != -* ]]; then
                COMPREPLY+=( $(compgen -f -- "${cur}") )
            fi
            ;;
        completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") ) ;;
        *) COMPREPLY=( $(compgen -W "` + completionWords("help") + ` --help" -- "${cur}") ) ;;
    esac
    return 0
}
complete -F _sm_complete sm
`

var zshCompletion = `#compdef sm
# zsh completion for sm — enable with: eval "$(sm completion zsh)"
_sm() {
    local -a commands
    commands=(
        'onboard:first-run setup: vault, secrets, agent wiring'
        'status:show what is configured and what needs attention'
        'agents:list detected harnesses and wiring status'
        'init:create a project manifest here'
        'add:store a secret and declare it'
        'import:move plaintext .env values into the vault'
        'env:list declared secrets and status'
        'exec:run a command with secrets injected'
        'inject:render a template, run, then shred'
        'rotate:replace a stored value'
        'group:move one secret into or out of a group'
        'service:rename or ungroup a whole group'
        'setup:wire detected harnesses'
        'config:print manual MCP wiring snippets'
        'mcp:run the MCP server over stdio'
        'doctor:scan for plaintext copies of secrets'
        'log:show or verify the audit trail'
        'backup:create an encrypted recovery archive'
        'restore:verify or restore an archive'
        'ui:open the local browser UI'
        'completion:print shell completion'
        'version:print the version'
        'help:show help'
    )
    if (( CURRENT == 2 )); then
        _describe -t commands 'sm command' commands
        return
    fi
    case "$words[2]" in
        add)
            _arguments \
                '--global[use the global manifest]' \
                '--service[group related values]:group:' \
                '--group[alias for --service]:group:' \
                '--config[mark as plain config]' \
                '--sensitive=[mark as sensitive]:value:(true false)' \
                '--generate[generate the value]:spec:' \
                '--transport[delivery transport]:transport:(env file proxy generated)' \
                '--scope[limit injection to commands]:scopes:' \
                '--ref[explicit vault reference]:ref:' \
                '--help[show help]' \
                '1:secret name:'
            ;;
        import)
            _arguments '--file[source file]:file:_files' '--global[use the global manifest]' '--all[import everything]' '--dry-run[show the plan]' '--help[show help]' '*:key:'
            ;;
        exec|inject)
            _arguments '--only[inject only these names]:names:' '--profile[dotenv profile]:profile:' '--redact[redact child output]:mode:(auto always never)' '--verbose[print resolved names]' '--tpl[template path]:file:_files' '--out[output path]:file:_files' '--help[show help]' '*::command:_command_names'
            ;;
        setup)
            _arguments '--dry-run[show what would change]' '--agent[wire one harness]:agent:(opencode claude hermes codex deepseek)' '--help[show help]'
            ;;
        config)
            _arguments '--agent[print one harness snippet]:agent:(claude claude-desktop cursor gemini windsurf opencode codex hermes deepseek)' '--help[show help]'
            ;;
        onboard)
            _arguments '--yes[non-interactive setup]' '--help[show help]'
            ;;
        env)
            _arguments '--verbose[show vault references]' '--show-config[show plain config values]' '--help[show help]'
            ;;
        get)
            _arguments '--scope[global or project]:scope:(global project)' '1:secret name:' '--help[show help]'
            ;;
        rotate)
            _arguments '--generate[generate the new value]:spec:' '--help[show help]'
            ;;
        group)
            _arguments '--service[group name]:group:' '--ungroup[remove the group]' '--help[show help]' '1:secret name:'
            ;;
        service)
            _arguments '--rename[new group name]:group:' '--ungroup[remove the group]' '--scope[manifest scope]:scope:(global project)' '--help[show help]' '1:group name:'
            ;;
        doctor)
            _arguments '--no-history[skip git history]' '--depth[commit depth]:count:' '--help[show help]'
            ;;
        status|agents|init|mcp|version)
            _arguments '--help[show help]'
            ;;
        log)
            _arguments '--limit[number of entries]:count:' '1:action:(verify)' '--help[show help]'
            ;;
        backup|restore)
            _arguments '--out[new archive path]:file:_files' '--file[archive path]:file:_files' '--verify[check only]' '--help[show help]'
            ;;
        ui)
            _arguments '--port[loopback port]:port:' '--no-open[do not open a browser]' '--help[show help]'
            ;;
        completion)
            _arguments '1:shell:(bash zsh fish)' '--help[show help]'
            ;;
        *)
            _arguments '--help[show help]'
            ;;
    esac
}
if [ "$funcstack[1]" = "_sm" ]; then
    _sm "$@"
else
    compdef _sm sm
fi
`

var fishCompletion = `# fish completion for sm — install with:
#   sm completion fish > ~/.config/fish/completions/sm.fish
function __sm_no_subcommand
    not __fish_seen_subcommand_from ` + strings.Join(commandOrder, " ") + `
end
complete -c sm -f
complete -c sm -n '__sm_no_subcommand' -a onboard -d 'First-run setup'
complete -c sm -n '__sm_no_subcommand' -a status -d 'Show what needs attention'
complete -c sm -n '__sm_no_subcommand' -a agents -d 'List detected harnesses'
complete -c sm -n '__sm_no_subcommand' -a init -d 'Create a project manifest'
complete -c sm -n '__sm_no_subcommand' -a add -d 'Store a secret'
complete -c sm -n '__sm_no_subcommand' -a import -d 'Import plaintext .env values'
complete -c sm -n '__sm_no_subcommand' -a env -d 'List declared secrets'
complete -c sm -n '__sm_no_subcommand' -a exec -d 'Run with secrets injected'
complete -c sm -n '__sm_no_subcommand' -a inject -d 'Render a template and run'
complete -c sm -n '__sm_no_subcommand' -a rotate -d 'Rotate a stored value'
complete -c sm -n '__sm_no_subcommand' -a group -d 'Group one secret'
complete -c sm -n '__sm_no_subcommand' -a service -d 'Rename or ungroup a group'
complete -c sm -n '__sm_no_subcommand' -a setup -d 'Wire detected harnesses'
complete -c sm -n '__sm_no_subcommand' -a config -d 'Print manual MCP snippets'
complete -c sm -n '__sm_no_subcommand' -a mcp -d 'Run the MCP server'
complete -c sm -n '__sm_no_subcommand' -a doctor -d 'Scan for plaintext copies'
complete -c sm -n '__sm_no_subcommand' -a log -d 'Show or verify the audit trail'
complete -c sm -n '__sm_no_subcommand' -a backup -d 'Create a recovery archive'
complete -c sm -n '__sm_no_subcommand' -a restore -d 'Verify or restore an archive'
complete -c sm -n '__sm_no_subcommand' -a ui -d 'Open the local UI'
complete -c sm -n '__sm_no_subcommand' -a completion -d 'Print shell completion'
complete -c sm -n '__sm_no_subcommand' -a version -d 'Print the version'
complete -c sm -n '__sm_no_subcommand' -a help -d 'Show help'

complete -c sm -n '__fish_seen_subcommand_from add' -l global -d 'Use the global manifest'
complete -c sm -n '__fish_seen_subcommand_from add' -l service -r -d 'Group name'
complete -c sm -n '__fish_seen_subcommand_from add' -l group -r -d 'Group name (alias)'
complete -c sm -n '__fish_seen_subcommand_from add' -l config -d 'Mark as plain config'
complete -c sm -n '__fish_seen_subcommand_from add' -l generate -r -d 'Generate the value'
complete -c sm -n '__fish_seen_subcommand_from add' -l transport -r -d 'Delivery transport'
complete -c sm -n '__fish_seen_subcommand_from add' -l scope -r -d 'Command scopes'
complete -c sm -n '__fish_seen_subcommand_from add' -l ref -r -d 'Explicit vault reference'
complete -c sm -n '__fish_seen_subcommand_from import' -l file -r -d 'Source file'
complete -c sm -n '__fish_seen_subcommand_from import' -l global -d 'Use the global manifest'
complete -c sm -n '__fish_seen_subcommand_from import' -l group -r -d 'Group name'
complete -c sm -n '__fish_seen_subcommand_from import' -l service -r -d 'Group name (alias)'
complete -c sm -n '__fish_seen_subcommand_from import' -l config -d 'Mark as plain config'
complete -c sm -n '__fish_seen_subcommand_from import' -l all -d 'Import everything'
complete -c sm -n '__fish_seen_subcommand_from import' -l dry-run -d 'Show the plan'
complete -c sm -n '__fish_seen_subcommand_from group' -l service -r -d 'Group name'
complete -c sm -n '__fish_seen_subcommand_from group' -l ungroup -d 'Remove the group'
complete -c sm -n '__fish_seen_subcommand_from service' -l rename -r -d 'New group name'
complete -c sm -n '__fish_seen_subcommand_from service' -l ungroup -d 'Remove the group'
complete -c sm -n '__fish_seen_subcommand_from service' -l scope -r -d 'global or project'
complete -c sm -n '__fish_seen_subcommand_from env' -l verbose -d 'Show vault references'
complete -c sm -n '__fish_seen_subcommand_from env' -l show-config -d 'Show plain config values'
complete -c sm -n '__fish_seen_subcommand_from get' -l scope -r -d 'global or project'
complete -c sm -n '__fish_seen_subcommand_from rotate' -l generate -r -d 'Generate the new value'
complete -c sm -n '__fish_seen_subcommand_from doctor' -l no-history -d 'Skip git history'
complete -c sm -n '__fish_seen_subcommand_from doctor' -l depth -r -d 'Commit depth'
complete -c sm -n '__fish_seen_subcommand_from onboard' -l yes -d 'Non-interactive setup'
complete -c sm -n '__fish_seen_subcommand_from exec' -l only -r -d 'Inject only these names'
complete -c sm -n '__fish_seen_subcommand_from exec' -l profile -r -d 'Dotenv profile'
complete -c sm -n '__fish_seen_subcommand_from exec' -l redact -r -d 'Redaction mode'
complete -c sm -n '__fish_seen_subcommand_from setup' -l dry-run -d 'Show what would change'
complete -c sm -n '__fish_seen_subcommand_from setup' -l agent -r -d 'Wire one harness'
complete -c sm -n '__fish_seen_subcommand_from config' -l agent -r -d 'Print one harness snippet'
complete -c sm -n '__fish_seen_subcommand_from log' -l limit -r -d 'Number of entries'
complete -c sm -n '__fish_seen_subcommand_from log' -a verify -d 'Verify the hash chain'
complete -c sm -n '__fish_seen_subcommand_from backup' -l out -r -F -d 'Archive path'
complete -c sm -n '__fish_seen_subcommand_from restore' -l file -r -F -d 'Archive path'
complete -c sm -n '__fish_seen_subcommand_from restore' -l verify -d 'Check only'
complete -c sm -n '__fish_seen_subcommand_from ui' -l port -r -d 'Loopback port'
complete -c sm -n '__fish_seen_subcommand_from ui' -l no-open -d 'Do not open a browser'
complete -c sm -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
`
