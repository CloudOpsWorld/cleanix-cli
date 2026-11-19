"""Shell-completion script generation for bash, zsh and fish.

Scripts are generated with the live subcommand list, cleaner ids and config keys
baked in, so completion always matches this build.
"""

from __future__ import annotations

from cleanix.config import field_names
from cleanix.core.registry import known_ids

SUBCOMMANDS = [
    "list", "scan", "clean", "info", "stats", "restore", "quarantine",
    "config", "schedule", "factory-reset", "completion", "gui",
]
SCAN_CLEAN_OPTS = [
    "--only", "--exclude", "--json", "--output", "--quiet", "--summary",
    "--sort", "--top", "--all-users", "--current-user", "--min-uid",
    "--execute", "--yes", "--quarantine", "--registry",
]


def _ids() -> str:
    return " ".join(known_ids())


def _keys() -> str:
    return " ".join(field_names())


def bash_script() -> str:
    return f"""# cleanix bash completion — source this file or install to
# /etc/bash_completion.d/cleanix
_cleanix() {{
    local cur prev words cword
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    local sub="{' '.join(SUBCOMMANDS)}"
    local cleaners="{_ids()}"
    local cfgkeys="{_keys()}"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$sub" -- "$cur") ); return
    fi
    case "$prev" in
        --only|--exclude)
            COMPREPLY=( $(compgen -W "$cleaners" -- "$cur") ); return;;
        --sort) COMPREPLY=( $(compgen -W "none size name" -- "$cur") ); return;;
    esac
    case "${{COMP_WORDS[1]}}" in
        scan|clean)
            COMPREPLY=( $(compgen -W "{' '.join(SCAN_CLEAN_OPTS)}" -- "$cur") );;
        config)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "list get set unset path" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$cfgkeys" -- "$cur") )
            fi;;
        quarantine)
            COMPREPLY=( $(compgen -W "list empty" -- "$cur") );;
        restore)
            COMPREPLY=( $(compgen -W "--yes" -- "$cur") );;
        schedule)
            COMPREPLY=( $(compgen -W "install uninstall status --frequency" -- "$cur") );;
        factory-reset)
            COMPREPLY=( $(compgen -W "--scope --execute" -- "$cur") );;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") );;
        list) COMPREPLY=( $(compgen -W "--all" -- "$cur") );;
    esac
}}
complete -F _cleanix cleanix
"""


def zsh_script() -> str:
    return f"""#compdef cleanix
# cleanix zsh completion — install to a dir on your $fpath as _cleanix
_cleanix() {{
    local -a subs cleaners cfgkeys
    subs=({' '.join(SUBCOMMANDS)})
    cleaners=({_ids()})
    cfgkeys=({_keys()})
    if (( CURRENT == 2 )); then
        _describe 'command' subs; return
    fi
    case "$words[2]" in
        scan|clean)
            case "$words[CURRENT-1]" in
                --only|--exclude) _values 'cleaner' $cleaners; return;;
                --sort) _values 'sort' none size name; return;;
            esac
            _values 'option' {' '.join(SCAN_CLEAN_OPTS)};;
        config)
            if (( CURRENT == 3 )); then _values 'action' list get set unset path
            else _values 'key' $cfgkeys; fi;;
        quarantine) _values 'action' list empty;;
        restore) _values 'option' --yes;;
        schedule) _values 'action' install uninstall status;;
        completion) _values 'shell' bash zsh fish;;
    esac
}}
compdef _cleanix cleanix
"""


def fish_script() -> str:
    lines = [
        "# cleanix fish completion — install to "
        "~/.config/fish/completions/cleanix.fish",
        "complete -c cleanix -f",
    ]
    subs = " ".join(SUBCOMMANDS)
    lines.append(
        f'complete -c cleanix -n "__fish_use_subcommand" -a "{subs}"'
    )
    for opt in ("--only", "--exclude"):
        lines.append(
            f'complete -c cleanix -n "__fish_seen_subcommand_from scan clean" '
            f'-l {opt.lstrip("-")} -a "{_ids()}"'
        )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from config" '
        f'-a "list get set unset path {_keys()}"'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from completion" '
        '-a "bash zsh fish"'
    )
    return "\n".join(lines) + "\n"


def generate(shell: str) -> str:
    return {"bash": bash_script, "zsh": zsh_script, "fish": fish_script}[shell]()
