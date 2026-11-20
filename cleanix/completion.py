"""Shell-completion script generation for bash, zsh and fish.

Scripts are generated with the live subcommand list, cleaner ids and config keys
baked in, so completion always matches this build.
"""

from __future__ import annotations

from cleanix.config import field_names
from cleanix.core.findings import FINDING_CATEGORIES
from cleanix.core.registry import known_ids

SUBCOMMANDS = [
    "list", "scan", "clean", "review", "info", "stats", "restore", "quarantine",
    "config", "schedule", "factory-reset", "completion", "gui",
]
# Options both `scan` and `clean` accept.
SCAN_CLEAN_OPTS = [
    "--only", "--exclude", "--all-users", "--current-user", "--min-uid",
    "--registry", "--min-size", "--profile",
]
# Only `scan` accepts these.
SCAN_ONLY_OPTS = [
    "--json", "--output", "--quiet", "--summary", "--sort", "--top", "--input",
]
# Only `clean` accepts these (scan rejects them).
CLEAN_ONLY_OPTS = [
    "--execute", "--yes", "--quarantine", "--simulate", "--interactive",
    "--act-on", "--keep", "--permanent",
]
SCAN_OPTS = SCAN_CLEAN_OPTS + SCAN_ONLY_OPTS
CLEAN_OPTS = SCAN_CLEAN_OPTS + CLEAN_ONLY_OPTS


def _ids() -> str:
    return " ".join(known_ids())


def _finding_ids() -> str:
    return " ".join(FINDING_CATEGORIES)


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
    local findingids="{_finding_ids()}"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$sub" -- "$cur") ); return
    fi
    case "$prev" in
        --only|--exclude)
            COMPREPLY=( $(compgen -W "$cleaners" -- "$cur") ); return;;
        --sort) COMPREPLY=( $(compgen -W "none size name" -- "$cur") ); return;;
        --keep) COMPREPLY=( $(compgen -W "oldest newest shortest-path" -- "$cur") ); return;;
    esac
    case "${{COMP_WORDS[1]}}" in
        scan)
            COMPREPLY=( $(compgen -W "{' '.join(SCAN_OPTS)}" -- "$cur") );;
        clean)
            COMPREPLY=( $(compgen -W "{' '.join(CLEAN_OPTS)}" -- "$cur") );;
        config)
            if [ "$COMP_CWORD" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "list get set unset path" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$cfgkeys" -- "$cur") )
            fi;;
        review)
            COMPREPLY=( $(compgen -W "$findingids --keep --permanent" -- "$cur") );;
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
                --keep) _values 'keep' oldest newest shortest-path; return;;
            esac
            if [[ "$words[2]" == scan ]]; then _values 'option' {' '.join(SCAN_OPTS)}
            else _values 'option' {' '.join(CLEAN_OPTS)}; fi;;
        config)
            if (( CURRENT == 3 )); then _values 'action' list get set unset path
            else _values 'key' $cfgkeys; fi;;
        review) _values 'option' {_finding_ids()} --keep --permanent;;
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
        'complete -c cleanix -n "__fish_seen_subcommand_from clean review" '
        '-l keep -a "oldest newest shortest-path"'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from clean" '
        f'-l act-on -a "{_finding_ids()}"'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from clean" -l permanent'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from review" '
        f'-a "{_finding_ids()}"'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from review" '
        '-l permanent'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from config" '
        f'-a "list get set unset path {_keys()}"'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from restore" -l yes'
    )
    lines.append(
        'complete -c cleanix -n "__fish_seen_subcommand_from completion" '
        '-a "bash zsh fish"'
    )
    return "\n".join(lines) + "\n"


def generate(shell: str) -> str:
    return {"bash": bash_script, "zsh": zsh_script, "fish": fish_script}[shell]()
