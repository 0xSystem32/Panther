# bash completion for panther
_panther() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    case "$prev" in
        --depth) COMPREPLY=( $(compgen -W "ecoute rapide normal approfondi" -- "$cur") ); return ;;
        --lang)  COMPREPLY=( $(compgen -W "fr en" -- "$cur") ); return ;;
        --iface) COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") ); return ;;
        --target|--port) return ;;
    esac
    COMPREPLY=( $(compgen -W "--help --version --cli --web --target --depth --iface --security --demo --lang --verbose --port" -- "$cur") )
}
complete -F _panther panther
