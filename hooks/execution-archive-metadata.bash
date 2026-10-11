# Source at the end of .bashrc, after the user's setup. No history/argv/env capture.
[[ $- == *i* && -n ${FSM_EA_SESSION:-} && ${FSM_EA_FD:-} =~ ^[0-9]+$ ]] || return 0
[[ -z ${_fsm_ea_hooked:-} ]] || return 0
# Existing DEBUG/extdebug/functrace configurations keep their own semantics.
[[ -z ${1:-} && -z $(trap -p DEBUG) && $- != *T* ]] || return 0
shopt -q extdebug && return 0
_fsm_ea_hooked=1
# Only wrap uncustomized external diagnostics. Other arguments bypass capture.
# Functions/aliases already owned by the user are preserved.
for _fsm_ea_name in date uname uptime; do
    if [[ $(type -t "$_fsm_ea_name") == file ]]; then
        eval "$_fsm_ea_name() { \"\$HOME/.local/bin/ea\" run $_fsm_ea_name \"\$@\"; }"
    fi
done
unset _fsm_ea_name
_fsm_ea_emit() {
    local previous=$1 event=$2 _fsm_ea_ack
    # Raw command and cwd cross only a local private pipe for in-memory exclusion.
    # They are never serialized to a file, hash, index, journal or report.
    printf '%s\0%s\0%s\0%s\0%s\0' "$event" "$BASHPID" "$previous" "$PWD" "${BASH_COMMAND:-}" >&"$FSM_EA_FD" 2>/dev/null || return "$previous"
    if [[ -n ${FSM_EA_ACK:-} ]]; then
        if IFS= read -r -n 1 -t .3 -u "$FSM_EA_ACK" _fsm_ea_ack && [[ $_fsm_ea_ack == R ]]; then
            if [[ $event == B ]]; then
                printf 'A\0%s\0%s\0\0\0' "$BASHPID" "$previous" >&"$FSM_EA_FD" 2>/dev/null || :
            fi
        else
            printf 'F\0%s\0%s\0\0\0' "$BASHPID" "$previous" >&"$FSM_EA_FD" 2>/dev/null || :
            _fsm_ea_failed=1
        fi
    fi
    return "$previous"
}
_fsm_ea_before() {
    local previous=$1
    [[ -z ${_fsm_ea_failed:-} ]] || return 0
    case $BASH_COMMAND in
        _fsm_ea_*|"local "*|"return "*) return 0 ;;
    esac
    _fsm_ea_emit "$previous" B
    return 0
}
_fsm_ea_prompt() { _fsm_ea_emit "$?" E; }
PROMPT_COMMAND+=("_fsm_ea_prompt")
_fsm_ea_emit 0 H
trap '_fsm_ea_before "$?"' DEBUG
