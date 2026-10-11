# Source at the end of .bashrc, after the user's setup. No history/argv/env capture.
[[ $- == *i* && -n ${FSM_EA_SESSION:-} && ${FSM_EA_FD:-} =~ ^[0-9]+$ ]] || return 0
[[ -z ${_fsm_ea_hooked:-} ]] || return 0
# Existing DEBUG/extdebug/functrace configurations keep their own semantics.
[[ -z $(trap -p DEBUG) && $- != *T* ]] || return 0
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
    local previous=$1 event=$2
    # A nonblocking private pipe. No BASH_COMMAND, history or input is serialized.
    printf '%s\t%s\t%s\n' "$event" "$BASHPID" "$previous" >&"$FSM_EA_FD" 2>/dev/null || :
    return "$previous"
}
_fsm_ea_before() {
    local previous=$1
    case $BASH_COMMAND in
        _fsm_ea_*|"local "*|"return "*) return 0 ;;
    esac
    _fsm_ea_emit "$previous" B
    return 0
}
_fsm_ea_prompt() { _fsm_ea_emit "$?" E; }
# Preserve scalar/array PROMPT_COMMAND and don't replace a user's existing trap.
PROMPT_COMMAND+=("_fsm_ea_prompt")
trap '_fsm_ea_before "$?"' DEBUG
