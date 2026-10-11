# Source at the start of .bashrc. Noninteractive shells never launch a PTY.
[[ $- == *i* && -t 0 && -t 1 ]] || return 0
[[ -z ${BASH_EXECUTION_STRING:-} ]] || return 0
[[ -z ${FSM_EA_ACTIVE:-} ]] || return 0
[[ ! -e "$HOME/.local/state/fedora-system-monitor/executions/disabled" ]] || return 0
[[ -x "$HOME/.local/bin/ea" ]] || return 0
if shopt -q login_shell; then
    exec "$HOME/.local/bin/ea" shell --login
else
    exec "$HOME/.local/bin/ea" shell
fi
