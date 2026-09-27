#!/usr/bin/env bash
# Read-only JSONL export of journals for locally defined and registered units.
set -euo pipefail

JOURNALCTL_BIN="${JOURNALCTL_BIN:-journalctl}"
JQ_BIN="${JQ_BIN:-jq}"
SQLITE3_BIN="${SQLITE3_BIN:-sqlite3}"
SYSTEM_UNIT_DIR="${SYSTEM_UNIT_DIR:-/etc/systemd/system}"
USER_UNIT_DIR="${USER_UNIT_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}"
REGISTRY_PATH="${MEGAVAULT_REGISTRY_PATH:-/home/daniele/MegaVault/megavault.sqlite}"
LIMIT=200
SINCE=""
UNTIL=""
OUTPUT="-"
declare -a REQUESTED_UNITS=()
declare -A UNIT_SCOPE=()
declare -A TIMER_TARGET=()

usage() {
    cat <<'EOF'
Usage: systemd-journal-collector.sh [options]

Read journal entries only for custom units defined in /etc/systemd/system,
~/.config/systemd/user, or the canonical MegaVault services registry.

Options:
  --unit UNIT       limit to one discovered unit (may be repeated)
  --since TIME      journalctl --since value
  --until TIME      journalctl --until value
  --recent WINDOW   equivalent to --since "WINDOW ago" (for example 6h, 2d)
  --limit N         entries per unit and journal; 1..5000 (default: 200)
  --output FILE     JSONL destination, or - for stdout (default)
  --registry PATH   MegaVault SQLite registry path (optional when absent)
  --help            show this help
EOF
}

fail() { printf 'systemd-journal-collector: %s\n' "$*" >&2; exit 2; }

valid_unit() {
    [[ $1 =~ ^[A-Za-z0-9@_.:-]+\.(service|timer)$ ]]
}

add_unit() {
    local unit=$1 scope=$2
    valid_unit "$unit" || return 0
    if [[ -z ${UNIT_SCOPE[$unit]+x} || $scope == user ]]; then
        UNIT_SCOPE[$unit]=$scope
    fi
}

timer_target_from_file() {
    local path=$1 timer=$2 target
    target=$(awk '
        /^\[/ { in_timer = ($0 == "[Timer]") }
        in_timer && /^Unit[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); print; exit
        }
    ' "$path")
    if [[ -z $target ]]; then
        target="${timer%.timer}.service"
    fi
    valid_unit "$target" && printf '%s\n' "$target"
}

discover_directory() {
    local directory=$1 scope=$2 path unit target
    [[ -d $directory ]] || return 0
    shopt -s nullglob
    for path in "$directory"/*.service "$directory"/*.timer; do
        unit=${path##*/}
        add_unit "$unit" "$scope"
        if [[ $unit == *.timer ]]; then
            target=$(timer_target_from_file "$path" "$unit")
            if [[ -n $target ]]; then
                TIMER_TARGET[$unit]=$target
                add_unit "$target" "$scope"
            fi
        fi
    done
    shopt -u nullglob
}

discover_registry() {
    local row scope units unit
    [[ -r $REGISTRY_PATH ]] || return 0
    command -v "$SQLITE3_BIN" >/dev/null 2>&1 || return 0
    while IFS=$'\t' read -r scope units; do
        [[ $scope == *user* ]] && scope=user || scope=system
        IFS='+' read -ra unit <<< "$units"
        for unit in "${unit[@]}"; do
            unit=${unit//[[:space:]]/}
            add_unit "$unit" "$scope"
        done
    done < <("$SQLITE3_BIN" -readonly -noheader -separator $'\t' "$REGISTRY_PATH" \
        "SELECT COALESCE(scope, ''), COALESCE(unit, '') FROM services WHERE TRIM(COALESCE(unit, '')) <> '';" 2>/dev/null || true)

    while IFS=$'\t' read -r timer service; do
        valid_unit "$timer" || continue
        valid_unit "$service" || continue
        TIMER_TARGET[$timer]=$service
        add_unit "$timer" "${UNIT_SCOPE[$timer]:-system}"
        add_unit "$service" "${UNIT_SCOPE[$timer]:-system}"
    done < <("$SQLITE3_BIN" -readonly -noheader -separator $'\t' "$REGISTRY_PATH" \
        "SELECT timer_unit, service_unit FROM periodic_service_evidence WHERE present = 1;" 2>/dev/null || true)
}

selected() {
    local unit=$1 requested
    ((${#REQUESTED_UNITS[@]} == 0)) && return 0
    for requested in "${REQUESTED_UNITS[@]}"; do
        [[ $unit == "$requested" ]] && return 0
    done
    return 1
}

normalize() {
    local unit=$1 scope=$2 target=${3:-}
    "$JQ_BIN" -c --arg unit "$unit" --arg scope "$scope" --arg hostname "$(hostname)" --arg timer_target "$target" '
        {
          timestamp: (.__REALTIME_TIMESTAMP // .SYSLOG_TIMESTAMP // null),
          hostname: (._HOSTNAME // $hostname),
          unit: (._SYSTEMD_UNIT // ._SYSTEMD_USER_UNIT // .UNIT // $unit),
          pid: (._PID // null),
          priority: (.PRIORITY // null),
          message: (.MESSAGE // ""),
          _SYSTEMD_INVOCATION_ID: (._SYSTEMD_INVOCATION_ID // null),
          result: (.RESULT // .JOB_RESULT // null),
          exit_status: (.EXIT_STATUS // .EXIT_CODE // null),
          journal_scope: $scope,
          timer_target: (if $timer_target == "" then null else $timer_target end),
          invocation_group: ($unit + ":" + (._SYSTEMD_INVOCATION_ID // "unknown"))
        }
    '
}

collect_unit() {
    local unit=$1 scope=$2 target=${TIMER_TARGET[$1]:-}
    local -a command=("$JOURNALCTL_BIN")
    [[ $scope == user ]] && command+=(--user)
    command+=(-u "$unit" --no-pager --output=json --lines "$LIMIT")
    [[ -n $SINCE ]] && command+=(--since "$SINCE")
    [[ -n $UNTIL ]] && command+=(--until "$UNTIL")
    "${command[@]}" 2>/dev/null | normalize "$unit" "$scope" "$target" || true
}

while (($#)); do
    case $1 in
        --unit) (($# >= 2)) || fail '--unit requires a value'; valid_unit "$2" || fail "invalid unit: $2"; REQUESTED_UNITS+=("$2"); shift 2 ;;
        --since) (($# >= 2)) || fail '--since requires a value'; SINCE=$2; shift 2 ;;
        --until) (($# >= 2)) || fail '--until requires a value'; UNTIL=$2; shift 2 ;;
        --recent) (($# >= 2)) || fail '--recent requires a value'; [[ -z $SINCE ]] || fail '--recent cannot be combined with --since'; SINCE="$2 ago"; shift 2 ;;
        --limit) (($# >= 2)) || fail '--limit requires a value'; LIMIT=$2; shift 2 ;;
        --output) (($# >= 2)) || fail '--output requires a value'; OUTPUT=$2; shift 2 ;;
        --registry) (($# >= 2)) || fail '--registry requires a value'; REGISTRY_PATH=$2; shift 2 ;;
        --help) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done
[[ $LIMIT =~ ^[0-9]+$ ]] && ((LIMIT >= 1 && LIMIT <= 5000)) || fail '--limit must be between 1 and 5000'
command -v "$JOURNALCTL_BIN" >/dev/null 2>&1 || fail 'journalctl is required'
command -v "$JQ_BIN" >/dev/null 2>&1 || fail 'jq is required'

discover_directory "$SYSTEM_UNIT_DIR" system
discover_directory "$USER_UNIT_DIR" user
discover_registry

if [[ $OUTPUT == - ]]; then
    for unit in "${!UNIT_SCOPE[@]}"; do
        if selected "$unit"; then collect_unit "$unit" "${UNIT_SCOPE[$unit]}"; fi
    done | sort
else
    umask 077
    {
        for unit in "${!UNIT_SCOPE[@]}"; do
            if selected "$unit"; then collect_unit "$unit" "${UNIT_SCOPE[$unit]}"; fi
        done | sort
    } > "$OUTPUT"
fi
