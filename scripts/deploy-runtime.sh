#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LIB_PARENT=/usr/local/libexec
LIB=$LIB_PARENT/fedora-system-monitor
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'Runtime-only deploy requires a Git checkout: %s\n' "$ROOT" >&2
    exit 1
fi
if [[ -n $(git -C "$ROOT" status --porcelain) ]]; then
    printf 'Refusing to deploy a dirty checkout. Commit or discard local changes first.\n' >&2
    git -C "$ROOT" status --short >&2
    exit 1
fi
REVISION=$(git -C "$ROOT" rev-parse HEAD)

if find "$ROOT/src/fedora_system_monitor" -type l -print -quit | grep -q .; then
    printf 'Refusing to deploy symlinks from the source package.\n' >&2
    exit 1
fi

install -d -m 0755 "$LIB_PARENT"
STAGE=$(mktemp -d "$LIB_PARENT/.fedora-system-monitor.XXXXXX")
cleanup() { [[ -z ${STAGE:-} ]] || rm -rf "$STAGE"; }
trap cleanup EXIT

install -d -m 0755 "$STAGE/fedora_system_monitor"
while IFS= read -r -d '' source; do
    relative=${source#"$ROOT/src/fedora_system_monitor/"}
    install -d -m 0755 "$STAGE/fedora_system_monitor/$(dirname "$relative")"
    install -m 0644 -o root -g root "$source" "$STAGE/fedora_system_monitor/$relative"
done < <(find "$ROOT/src/fedora_system_monitor" -type f -name '*.py' -print0)
# Owned static Chrome panel; loading it in Chrome remains an explicit user action.
if find "$ROOT/chrome/resource-rescue" -type l -print -quit | grep -q .; then
    printf 'Refusing symlinks in Chrome resource panel.\n' >&2
    exit 1
fi
install -d -m 0755 "$STAGE/chrome-resource-rescue"
for asset in manifest.json popup.html popup.css popup.js model.js; do
    install -m 0644 -o root -g root "$ROOT/chrome/resource-rescue/$asset" "$STAGE/chrome-resource-rescue/$asset"
done
install -d -m 0755 "$STAGE/scripts"
install -m 0755 -o root -g root "$ROOT/scripts/systemd-journal-collector.sh" "$STAGE/scripts/systemd-journal-collector.sh"
printf '%s\n' "$REVISION" > "$STAGE/.source-revision"

/usr/bin/python3 -m compileall -q "$STAGE/fedora_system_monitor"
PYTHONPATH="$STAGE" /usr/bin/python3 -c 'import fedora_system_monitor; import fedora_system_monitor.capsules.runtime.coordinator'
PYTHONPATH="$STAGE" /usr/bin/python3 -m fedora_system_monitor config-check >/dev/null
# Validate staged schema without migrating the live DB under the old runtime.
PYTHONPATH="$STAGE" /usr/bin/python3 -m fedora_system_monitor --database :memory: db-check >/dev/null
chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 0755 '{}' +
find "$STAGE" -type f -exec chmod 0644 '{}' +
chmod 0755 "$STAGE/scripts/systemd-journal-collector.sh"
if find "$STAGE" \( ! -user root -o -perm /022 \) -print -quit | grep -q .; then
    printf 'Unsafe ownership or mode in staged runtime.\n' >&2
    exit 1
fi

OLD="$LIB_PARENT/.fedora-system-monitor.old-$STAMP"
if [[ -e "$LIB" ]]; then
    mv "$LIB" "$OLD"
fi
if ! mv "$STAGE" "$LIB"; then
    [[ ! -e "$OLD" ]] || mv "$OLD" "$LIB"
    exit 1
fi
STAGE=

install -m 0755 "$ROOT/packaging/fedora-system-monitor" /usr/local/bin/fedora-system-monitor
install -m 0755 "$ROOT/packaging/fsm-chrome-capabilities" /usr/local/bin/fsm-chrome-capabilities
/usr/bin/python3 - "$ROOT/chrome/resource-rescue/EXTENSION_ID" <<'PYHOST'
import json,sys,os
from pathlib import Path
origin='chrome-extension://'+Path(sys.argv[1]).read_text().strip()+'/'
p=Path('/etc/opt/chrome/native-messaging-hosts/com.gernalix.fsm_resource_rescue.json')
value={'name':'com.gernalix.fsm_resource_rescue','description':'FSM capabilities-only one-shot host','path':'/usr/local/bin/fsm-chrome-capabilities','type':'stdio','allowed_origins':[origin]}
if p.exists() and json.loads(p.read_text()).get('path')!=value['path']:
    raise SystemExit('Refusing unrelated native host')
p.parent.mkdir(parents=True,exist_ok=True)
p.write_text(json.dumps(value)+'\n');os.chmod(p,0o644)
PYHOST
command -v restorecon >/dev/null && restorecon -RF "$LIB" /usr/local/bin/fedora-system-monitor || true

if ! /usr/local/bin/fedora-system-monitor config-check >/dev/null \
    || ! /usr/local/bin/fedora-system-monitor db-check >/dev/null; then
    FAILED="$LIB_PARENT/.fedora-system-monitor.failed-$STAMP"
    mv "$LIB" "$FAILED"
    [[ ! -e "$OLD" ]] || mv "$OLD" "$LIB"
    rm -rf "$FAILED"
    printf 'Runtime validation failed; previous runtime restored.\n' >&2
    exit 1
fi
rm -rf "$OLD"

systemd_drift=()
for source in "$ROOT"/systemd/*.service "$ROOT"/systemd/*.timer "$ROOT"/systemd/*.path; do
    [[ -f "$source" ]] || continue
    unit=$(basename "$source")
    installed="/etc/systemd/system/$unit"
    if [[ ! -f "$installed" ]] || ! cmp -s "$source" "$installed"; then
        systemd_drift+=("$unit")
    fi
done

printf 'Fedora System Monitor runtime deployed: %s\n' "$REVISION"
if (( ${#systemd_drift[@]} )); then
    printf 'NOTICE: runtime-only deploy did not synchronize systemd definitions:' >&2
    printf ' %s' "${systemd_drift[@]}" >&2
    printf '\nUse scripts/deploy-systemd-unit.sh for the affected unit(s).\n' >&2
fi
