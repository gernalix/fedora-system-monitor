#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LIB_PARENT=/usr/local/libexec
LIB=$LIB_PARENT/fedora-system-monitor
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

if [[ ! -d "$ROOT/.git" ]]; then
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
printf '%s\n' "$REVISION" > "$STAGE/.source-revision"

/usr/bin/python3 -m compileall -q "$STAGE/fedora_system_monitor"
PYTHONPATH="$STAGE" /usr/bin/python3 -c 'import fedora_system_monitor; import fedora_system_monitor.capsules.runtime.coordinator'
chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 0755 '{}' +
find "$STAGE" -type f -exec chmod 0644 '{}' +
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
rm -rf "$OLD"

install -m 0755 "$ROOT/packaging/fedora-system-monitor" /usr/local/bin/fedora-system-monitor
command -v restorecon >/dev/null && restorecon -RF "$LIB" /usr/local/bin/fedora-system-monitor || true

/usr/local/bin/fedora-system-monitor config-check >/dev/null
/usr/local/bin/fedora-system-monitor db-check >/dev/null

printf 'Fedora System Monitor runtime deployed: %s\n' "$REVISION"
