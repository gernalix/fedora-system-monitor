#!/usr/bin/bash
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
runtime="$HOME/.local/libexec/fedora-telegram-history"
session_dir="$HOME/.cache/fedora-telegram-history"
packages="$runtime/packages"
lock="$runtime/.dependency-update.lock"
if [[ -L $runtime || -L $lock || -L $packages || ( -e $packages && ! -d $packages ) ]]; then
    echo 'Expected locally owned Telegram runtime paths.' >&2
    exit 1
fi
install -d -m 700 "$runtime" "$session_dir"
exec 8<>"$lock"
flock -n -E 75 8
exec 9<>"$session_dir/session.lock"
flock -n -E 75 9

stage=$(mktemp -d "$runtime/.install.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$stage" \
    "$root/scripts/stage-telegram-packages.sh" "$stage/packages"
if [[ -d $packages ]]; then
    previous=$(mktemp -d "$runtime/.previous.XXXXXXXX")
    /usr/bin/mv -T -- "$stage/packages" "$previous/packages"
    /usr/bin/mv -T --exchange --no-copy "$previous/packages" "$packages"
else
    /usr/bin/mv -T -- "$stage/packages" "$packages"
fi
