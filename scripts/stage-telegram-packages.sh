#!/usr/bin/bash
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
if [[ $# != 1 && $# != 3 ]] || [[ $1 != /* || -e $1 || -L $1 ]]; then
    echo 'Usage: stage-telegram-packages TARGET [PINS ACTIVE_TARGET]' >&2
    exit 2
fi
target=$1
constraints=()
if [[ $# == 3 ]]; then
    if [[ $2 != /* || ! -f $2 || -L $2 || $3 != /* || ! -d $3 || -L $3 ]]; then
        echo 'Expected a local pin file and an existing package directory.' >&2
        exit 2
    fi
    constraints=(-c "$2")
fi

work=$(mktemp -d -- "$(dirname -- "$target")/.telegram-build.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
python=/usr/bin/python3
index=https://pypi.org/simple
uv=(/usr/bin/uv --no-config pip install --python "$python" --index-url "$index")
"${uv[@]}" --only-binary :all: --target "$work/build" setuptools wheel
mkdir "$work/wheels"
printf '%s\n' 'pyaes==1.6.1 --hash=sha256:02c1b1405c38d3c370b085fb952dd8bea3fadcee6411ad99f312cc129c536d8f' > "$work/pyaes.txt"
PYTHONPATH="$work/build" "$python" -s -P -m pip --isolated --disable-pip-version-check wheel \
    --no-deps --no-build-isolation --require-hashes --index-url "$index" \
    --wheel-dir "$work/wheels" -r "$work/pyaes.txt"
"${uv[@]}" --only-binary :all: --find-links "$work/wheels" --target "$target" \
    -r "$root/config/telegram-history-requirements.txt" "${constraints[@]}"

/usr/bin/bwrap --die-with-parent --unshare-net --unshare-pid \
    --ro-bind / / --tmpfs /home --tmpfs /tmp --tmpfs /run --tmpfs /mnt --tmpfs /media \
    --tmpfs /var/lib --proc /proc --dev /dev \
    --ro-bind "$target" /tmp/packages --ro-bind "$root" /tmp/work \
    --clearenv --setenv PATH /usr/bin:/bin --setenv HOME /tmp \
    --setenv PYTHONPATH /tmp/work:/tmp/work/src:/tmp/packages --chdir /tmp/work \
    "$python" -S -P -B -m unittest discover -s tests -p 'test_telegram_*.py' -q
