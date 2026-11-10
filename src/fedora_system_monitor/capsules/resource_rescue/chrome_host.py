"""Bounded one-shot Chrome native host; tab titles stay in user-only runtime tmpfs."""
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import time

MAX_FRAME = 16384
MAX_TABS = 16
MAX_TITLE = 120
MAX_AGE_SECONDS = 1800
CAP_KEYS = {'session', 'processes_exposed', 'tabs_available', 'browser_major'}
TAB_KEYS = {'kind', 'session', 'total', 'tabs'}


def receive(stream):
    header = stream.read(4)
    if len(header) != 4:
        raise ValueError('missing frame')
    length = struct.unpack('<I', header)[0]
    if not 1 <= length <= MAX_FRAME:
        raise ValueError('frame limit')
    data = stream.read(length)
    if len(data) != length:
        raise ValueError('incomplete frame')
    value = json.loads(data)
    if not isinstance(value, dict) or not re.fullmatch(
        r'[a-f0-9-]{32,36}', str(value.get('session', ''))
    ):
        raise ValueError('session')
    if set(value) == CAP_KEYS:
        if type(value['processes_exposed']) is not bool or type(value['tabs_available']) is not bool:
            raise ValueError('capabilities')
        if type(value['browser_major']) is not int or not 100 <= value['browser_major'] <= 999:
            raise ValueError('version')
    elif set(value) == TAB_KEYS and value['kind'] == 'tabs':
        if type(value['total']) is not int or not 0 <= value['total'] <= 10000:
            raise ValueError('tab count')
        tabs = value['tabs']
        if type(tabs) is not list or not 0 <= len(tabs) <= min(MAX_TABS, value['total']):
            raise ValueError('tab rows')
        for tab in tabs:
            if type(tab) is not dict or set(tab) != {'title', 'active', 'discarded'}:
                raise ValueError('tab metadata')
            title = tab['title']
            if type(title) is not str or not 1 <= len(title) <= MAX_TITLE or not title.isprintable():
                raise ValueError('unsafe tab title')
            if type(tab['active']) is not bool or type(tab['discarded']) is not bool:
                raise ValueError('tab flags')
    else:
        raise ValueError('unknown keys')
    return value


def _write_private(root, filename, data):
    root = Path(root)
    metadata = root.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise PermissionError('private runtime required')
    temp = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=root, prefix='.fsm-chrome-', delete=False) as output:
            temp = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            json.dump(data, output, ensure_ascii=False)
        os.replace(temp, root / filename)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def persist(value, root):
    value = {**value, 'observed_at_utc': time.time(),
             'cpu_per_tab': None, 'rss_per_tab': None, 'io_per_tab': None}
    _write_private(root, 'fsm-chrome-capabilities.json', value)
    return value


def persist_tabs(value, root):
    # No URLs, tab IDs, Linux PIDs, history, database, or persistent file.
    data = {**value, 'observed_at_utc': time.time()}
    _write_private(root, 'fsm-chrome-tabs.json', data)
    return data


def read_recent_tabs(root, *, now=None):
    """Read only a recent, owner-only regular file; tolerate absent/invalid data."""
    path = Path(root) / 'fsm-chrome-tabs.json'
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_FRAME):
            return None
        data = json.loads(os.read(fd, MAX_FRAME + 1))
        if not isinstance(data, dict) or set(data) != TAB_KEYS | {'observed_at_utc'}:
            return None
        timestamp = data['observed_at_utc']
        age = (time.time() if now is None else now) - timestamp
        if (type(timestamp) not in (int, float) or not 0 <= age <= MAX_AGE_SECONDS
                or data['kind'] != 'tabs' or type(data['total']) is not int):
            return None
        # Reuse the native input validation for titles and field bounds.
        raw = json.dumps({key: data[key] for key in TAB_KEYS}, ensure_ascii=False).encode()
        receive_bytes = struct.pack('<I', len(raw)) + raw
        import io
        receive(io.BytesIO(receive_bytes))
        data['age_seconds'] = round(age)
        return data
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def describe_tabs(data):
    preface = 'Chrome: i processi elencati NON corrispondono necessariamente a singole schede.'
    if data is None:
        return preface + ('\nTitoli non disponibili: apri «FSM Schede Chrome» '
                          'oppure il Task Manager Chrome (Maiusc+Esc, colonna PID).')
    rows = data['tabs']
    details = [f'  • {t["title"]} · ' + ('attiva' if t['active'] else
               'già scaricata' if t['discarded'] else 'inattiva') for t in rows]
    count = f'{len(rows)}/{data["total"]}' if data['total'] != len(rows) else str(len(rows))
    return ('\n'.join([preface,
        f'Schede Chrome, titoli osservati {data["age_seconds"]} s fa ({count}; NON ordinate per consumo):',
        *details]) if details else preface + '\nNessuna scheda normale rilevata.')


def main():
    try:
        if os.getuid() == 0:
            raise PermissionError('user host only')
        value = receive(sys.stdin.buffer)
        if value.get('kind') == 'tabs':
            persist_tabs(value, f'/run/user/{os.getuid()}')
            result = {'ok': True, 'stored': 'volatile_titles_only'}
        else:
            persist(value, f'/run/user/{os.getuid()}')
            result = {'ok': True, 'metrics': 'not_available', 'stored': 'capabilities_only'}
    except Exception:
        result = {'ok': False, 'error': 'invalid native message'}
    data = json.dumps(result).encode()
    sys.stdout.buffer.write(struct.pack('<I', len(data)) + data)
    sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
