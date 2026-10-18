"""Request an exported GTK quit action on a verified, existing D-Bus owner only."""
import re


def request_quit(candidate):
    import gi
    from gi.repository import Gio,GLib
    match=re.search(r'/app-(?:gnome-)?(org\.[A-Za-z0-9_.]+|com\.[A-Za-z0-9_.]+)(?:-[A-Za-z0-9]+)?\.scope(?:/|$)',candidate.leader.cgroup)
    if not match: return False
    appid=match[1]
    # Reject ambiguous trailing unit suffixes instead of guessing a bus identity.
    if not re.fullmatch(r'(?:org|com)(?:\.[A-Za-z_][A-Za-z0-9_]*){2,}',appid): return False
    bus=Gio.bus_get_sync(Gio.BusType.SESSION,None)
    flags=Gio.DBusCallFlags.NO_AUTO_START
    def dbus(method,name,typ):
        return bus.call_sync('org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',
            method,GLib.Variant('(s)',(name,)),GLib.VariantType.new(typ),flags,1000,None).unpack()[0]
    try: owner=dbus('GetNameOwner',appid,'(s)')
    except GLib.Error: return False # No existing app, never activate a new process.
    pid=dbus('GetConnectionUnixProcessID',owner,'(u)');uid=dbus('GetConnectionUnixUser',owner,'(u)')
    if uid!=candidate.leader.uid or pid not in {i.pid for i in candidate.members}:
        raise PermissionError('D-Bus owner changed')
    from .targets import identity,same,protected
    expected=next(i for i in candidate.members if i.pid==pid)
    current=identity(pid)
    if not same(expected,current) or protected(current,uid):
        raise PermissionError('D-Bus process identity changed')
    path='/'+appid.replace('.','/')
    try:
        description=bus.call_sync(owner,path,'org.gtk.Actions','Describe',GLib.Variant('(s)',('quit',)),
            None,flags,1000,None).unpack()[0]
    except GLib.Error: return False # No verified normal quit action: explicit SIGTERM fallback.
    # Describe returns enabled + parameter signature + state. Parameterless quit only.
    enabled,signature,_state=description
    if not enabled: raise PermissionError('Normal quit action disabled')
    if signature: return False
    bus.call_sync(owner,path,'org.gtk.Actions','Activate',GLib.Variant('(sava{sv})',('quit',[],{})),
        None,flags,1000,None)
    return True
