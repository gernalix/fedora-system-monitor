"""A single user-session GTK4 dialog; explicit choices only, no automatic killing."""
from pathlib import Path
import fcntl
import json
import os
import stat
import subprocess
import threading
import time

from .pressure import sample, classify, clearly_healthy
from .targets import candidates, terminate
from .watch import session_unlocked


def user_environment():
    uid=os.getuid()
    if uid==0: raise PermissionError('Il dialogo deve funzionare con UID utente, mai root.')
    runtime=Path(f'/run/user/{uid}')
    meta=runtime.stat()
    if meta.st_uid!=uid or not stat.S_ISDIR(meta.st_mode): raise PermissionError('Sessione non verificata.')
    sockets=[p for p in runtime.glob('wayland-*') if p.is_socket() and p.stat().st_uid==uid]
    if len(sockets)!=1: raise RuntimeError('Display Wayland assente o ambiguo.')
    os.environ.update(XDG_RUNTIME_DIR=str(runtime),DBUS_SESSION_BUS_ADDRESS=f'unix:path={runtime}/bus',
        WAYLAND_DISPLAY=sockets[0].name,GDK_BACKEND='wayland',GSK_RENDERER='cairo')
    return runtime


def singleton(runtime):
    fd=os.open(runtime/'fsm-resource-dialog.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    if os.fstat(fd).st_uid!=os.getuid(): os.close(fd);raise PermissionError('Lock non posseduto.')
    try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError: os.close(fd);return None
    return fd


class Dialog:
    def __init__(self,config,*,fixture=False):
        import gi
        gi.require_version('Gtk','4.0')
        from gi.repository import Gtk,GLib
        self.Gtk,self.GLib=Gtk,GLib;self.config=config;self.cfg=config['resource_rescue'];self.fixture=fixture
        self.app=Gtk.Application(application_id='com.gernalix.FSM.ResourceRescue')
        self.app.connect('activate',self.activate)
        self.window=None;self.previous=None;self.snapshot=None;self.busy=False;self.healthy=0
        self.started=time.monotonic();self.outcome=2;self.actions=0;self.sources=[];self.frozen=None;self.io_previous={}

    def activate(self,app):
        self.build()
        self.refresh()
        self.sources.append(self.GLib.timeout_add_seconds(int(self.cfg['active_seconds']),self.refresh))

    def build(self,message=''):
        Gtk=self.Gtk
        if self.window: self.window.destroy()
        self.window=Gtk.ApplicationWindow(application=self.app,title='FSM · Recupero risorse'+(' · TEST' if self.fixture else ''))
        self.window.set_default_size(740,540)
        self.window.connect('close-request',lambda *_: self.finish(2))
        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12)
        for edge in ('top','bottom','start','end'): getattr(box,'set_margin_'+edge)(18)
        self.window.set_child(box)
        self.heading=Gtk.Label(wrap=True,xalign=0);box.append(self.heading)
        self.metrics=Gtk.Label(wrap=True,xalign=0);box.append(self.metrics)
        self.ranking=Gtk.Label(wrap=True,xalign=0,selectable=True)
        scroll=Gtk.ScrolledWindow(vexpand=True);scroll.set_child(self.ranking);box.append(scroll)
        self.entry=Gtk.Entry(placeholder_text='Numero applicazione, poi Invio (nessuna scelta automatica)')
        self.entry.connect('activate',self.choose);box.append(self.entry)
        self.status=Gtk.Label(label=message,wrap=True,xalign=0);box.append(self.status)
        buttons=Gtk.Box(spacing=10);box.append(buttons)
        self.choose_button=Gtk.Button(label='Richiedi chiusura');self.choose_button.connect('clicked',self.choose);buttons.append(self.choose_button)
        snooze=Gtk.Button(label='Rimanda');snooze.connect('clicked',lambda *_:self.finish(2));buttons.append(snooze)
        chrome=Gtk.Button(label='Schede Chrome');chrome.connect('clicked',self.chrome);buttons.append(chrome)
        self.window.present()

    def finish(self,code):
        self.outcome=code
        self.app.quit()
        return False

    def live(self):
        if self.fixture:
            from .pressure import Sample
            return Sample(time.monotonic(),8,4,1,0,0,0,2048,0)
        s,self.previous=sample(self.previous,volumes=tuple(self.config['collection']['critical_filesystems']))
        return s

    def refresh(self):
        if not self.fixture and not session_unlocked(self.config['monitor']['operator_user']):
            self.finish(3);return False
        if time.monotonic()-self.started>self.cfg['dialog_timeout_seconds']:
            self.finish(2);return False
        s=self.live();risk=classify(s,self.cfg)
        self.metrics.set_text(f'RAM disponibile: {s.available if s.available is not None else "N/D"}% · PSI RAM some/full: {s.memory_some}/{s.memory_full}%\n'
            f'Swap occupato: {s.swap_used} byte · swap-out: {s.swap_out} B/s · reclaim: {s.reclaim} pag/s · PSI I/O full: {s.io_full}%\n'+risk.explanation)
        if self.busy: return True
        self.healthy=self.healthy+1 if risk.level==0 and clearly_healthy(s,self.cfg) else 0
        if self.healthy>=self.cfg['recovery_samples']:
            self.heading.set_text('Risolto: pressione rientrata dopo verifica e isteresi.')
            self.entry.set_sensitive(False);self.choose_button.set_sensitive(False)
            self.GLib.timeout_add_seconds(4,lambda:self.finish(0));return False
        if risk.level<=0:
            self.heading.set_text('Assestamento: attendo conferma del recupero.' if risk.level==0 else 'Dati mancanti: recupero non verificabile.')
            self.choose_button.set_sensitive(False)
            return True
        self.heading.set_text('Risorse in esaurimento: termina una delle seguenti applicazioni il prima possibile' if risk.kind=='memory' else 'Risorse in esaurimento: verifica le azioni contestuali seguenti')
        if risk.kind=='disk':
            self.entry.set_sensitive(False);self.choose_button.set_sensitive(False);self.snapshot=None
            self.ranking.set_text('Disco/inode: apri Analizzatore utilizzo disco e scegli manualmente cosa conservare. Chiudere processi non garantisce spazio libero; nessuna cancellazione automatica.' if risk.kind=='disk' else 'I/O: verifica le operazioni attive nei report process-history. Attribuzione per-app non sufficientemente affidabile: nessuna chiusura proposta.')
            return True
        self.entry.set_sensitive(True);self.choose_button.set_sensitive(True)
        # Freeze the displayed number→identity mapping while a number is being typed.
        if not self.entry.get_text():
            try:
                if self.fixture:
                    from .targets import Snapshot,Candidate,Identity
                    i=Identity('fixture',999999999,1,os.getuid(),'Applicazione TEST','fixture',1024**3)
                    self.snapshot=Snapshot('fixture',time.monotonic(),(Candidate(i,(i,),1024**3,'simulata'),))
                    lines=['1. Applicazione TEST · 1024 MiB simulati · nessun segnale a processi reali']
                else:
                    self.snapshot=candidates(os.getuid(),io_previous=self.io_previous,kind=risk.kind)
                    self.io_previous=dict(self.snapshot.io_counters)
                    lines=[f'{n}. {c.leader.name} · '+(f'{c.io_bps:.0f} B/s disco (delta osservato)' if risk.kind=='io' else f'{c.estimated_bytes/1024**2:.1f} MiB · {c.basis}')+f' · {len(c.members)} processi · osservata' for n,c in enumerate(self.snapshot.candidates,1)]
                self.ranking.set_text('\n'.join(lines) or 'Nessun target sicuro osservabile. Salva il lavoro e chiudi manualmente un’applicazione.')
            except (OSError,ValueError,TimeoutError):
                self.snapshot=None;self.ranking.set_text('Classifica non verificabile: nessuna azione abilitata.')
        return True

    def choose(self,*_):
        if self.busy or self.snapshot is None: return
        try:
            number=int(self.entry.get_text())
            if not 1<=number<=len(self.snapshot.candidates) or time.monotonic()-self.snapshot.at>20:
                raise ValueError()
        except ValueError:
            self.entry.set_text('');self.refresh();self.status.set_text('Numero non valido o elenco scaduto. Scegli dalla nuova classifica.');return
        snapshot=self.snapshot;candidate=snapshot.candidates[number-1]
        self.busy=True;self.entry.set_sensitive(False)
        # All apps require an additional informed confirmation, including editors/browser.
        Gtk=self.Gtk
        confirmation=Gtk.Window(application=self.app,transient_for=self.window,modal=True,title='Conferma chiusura')
        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12)
        for edge in ('top','bottom','start','end'): getattr(box,'set_margin_'+edge)(18)
        confirmation.set_child(box)
        box.append(Gtk.Label(label=f'Richiedere la chiusura di {candidate.leader.name}?',wrap=True))
        box.append(Gtk.Label(label='Possibili dati non salvati e sessioni aperte. Prima salva il lavoro. Chiusura normale quando disponibile, altrimenti SIGTERM; nessun SIGKILL.',wrap=True,max_width_chars=65))
        cancel=Gtk.Button(label='Annulla');accept=Gtk.Button(label='Confermo: richiedi chiusura')
        box.append(cancel);box.append(accept)
        def response(dialog,response):
            dialog.destroy()
            if response!=Gtk.ResponseType.OK:
                self.busy=False;self.entry.set_text('');self.refresh();self.status.set_text('Annullato: nessun segnale inviato.');return
            def worker():
                try:
                    if self.fixture: raise PermissionError('Test: azioni reali disabilitate.')
                    if not session_unlocked(self.config['monitor']['operator_user']): raise PermissionError('Sessione bloccata.')
                    from .app_close import request_quit
                    result=terminate(snapshot,number,os.getuid(),confirmed=True,normal_close=request_quit)
                    message='Cessazione osservata; ricontrollo la pressione live.' if result=='exited' else 'Chiusura non completata: nessun miglioramento presunto e nessun SIGKILL.'
                    self.actions+=1
                except Exception: # Never force a signal after an uncertain normal-close failure.
                    message='Chiusura non eseguita: identità/permessi/elenco non validi. Salva e chiudi manualmente.'
                self.GLib.idle_add(lambda:self.GLib.timeout_add_seconds(3,self.after_action,message) and False)
            threading.Thread(target=worker,daemon=True).start()
        self.confirmation=confirmation
        self.confirm_cancel=cancel;self.confirm_accept=accept
        cancel.connect('clicked',lambda *_:response(confirmation,Gtk.ResponseType.CANCEL))
        accept.connect('clicked',lambda *_:response(confirmation,Gtk.ResponseType.OK))
        confirmation.connect('close-request',lambda *_:(response(confirmation,Gtk.ResponseType.CANCEL),True)[1])
        confirmation.present();cancel.grab_focus()

    def after_action(self,message):
        self.busy=False;self.healthy=0
        self.build(message);self.refresh()
        return False

    def chrome(self,*_):
        # A separate user-requested extension popup performs tab API actions;
        # this dialog never kills a shared Chrome renderer for a single tab.
        self.status.set_text('Apri l’icona «FSM Schede Chrome» in Chrome. Titoli solo effimeri, metriche per-tab non disponibili su questa integrazione Stable; ogni scaricamento/chiusura richiede conferma.')

    def run(self):
        self.app.run([])
        for source in self.sources:
            try: self.GLib.source_remove(source)
            except Exception: pass
        return self.outcome


def run(config,fixture=False):
    import pwd
    if pwd.getpwnam(config['monitor']['operator_user']).pw_uid!=os.getuid():
        raise PermissionError('Il dialogo non appartiene all’utente operatore configurato.')
    runtime=user_environment();fd=singleton(runtime)
    if fd is None: return 5
    try:
        if not fixture and not session_unlocked(config['monitor']['operator_user']): return 3
        return Dialog(config,fixture=fixture).run()
    finally: os.close(fd)
