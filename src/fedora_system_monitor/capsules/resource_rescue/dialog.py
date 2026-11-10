"""A single user-session GTK4 dialog; explicit choices only, no automatic killing."""
from pathlib import Path
import fcntl
import json
import os
import stat
import subprocess
import threading
import time

from math import isfinite

from .pressure import sample, classify, clearly_healthy
from .chrome_host import read_recent_tabs
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


def percent(value):
    return f'{value:.1f}%' if isinstance(value, (float, int)) and isfinite(value) else 'N/D'


def size(value, *, rate=False):
    if value is None or not isfinite(value) or value < 0:
        return 'N/D'
    unit = 'B'
    for larger in ('KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024:
            break
        value /= 1024
        unit = larger
    value_text = f'{value:.1f}' if unit != 'B' else f'{value:.0f}'
    return f'{value_text} {unit}' + ('/s' if rate else '')


def risk_title(risk):
    return {
        'io': 'Attese disco/I/O elevate',
        'memory': 'Pressione RAM elevata',
        'disk': 'Spazio disco insufficiente',
        'healthy': 'Pressione in rientro',
        'unknown': 'Misurazione incompleta',
    }.get(risk.kind, 'Risorse da verificare')


def resource_summary(s, risk):
    ram = f'RAM disponibile: {percent(s.available)}'
    io = f'PSI I/O full (10 s): {percent(s.io_full)}'
    swap = f'Swap usata: {size(s.swap_used)}'
    memory = f'PSI RAM some/full: {percent(s.memory_some)} / {percent(s.memory_full)}'
    lead = (io, ram) if risk.kind == 'io' else (ram, io)
    return '  ·  '.join(lead) + '\n' + '  ·  '.join((swap, memory))


def technical_summary(s):
    return (f'Swap-out: {size(s.swap_out, rate=True)}  ·  '
            f'Reclaim: {s.reclaim:.0f} pag/s' if s.reclaim is not None else
            f'Swap-out: {size(s.swap_out, rate=True)}  ·  Reclaim: N/D')


def process_description(candidate, kind):
    name = candidate.leader.name + (' (browser intero)' if candidate.leader.name.lower() == 'chrome' else '')
    if kind == 'io':
        metric = size(candidate.io_bps, rate=True) + ' lettura/scrittura disco osservata'
    else:
        metric = f'{candidate.estimated_bytes / 1024**2:.0f} MiB · {candidate.basis}'
    return name, f'{metric}  ·  {len(candidate.members)} processi; non prova la causa'




class Dialog:
    def __init__(self,config,*,fixture=False):
        import gi
        gi.require_version('Gtk','4.0')
        from gi.repository import Gtk,GLib
        self.Gtk,self.GLib=Gtk,GLib;self.config=config;self.cfg=config['resource_rescue'];self.fixture=fixture
        self.app=Gtk.Application(application_id='com.gernalix.FSM.ResourceRescue')
        self.app.connect('activate',self.activate)
        self.window=None;self.previous=None;self.snapshot=None;self.busy=False;self.healthy=0
        self.started=time.monotonic();self.outcome=2;self.actions=0;self.sources=[];self.io_previous={}
        self.selected_number=None;self.ranked_kind=None;self.chrome_signature=None

    def activate(self,app):
        self.build()
        self.refresh()
        self.sources.append(self.GLib.timeout_add_seconds(int(self.cfg['active_seconds']),self.refresh))

    def build(self,message=''):
        Gtk=self.Gtk
        if self.window: self.window.destroy()
        self.selected_number=None;self.chrome_signature=None;self.snapshot=None
        self.window=Gtk.ApplicationWindow(application=self.app,title='FSM · Recupero risorse'+(' · TEST' if self.fixture else ''))
        self.window.set_default_size(690,440)
        self.window.connect('close-request',lambda *_: self.finish(2))
        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=9)
        for edge in ('top','bottom','start','end'): getattr(box,'set_margin_'+edge)(16)
        self.window.set_child(box)

        self.heading=Gtk.Label(xalign=0,wrap=True)
        self.heading.add_css_class('title-3')
        box.append(self.heading)
        self.metrics=Gtk.Label(xalign=0,wrap=True,selectable=True)
        box.append(self.metrics)
        self.reason=Gtk.Label(xalign=0,wrap=True)
        self.reason.add_css_class('dim-label')
        box.append(self.reason)
        tech=Gtk.Expander(label='Dettagli tecnici')
        self.details=Gtk.Label(xalign=0,wrap=True,selectable=True)
        tech.set_child(self.details);box.append(tech)

        self.pages=Gtk.Notebook()
        self.pages.set_vexpand(True)
        box.append(self.pages)

        process_page=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=7)
        self.process_note=Gtk.Label(xalign=0,wrap=True)
        process_page.append(self.process_note)
        self.process_list=Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.process_list.connect('row-selected',self.select_process)
        process_scroll=Gtk.ScrolledWindow(vexpand=True)
        process_scroll.set_policy(Gtk.PolicyType.NEVER,Gtk.PolicyType.AUTOMATIC)
        process_scroll.set_child(self.process_list)
        process_page.append(process_scroll)
        self.pages.append_page(process_page,Gtk.Label(label='Processi'))

        chrome_page=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        self.chrome_info=Gtk.Label(xalign=0,wrap=True)
        chrome_page.append(self.chrome_info)
        self.chrome_list=Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        chrome_scroll=Gtk.ScrolledWindow(vexpand=True)
        chrome_scroll.set_policy(Gtk.PolicyType.NEVER,Gtk.PolicyType.AUTOMATIC)
        chrome_scroll.set_child(self.chrome_list)
        chrome_page.append(chrome_scroll)
        guidance=Gtk.Label(label='Per identificare i consumi: Task Manager Chrome (Maiusc+Esc). Per scaricare una scheda: icona «FSM Schede Chrome».',wrap=True,xalign=0)
        guidance.add_css_class('dim-label')
        chrome_page.append(guidance)
        self.pages.append_page(chrome_page,Gtk.Label(label='Schede Chrome'))

        self.status=Gtk.Label(label=message,wrap=True,xalign=0)
        self.status.set_visible(bool(message))
        box.append(self.status)
        buttons=Gtk.Box(spacing=10)
        box.append(buttons)
        self.choose_button=Gtk.Button(label='Richiedi chiusura…')
        self.choose_button.set_sensitive(False)
        self.choose_button.connect('clicked',self.choose)
        buttons.append(self.choose_button)
        snooze=Gtk.Button(label='Rimanda 10 minuti')
        snooze.connect('clicked',lambda *_: self.finish(2))
        buttons.append(snooze)
        self.window.present()

    def select_process(self,listbox,row):
        self.selected_number=row.get_index()+1 if row is not None else None
        self.choose_button.set_sensitive(bool(self.selected_number) and not self.busy)

    def clear_processes(self,message):
        self.process_list.unselect_all()
        self.snapshot=None
        self.ranked_kind=None
        self.process_list.set_sensitive(False)
        self.choose_button.set_sensitive(False)
        self.process_note.set_text(message)
        while row:=self.process_list.get_row_at_index(0):
            self.process_list.remove(row)

    def update_processes(self,kind):
        Gtk=self.Gtk
        # Once selected, the number->PID snapshot stays frozen (maximum 20s).
        if self.selected_number and self.snapshot and kind==self.ranked_kind:
            if time.monotonic()-self.snapshot.at<=20:
                return
        self.process_list.unselect_all()
        self.selected_number=None
        self.choose_button.set_sensitive(False)
        self.snapshot=None
        try:
            if self.fixture:
                from .targets import Snapshot,Candidate,Identity
                i=Identity('fixture',999999999,1,os.getuid(),'Applicazione TEST','fixture',1024**3)
                self.snapshot=Snapshot('fixture',time.monotonic(),(Candidate(i,(i,),1024**3,'simulata'),))
            else:
                self.snapshot=candidates(os.getuid(),io_previous=self.io_previous,kind=kind)
                self.io_previous=dict(self.snapshot.io_counters)
            self.ranked_kind=kind
            self.process_note.set_text(
                'Seleziona un processo e conferma. I valori sono indicativi, non una prova di responsabilità.'
                if self.snapshot.candidates else
                'Nessun processo attribuibile in sicurezza. Controlla l’attività disco prima di chiudere applicazioni.')
            while row:=self.process_list.get_row_at_index(0):
                self.process_list.remove(row)
            for candidate in self.snapshot.candidates:
                name,detail=process_description(candidate,kind)
                item=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=2)
                item.set_margin_top(9);item.set_margin_bottom(9)
                item.set_margin_start(12);item.set_margin_end(12)
                title=Gtk.Label(label=name,xalign=0,wrap=True)
                title.add_css_class('heading')
                item.append(title)
                sub=Gtk.Label(label=detail,xalign=0,wrap=True)
                sub.add_css_class('dim-label')
                item.append(sub)
                row=Gtk.ListBoxRow()
                row.set_child(item)
                self.process_list.append(row)
        except (OSError,ValueError,TimeoutError):
            self.snapshot=None
            self.process_note.set_text('Processi non verificabili: nessuna chiusura proposta.')
            while row:=self.process_list.get_row_at_index(0):
                self.process_list.remove(row)

    def update_chrome(self):
        Gtk=self.Gtk
        from gi.repository import Pango
        data=read_recent_tabs(Path(f'/run/user/{os.getuid()}')) if not self.fixture else None
        if data is None:
            self.chrome_info.set_text('Titoli non disponibili. Apri «FSM Schede Chrome» nel browser per aggiornare.')
        else:
            self.chrome_info.set_text(
                f'{len(data["tabs"])}/{data["total"]} schede · dati di {data["age_seconds"]} s fa. '
                'Non attribuibili ai singoli processi né ordinate per consumo.')
        signature=(data['observed_at_utc'],data['total']) if data is not None else None
        if signature==self.chrome_signature:
            return
        self.chrome_signature=signature
        while row:=self.chrome_list.get_row_at_index(0):
            self.chrome_list.remove(row)
        if data is None: return
        for tab in data['tabs']:
            line=Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,spacing=8)
            line.set_margin_top(6);line.set_margin_bottom(6)
            line.set_margin_start(10);line.set_margin_end(10)
            title=Gtk.Label(label=tab['title'],ellipsize=Pango.EllipsizeMode.END,xalign=0,hexpand=True,max_width_chars=68)
            title.set_tooltip_text(tab['title'])
            line.append(title)
            state='Attiva' if tab['active'] else 'Scaricata' if tab['discarded'] else 'Inattiva'
            flag=Gtk.Label(label=state,xalign=1)
            flag.add_css_class('dim-label')
            line.append(flag)
            row=Gtk.ListBoxRow()
            row.set_child(line)
            self.chrome_list.append(row)

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
        self.heading.set_text(risk_title(risk))
        self.metrics.set_text(resource_summary(s,risk))
        self.reason.set_text(risk.explanation)
        self.details.set_text(technical_summary(s))
        self.update_chrome()
        if self.busy:return True
        self.healthy=self.healthy+1 if risk.level==0 and clearly_healthy(s,self.cfg) else 0
        if self.healthy>=self.cfg['recovery_samples']:
            self.heading.set_text('Pressione rientrata')
            self.clear_processes('Pressione rientrata: nessuna chiusura necessaria.')
            self.GLib.timeout_add_seconds(4,lambda:self.finish(0));return False
        if risk.level<=0:
            self.clear_processes('In attesa di conferma del recupero; nessuna chiusura proposta.')
            return True
        if risk.kind=='disk':
            self.clear_processes('Per liberare spazio usa Analizzatore utilizzo disco. FSM non elimina file.')
            return True
        self.process_list.set_sensitive(True)
        self.update_processes(risk.kind)
        return True

    def choose(self,*_):
        if self.busy or self.snapshot is None or self.selected_number is None: return
        try:
            number=self.selected_number
            if not 1<=number<=len(self.snapshot.candidates) or time.monotonic()-self.snapshot.at>20:
                raise ValueError()
        except ValueError:
            self.process_list.unselect_all();self.refresh()
            self.status.set_text('Selezione scaduta. Seleziona nuovamente il processo.')
            self.status.set_visible(True)
            return
        snapshot=self.snapshot;candidate=snapshot.candidates[number-1]
        self.busy=True;self.choose_button.set_sensitive(False)
        # All apps require an additional informed confirmation, including editors/browser.
        Gtk=self.Gtk
        confirmation=Gtk.Window(application=self.app,transient_for=self.window,modal=True,title='Conferma chiusura')
        box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=12)
        for edge in ('top','bottom','start','end'): getattr(box,'set_margin_'+edge)(18)
        confirmation.set_child(box)
        action_name=candidate.leader.name + (' (può chiudere l’intero browser)' if candidate.leader.name.lower() == 'chrome' else '')
        box.append(Gtk.Label(label=f'Richiedere la chiusura di {action_name}?',wrap=True))
        box.append(Gtk.Label(label='Possibili dati non salvati e sessioni aperte. Prima salva il lavoro. Chiusura normale quando disponibile, altrimenti SIGTERM; nessun SIGKILL.',wrap=True,max_width_chars=65))
        cancel=Gtk.Button(label='Annulla');accept=Gtk.Button(label='Confermo: richiedi chiusura')
        box.append(cancel);box.append(accept)
        def response(dialog,response):
            dialog.destroy()
            if response!=Gtk.ResponseType.OK:
                self.busy=False;self.process_list.unselect_all();self.refresh()
                self.status.set_text('Annullato: nessun segnale inviato.')
                self.status.set_visible(True)
                return
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
        self.pages.set_current_page(1)

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
