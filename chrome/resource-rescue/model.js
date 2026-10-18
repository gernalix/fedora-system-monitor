/* No storage, network, debugger, content injection or process termination. */
export function snapshot(tabs, session, now = Date.now()) {
  return Object.freeze({session, nonce: crypto.randomUUID(), at: now,
    rows: Object.freeze(tabs.filter(t => !t.incognito).map(t => Object.freeze({
      id:t.id, windowId:t.windowId, title:t.title || `Scheda ${t.id}`,
      url:t.url, pendingUrl:t.pendingUrl, active:t.active, audible:!!t.audible,
      discarded:!!t.discarded, pinned:!!t.pinned, autoDiscardable:t.autoDiscardable,
      lastAccessed:t.lastAccessed || 0, cpu:null, rss:null, privateBytes:null,
      io:null, linuxPid:null, reliability:'non disponibile: nessuna attribuzione renderer/tab verificata'
    })).sort((a,b) => a.lastAccessed-b.lastAccessed))});
}
export function validate(s, number, current, session, now=Date.now(), invalidated=false) {
  const old=s.rows[number-1];
  if (invalidated || session!==s.session || now-s.at>20000 || now<s.at || !Number.isInteger(number) || !old)
    throw Error('Classifica scaduta o cambiata: premi Aggiorna e scegli nuovamente.');
  if (!current || old.id!==current.id || old.windowId!==current.windowId || old.url!==current.url || old.pendingUrl!==current.pendingUrl || current.incognito)
    throw Error('Identità della scheda cambiata: nessuna azione eseguita.');
  return old;
}
export function discardable(t) { return !t.active && !t.audible && !t.pinned && !t.discarded && t.autoDiscardable!==false; }
export async function apply(api,s,number,session,action,confirmChoice,invalidated,clock=Date.now) {
  const old=s.rows[number-1];
  if (!old) throw Error('Numero non valido.');
  if (!['discard','close'].includes(action)) throw Error('Azione non supportata.');
  let t=await api.get(old.id);
  validate(s,number,t,session,clock(),invalidated());
  if (action==='discard' && !discardable(t)) throw Error('Scheda attiva, audio, fissata, già scaricata o protetta: scaricamento rifiutato.');
  if (!await confirmChoice()) return {outcome:'cancelled'};
  // Re-read AFTER the user confirmation, never assume the old number is current.
  t=await api.get(old.id);
  validate(s,number,t,session,clock(),invalidated());
  if (action==='discard') {
    if (!discardable(t)) throw Error('La scheda non è più scaricabile.');
    await api.discard(t.id); // Explicit tabId, never Chrome's implicit choice.
    const after=await api.get(t.id);
    if (!after.discarded) throw Error('Scaricamento non verificato; nessun beneficio RAM presunto.');
    return {outcome:'discarded',ramFreed:null};
  }
  await api.remove(t.id);
  try { await api.get(t.id); } catch (_) { return {outcome:'closed',ramFreed:null}; }
  throw Error('La scheda risulta ancora presente.');
}
