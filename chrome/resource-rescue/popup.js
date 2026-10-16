import {snapshot,apply} from './model.js';
const session=crypto.randomUUID();let current=null,invalidated=false,busy=false;
const el=id=>document.getElementById(id);
const status=text=>{el('status').textContent=text;};
async function refresh() {
  if (busy) return;
  current=snapshot(await chrome.tabs.query({}),session);invalidated=false;el('number').value='';
  el('tabs').replaceChildren(...current.rows.map(t=>{
    const li=document.createElement('li');
    li.textContent=`#${t.id} · ${t.title} · ${t.active?'attiva':t.discarded?'scaricata':'inattiva'} · RAM/CPU/I/O: N/D · affidabilità: ${t.reliability}`;
    return li;
  }));
  el('capabilities').textContent=`Schede osservate: ${current.rows.length}. API processes esposta a questa estensione: ${typeof chrome.processes==='object'?'sì, non usata senza attribuzione verificata':'no'}. Nessun permesso processes/debugger richiesto.`;
  status('Nuova classifica: digita un numero. L’elenco scade dopo 20 secondi.');
  const major=Number(navigator.userAgent.match(/Chrome\/(\d+)/)?.[1] || 0);
  try {
    await chrome.runtime.sendNativeMessage('com.gernalix.fsm_resource_rescue',{
      session,processes_exposed:typeof chrome.processes==='object',
      tabs_available:typeof chrome.tabs?.query==='function',browser_major:major
    });
  } catch(_) {status('Elenco disponibile; host locale non connesso. Nessun dato personale inviato.');}

}
async function act(action) {
  if (busy || !current) return;
  busy=true;el('discard').disabled=true;el('close').disabled=true;
  try {
    const number=Number(el('number').value);
    const result=await apply(chrome.tabs,current,number,session,action,async()=>confirm(
      `${action==='discard'?'Scaricare dalla RAM':'Chiudere'} solo la scheda selezionata? Possibili dati non salvati. Nessuna garanzia sulla RAM liberata. Conferma per continuare.`),()=>invalidated);
    status(result.outcome==='cancelled'?'Annullato: nessuna azione.':result.outcome==='discarded'?'Scaricamento verificato. RAM liberata non misurabile per scheda; verifica la pressione FSM.':'Chiusura verificata. RAM liberata non attribuibile con precisione.');
    invalidated=true;
  } catch(e) {status(e.message);}
  finally {busy=false;el('discard').disabled=false;el('close').disabled=false;}
}
el('refresh').addEventListener('click',refresh);
el('discard').addEventListener('click',()=>act('discard'));
el('close').addEventListener('click',()=>act('close'));
// Enter requests a discard only; still requires an explicit number and confirmation.
el('number').addEventListener('keydown',e=>{if(e.key==='Enter')act('discard');});
chrome.tabs.onUpdated.addListener(()=>{invalidated=true;});
chrome.tabs.onRemoved.addListener(()=>{invalidated=true;});
refresh().catch(e=>status(e.message));
