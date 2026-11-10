import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
globalThis.crypto??=webcrypto;
import {snapshot,validate,discardable,apply,tabTitleSnapshot} from '../chrome/resource-rescue/model.js';
const tab={id:42,windowId:1,url:'https://example.test',title:'Private test title',lastAccessed:1,active:false,audible:false,pinned:false,discarded:false,autoDiscardable:true};
const s=snapshot([tab,{...tab,id:43}], 'session',1000);
assert.equal(s.rows.length,2);assert.equal(s.rows[0].rss,null);assert.equal(s.rows[0].linuxPid,null);
assert.throws(()=>validate(s,1,tab,'other',1001));
assert.throws(()=>validate(s,1,tab,'session',22000));
assert.throws(()=>validate(s,1,{...tab,url:'https://changed.test'},'session',1001));
assert.throws(()=>validate(s,1,tab,'session',1001,true));
assert.equal(discardable({...tab,active:true}),false);
assert.equal(discardable({...tab,audible:true}),false);
let calls=[];let state={...tab};
const api={get:async()=>state,discard:async id=>{calls.push(['discard',id]);state.discarded=true;},remove:async id=>calls.push(['remove',id])};
let result=await apply(api,s,1,'session','discard',async()=>false,()=>false,()=>1001);
assert.equal(result.outcome,'cancelled');assert.equal(calls.length,0);
result=await apply(api,s,1,'session','discard',async()=>true,()=>false,()=>1001);
assert.equal(result.outcome,'discarded');assert.deepEqual(calls,[['discard',42]]);assert.equal(result.ramFreed,null);
state={...tab};calls=[];
await assert.rejects(()=>apply(api,s,1,'session','discard',async()=>{state.url='https://changed.test';return true;},()=>false,()=>1001));
assert.equal(calls.length,0);
state={...tab};await assert.rejects(()=>apply(api,s,1,'session','discard',async()=>true,()=>true,()=>1001));
assert.equal(calls.length,0);
const titlePacket=tabTitleSnapshot([
  ...Array.from({length:20},(_,i)=>({...tab,id:100+i,active:false,lastAccessed:i+1})),
  {...tab,id:40,active:true,title:'Scheda <attiva>\n aggiornata',lastAccessed:100},
  {...tab,id:60,incognito:true,title:'NON ESPORRE'}
],crypto.randomUUID());
assert.equal(titlePacket.kind,'tabs');
assert.equal(titlePacket.total,21);
assert.equal(titlePacket.tabs.length,16);
assert.equal(titlePacket.tabs[0].title,'Scheda <attiva>  aggiornata');
assert.equal(titlePacket.tabs[0].active,true);
assert.equal(titlePacket.tabs.some(t=>t.title.includes('NON ESPORRE')),false);
assert.equal(JSON.stringify(titlePacket).includes('https://'),false);
assert.equal(JSON.stringify(titlePacket).includes('windowId'),false);
assert.equal(JSON.stringify(titlePacket).includes('linuxPid'),false);
console.log('Chrome rescue: snapshot/session/reuse/confirmation/shared-memory/privacy/degraded tests PASS');
