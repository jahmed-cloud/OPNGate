const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = ['credentials','dom','live','ui','charts','flow'].map(name => fs.readFileSync(`portal/app/static/console/${name}.js`,'utf8')).join('\n') + fs.readFileSync('portal/app/static/portal.js','utf8');
const handlers = new Map(), intervals = [], requests = [], streams = [];
let now = 100000, frame = {revision:'1',reported_at:100,source:'live',stale:false,clients_stale:false,
  clients_reported_at:100,interfaces:[],wan:{rx_bps:1000,tx_bps:100},clients:[]};
const classes = {toggle(){}};
const chip = {classList:classes,setAttribute(){},addEventListener(type,fn){handlers.set('chip:'+type,fn);}};
const main = {dataset:{refresh:'60'},classList:classes,contains:()=>false,
  querySelector:selector=>selector.includes('[data-live-rate]')?{}:null,querySelectorAll:()=>[]};
const document = {hidden:false,activeElement:null,getElementById:id=>({main,live:chip}[id]||null),
  addEventListener(type,fn){handlers.set('document:'+type,fn);}};
class EventSource {
  constructor(url){this.url=url;this.listeners={};this.closed=false;streams.push(this);}
  addEventListener(type,fn){this.listeners[type]=fn;}
  close(){this.closed=true;}
}
class Clock extends Date { static now(){return now;} }
const context={document,EventSource,Date:Clock,AbortController,URL,
  window:{location:{href:'https://example.test/',reload(){throw new Error('unexpected reload');}},
    getSelection:()=>'',addEventListener(type,fn){handlers.set('window:'+type,fn);}},
  localStorage:{getItem:()=>null,setItem(){}},
  setInterval(fn,ms){intervals.push({fn,ms});},setTimeout,clearTimeout,
  fetch:async (url)=>{requests.push(url);return {ok:true,status:200,redirected:false,json:async()=>frame,text:async()=>''};},
  paintLiveGraph(){},patchFragment(){},placeFlowControls(){},watchFlow(){},flowOpen:()=>''};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function startLive'),source.indexOf('// Tell the server')),context);
const settle=()=>new Promise(setImmediate);
async function mainTest(){
  context.startLive(); await settle();
  assert.equal(streams.length,1); assert.equal(streams[0].url,'/api/live/stream');
  assert.deepEqual(requests,['/api/live']); // Single bootstrap snapshot.
  streams[0].onopen();
  streams[0].listeners.telemetry({data:JSON.stringify(frame)});
  const watch=intervals.find(i=>i.ms===1000).fn;
  now+=1000; watch(); await settle();
  assert.equal(requests.length,1,'healthy SSE must not also poll JSON');
  handlers.get('chip:click')();
  assert.equal(streams[0].closed,true,'pause closes the stream');
  now+=1000; watch(); await settle();
  assert.equal(requests.length,1,'pause stops fallback polling too');
  handlers.get('chip:click')(); await settle();
  assert.equal(streams.length,2,'resume creates one fresh stream');
  const resumed=streams[1]; resumed.onopen();
  frame={...frame,reported_at:now/1000,revision:'2'};
  resumed.listeners.telemetry({data:JSON.stringify(frame)});
  const beforeError=requests.filter(url=>url==='/api/live').length;
  resumed.onerror(); await settle();
  assert.equal(resumed.closed,true);
  assert.equal(requests.filter(url=>url==='/api/live').length,beforeError+1,'stream failure immediately falls back');
  now+=1000; watch(); await settle();
  assert.equal(requests.filter(url=>url==='/api/live').length,beforeError+2,'fallback runs at one second');
  document.hidden=true; handlers.get('document:visibilitychange')();
  const count=requests.length; now+=1000; watch(); await settle();
  assert.equal(requests.length,count,'hidden tabs stop all fast requests');
  handlers.get('window:pagehide')();
  console.log('PASS: SSE bootstrap, no duplicate healthy polls, pause/resume, one-second fallback and hidden-tab cleanup');
}
mainTest().catch(error=>{console.error(error);process.exitCode=1;});
