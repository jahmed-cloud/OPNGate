const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = ['credentials','dom','live','ui','charts','flow'].map(name => fs.readFileSync(`portal/app/static/console/${name}.js`,'utf8')).join('\n') + fs.readFileSync('portal/app/static/portal.js','utf8');
const handlers = new Map(), intervals = [], requests = [], streams = [], paints = [], queries = new Map();
let graphPaints = 0, graphedPoints = 0;
let expandedDetails = [];
let now = 100000, frame = {revision:'1',reported_at:100,source:'live',stale:false,clients_stale:false,
  clients_reported_at:100,interfaces:[],wan:{rx_bps:1000,tx_bps:100},clients:[]};
const classes = {toggle(){}};
const chip = {classList:classes,setAttribute(){},addEventListener(type,fn){handlers.set('chip:'+type,fn);}};
const refresh = {disabled:false,setAttribute(){},removeAttribute(){},addEventListener(type,fn){handlers.set('refresh:'+type,fn);}};
const rateNode = {dataset:{liveRate:'rx_bps'},textContent:''};
const main = {dataset:{refresh:'60'},classList:classes,contains:()=>false,
  querySelector:selector=>selector.includes('[data-live-rate]')?{}:null,querySelectorAll:selector=>{
    queries.set(selector,(queries.get(selector)||0)+1);
    if(selector==='details[open]')return expandedDetails;
    return selector==='[data-live-rate]'?[rateNode]:[];
  }};
const document = {hidden:false,activeElement:null,getElementById:id=>({main,live:chip,'refresh-now':refresh}[id]||null),
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
  requestAnimationFrame(fn){paints.push(fn);return paints.length;},
  fetch:async (url)=>{requests.push(url);return {ok:true,status:200,redirected:false,json:async()=>frame,text:async()=>''};},
  paintLiveGraph(points){graphPaints++;graphedPoints=points.length;},liveRate:value=>String(value),
  patchFragment(){},placeFlowControls(){},watchFlow(){},flowOpen:()=>''};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function startLive'),source.indexOf('// Tell the server')),context);
const settle=()=>new Promise(setImmediate);
const paint=()=>{while(paints.length)paints.shift()();};
async function mainTest(){
  context.startLive(); await settle();
  assert.equal(streams.length,1); assert.equal(streams[0].url,'/api/live/stream');
  assert.deepEqual(requests,['/api/live']); // Single bootstrap snapshot.
  assert.equal(paints.length,1,'bootstrap/timer work shares one animation-frame paint');
  paint();
  assert.equal(rateNode.textContent,'1000');
  streams[0].onopen();
  streams[0].listeners.telemetry({data:JSON.stringify(frame)});
  const painted=graphPaints, beforeQueries=queries.get('[data-live-rate]');
  for(let i=1;i<=3;i++){
    frame={...frame,revision:String(i+1),reported_at:100+i/10,wan:{rx_bps:1000+i,tx_bps:100}};
    streams[0].listeners.telemetry({data:JSON.stringify(frame)});
  }
  assert.equal(paints.length,1,'bursty SSE reports must coalesce into one frame');
  assert.equal(graphPaints,painted,'no immediate duplicate chart redraw');
  paint();
  assert.equal(graphPaints,painted+1);assert.equal(graphedPoints,4,'keep every observed point despite coalescing paints');
  assert.equal(rateNode.textContent,'1003');
  assert.equal(queries.get('[data-live-rate]'),beforeQueries,'mounted live nodes are reused');
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
  document.hidden=false;
  handlers.get('chip:click')(); // Pause again for an explicit manual refresh.
  paint();
  frame={...frame,revision:'manual',reported_at:now/1000,wan:{rx_bps:2048,tx_bps:100}};
  const beforeManual=graphPaints, beforeManualQueries=queries.get('[data-live-rate]');
  const updating=handlers.get('refresh:click')();
  assert.equal(refresh.disabled,true,'manual refresh shows a pending state');
  await updating;paint();
  assert.equal(refresh.disabled,false);
  assert.equal(rateNode.textContent,'2048');
  assert.equal(graphPaints,beforeManual+1,'manual refresh updates the chart while automatic updates stay paused');
  assert.equal(queries.get('[data-live-rate]'),beforeManualQueries+1,'fragment refresh invalidates cached node references');
  expandedDetails=[{closest:()=>({})}]; // An expanded subgroup inside a closed Manage menu.
  const beforeResume=requests.filter(url=>url==='https://example.test/').length;
  handlers.get('chip:click')();await settle();paint();
  assert.equal(requests.filter(url=>url==='https://example.test/').length,beforeResume+1,
    'hidden expanded subgroups must not freeze page refresh');
  expandedDetails=[{closest:()=>null}]; // A genuinely open, visible menu.
  const beforeBusy=requests.length;
  intervals.find(i=>i.ms===60000).fn();await settle();
  assert.equal(requests.length,beforeBusy,'visible menus still protect form inputs from refresh');
  handlers.get('window:pagehide')();
  console.log('PASS: SSE bootstrap/fallback, frame-coalesced paints, mounted-node caching, paused manual refresh and hidden-tab cleanup');
}
mainTest().catch(error=>{console.error(error);process.exitCode=1;});
