const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('portal/app/static/portal.js','utf8');
let tooltip;
const hoverContext={document:{querySelectorAll:()=>[],createElement:()=>({style:{},setAttribute(){},offsetWidth:50,offsetHeight:20}),body:{appendChild(el){tooltip=el;}}},window:{innerWidth:1000}};
vm.createContext(hoverContext);
vm.runInContext(source.slice(source.indexOf('const tipCache'),source.indexOf('// Coalesce fast pointer')),hoverContext);
const hoverSvg={dataset:{tips:'[[10,20,"old value"]]'},getBoundingClientRect:()=>({left:0,top:100,width:100}),viewBox:{baseVal:{width:100}},querySelector:()=>null,classList:{add(){}}};
const pointer={target:{closest:()=>hoverSvg},clientX:10};
hoverContext.chartTip(pointer); assert.equal(tooltip.textContent,'old value');
hoverSvg.dataset.tips='[[10,20,"new value"]]';
hoverContext.chartTip(pointer); assert.equal(tooltip.textContent,'new value');
const seriesContext = {}; vm.createContext(seriesContext);
vm.runInContext(source.slice(source.indexOf('function liveSeries'),source.indexOf('function paintLiveGraph')),seriesContext);
const series = seriesContext.liveSeries([{ts:100,rx:100,tx:50},{ts:102,rx:200,tx:null},{ts:120,rx:300,tx:100}],120);
assert.equal((series.rx.match(/ M/g)||[]).length + (series.rx.startsWith('M')?1:0),2);
assert.equal(series.count,3);
assert.equal(seriesContext.liveSeries([{ts:1,rx:1000,tx:1000}],200).count,0);
assert.equal(seriesContext.liveSeries([{ts:200,rx:null,tx:null}],200).rx,'');
const ctx = {};
vm.createContext(ctx);
vm.runInContext(source.slice(source.indexOf('function patchNode'),source.indexOf('function patchFragment')),ctx);
class Node {
 constructor(name, attrs={}, children=[]) { this.nodeName=name; this.nodeType=name==='#text'?3:1; this.attrs={...attrs}; this.childNodes=[]; this.nodeValue=attrs.value||null; for(const c of children)this.insertBefore(c,null); }
 get attributes(){return Object.entries(this.attrs).map(([name,value])=>({name,value}));}
 get firstChild(){return this.childNodes[0]||null;}
 get nextSibling(){if(!this.parentNode)return null;return this.parentNode.childNodes[this.parentNode.childNodes.indexOf(this)+1]||null;}
 get id(){return this.attrs.id;}
 getAttribute(k){return this.attrs[k]??null;} hasAttribute(k){return k in this.attrs;}
 setAttribute(k,v){this.attrs[k]=v;} removeAttribute(k){delete this.attrs[k];}
 insertBefore(n,c){n.remove();const i=c?this.childNodes.indexOf(c):this.childNodes.length;this.childNodes.splice(i,0,n);n.parentNode=this;return n;}
 remove(){if(this.parentNode){const a=this.parentNode.childNodes;a.splice(a.indexOf(this),1);this.parentNode=null;}}
 replaceWith(n){const p=this.parentNode;p.insertBefore(n,this);this.remove();}
 cloneNode(){return new Node(this.nodeName,this.attrs,this.childNodes.map(n=>n.cloneNode()));}
 isEqualNode(n){return this.nodeName===n.nodeName&&this.nodeValue===n.nodeValue&&JSON.stringify(this.attrs)===JSON.stringify(n.attrs)&&this.childNodes.length===n.childNodes.length&&this.childNodes.every((c,i)=>c.isEqualNode(n.childNodes[i]));}
}
const path = new Node('path',{d:'M0 0L1 1'}), svg = new Node('svg',{},[path]);
const chart = new Node('section',{'data-refresh-section':'chart'},[svg]);
const metrics = new Node('div',{'data-refresh-section':'metrics'},[new Node('#text',{value:'10'})]);
const main = new Node('main',{},[metrics,chart]);
const next = new Node('main',{},[new Node('p',{'data-refresh-section':'warning'},[new Node('#text',{value:'stale'})]),chart.cloneNode(),metrics.cloneNode()]);
next.childNodes[1].firstChild.firstChild.attrs.d='M0 0L2 2';
ctx.patchChildren(main,next);
assert.equal(main.childNodes[1],chart); assert.equal(chart.firstChild,svg); assert.equal(svg.firstChild,path); assert.equal(path.attrs.d,'M0 0L2 2');
assert.equal(main.childNodes[2],metrics);
ctx.patchChildren(main,new Node('main',{},[metrics.cloneNode(),chart.cloneNode()]));
assert.equal(main.childNodes.length,2); assert.equal(main.firstChild,metrics); assert.equal(main.childNodes[1],chart);
const mixed=new Node('main',{},[new Node('div'),new Node('#text',{value:'old'}),new Node('b')]);
ctx.patchChildren(mixed,new Node('main',{},[new Node('p'),new Node('#text',{value:'new'})]));
assert.equal(mixed.childNodes.length,2);assert.equal(mixed.firstChild.nodeName,'p');assert.equal(mixed.childNodes[1].nodeValue,'new');
console.log('PASS: keyed insertion/reordering/removal, SVG identity and path updates, mixed-node replacement');
