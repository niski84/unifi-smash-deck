// ─────────────────────────────────────────────────────────────────────────────
// Smash Deck 3D — generic, world-agnostic visualization engine.
//
// It knows how to render a graph of {nodes, links} as a live 3D scene: cone-tree
// layout, a persistent bandwidth-driven particle pool, cinematic camera fly-to,
// bloom, picking, filter pills, and an SSE/polling data loop. It knows NOTHING
// about UniFi, networks, cameras, or security — those live in a "world adapter".
//
// A world adapter supplies: where to fetch data + how to map it to {nodes,links}
// (buildGraph), how to style/label/describe a node, and optional per-update and
// per-frame hooks for overlays. Build a new world = write an adapter, not edit this.
//
// Node schema the engine relies on:
//   { id, parent, nodeType, label, sz, network?, upBps, downBps, directRate?,
//     txB?, rxB? }   (+ x/y/z written by layout)
// Link schema: { child, parent, net }   (net = filter group; 'infra' = always shown)
// ─────────────────────────────────────────────────────────────────────────────
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { Line2 } from 'three/addons/lines/Line2.js';
import { LineGeometry } from 'three/addons/lines/LineGeometry.js';
import { LineMaterial } from 'three/addons/lines/LineMaterial.js';

export { THREE };
export const fmtUp = s => { if(!s) return '—'; const d=Math.floor(s/86400), h=Math.floor((s%86400)/3600); return d>0?`${d}d ${h}h`:`${h}h ${Math.floor((s%3600)/60)}m`; };
export const fmtB  = b => { if(!b) return '0 B'; if(b<1024) return b+' B'; if(b<1048576) return (b/1024).toFixed(1)+' KB'; return (b/1048576).toFixed(1)+' MB'; };

const MIN_BPS  = 2000;        // < 2 KB/s ⇒ idle (no dots). Low so real traffic shows.
const FULL_BPS = 3_000_000;   // ~3 MB/s saturates the visual (max dot density)
const SLOTS    = 16;          // max dots per direction per link
const DOWN_COL = new THREE.Color(0x36c5ff);   // download: parent → child (cyan)
const UP_COL   = new THREE.Color(0xffe24d);   // upload:   child → parent (yellow)
const WHITE_HOT= new THREE.Color(0xbfeaff);

export function createEngine(adapter){
  const W=()=>innerWidth, H=()=>innerHeight;

  // ── scene / camera / renderer / post ───────────────────────────────────────
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x03040a, 0.0009);
  const camera = new THREE.PerspectiveCamera(55, W()/H(), 1, 6000);
  camera.position.set(0, 60, 760);

  const renderer = new THREE.WebGLRenderer({ antialias:true, alpha:false });
  renderer.setSize(W(), H()); renderer.setPixelRatio(Math.min(devicePixelRatio,2));
  renderer.setClearColor(0x03040a, 1);
  document.getElementById('scene').appendChild(renderer.domElement);

  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(W(),H()), 0.9, 0.7, 0.2);
  composer.addPass(bloom);

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true; controls.dampingFactor = 0.08;
  controls.autoRotate = true; controls.autoRotateSpeed = 0.5;
  controls.target.set(0, -60, 0);
  renderer.domElement.addEventListener('pointerdown', ()=>{ controls.autoRotate=false; fly=null; });

  scene.add(new THREE.AmbientLight(0x556688, 0.7));
  const keyLight = new THREE.PointLight(0xffffff, 1.1, 0, 0); keyLight.position.set(200,400,300); scene.add(keyLight);

  (function stars(){
    const g=new THREE.BufferGeometry(), n=900, p=new Float32Array(n*3);
    for(let i=0;i<n;i++){ const r=2200+Math.random()*1500, t=Math.random()*Math.PI*2, ph=Math.acos(2*Math.random()-1);
      p[i*3]=r*Math.sin(ph)*Math.cos(t); p[i*3+1]=r*Math.cos(ph); p[i*3+2]=r*Math.sin(ph)*Math.sin(t); }
    g.setAttribute('position', new THREE.BufferAttribute(p,3));
    scene.add(new THREE.Points(g, new THREE.PointsMaterial({color:0x223152,size:2,sizeAttenuation:false})));
  })();

  // reusable node geometries (a world picks one per node via styleNode().geoKey)
  const GEO = Object.assign({
    udm: new THREE.IcosahedronGeometry(1,1),
    usw: new THREE.BoxGeometry(1.5,1.5,1.5),
    uap: new THREE.CylinderGeometry(1.2,1.2,0.5,16),
    wan: new THREE.OctahedronGeometry(1,0),
    client: new THREE.SphereGeometry(1,12,12),
    camera: new THREE.ConeGeometry(1.1,2.2,4),
  }, adapter.GEO||{});

  const nodeGroup=new THREE.Group(), linkGroup=new THREE.Group(), labelGroup=new THREE.Group();
  const camGroup=new THREE.Group(), alertGroup=new THREE.Group();   // for world overlays
  scene.add(nodeGroup, linkGroup, labelGroup, camGroup, alertGroup);

  // ── shared graph/render state ───────────────────────────────────────────────
  let byId={}, pickables=[], meshById={}, structKey='', framedOnce=false;
  let activeNets=new Set(['all']);
  let linkRefs=[], linkLines=[], rateState={}, prevBytes={}, pool=null;
  let fly=null;

  // ── utilities ───────────────────────────────────────────────────────────────
  function clearGroup(g){ while(g.children.length){ const o=g.children.pop(); o.geometry?.dispose?.(); o.material?.dispose?.(); } }
  function makeLabel(text, color){
    const c=document.createElement('canvas'), ctx=c.getContext('2d');
    ctx.font='600 30px Courier New'; const w=ctx.measureText(text).width;
    c.width=w+24; c.height=44;
    ctx.font='600 30px Courier New'; ctx.fillStyle=color; ctx.textBaseline='middle';
    ctx.shadowColor=color; ctx.shadowBlur=8; ctx.fillText(text,12,24);
    const tex=new THREE.CanvasTexture(c); tex.minFilter=THREE.LinearFilter;
    const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:tex, depthTest:false, transparent:true}));
    sp.scale.set(c.width*0.16, c.height*0.16, 1);
    return sp;
  }
  function makeDot(){
    const c=document.createElement('canvas'); c.width=c.height=32; const x=c.getContext('2d');
    const grd=x.createRadialGradient(16,16,0,16,16,16); grd.addColorStop(0,'#fff'); grd.addColorStop(0.3,'#fff'); grd.addColorStop(1,'rgba(255,255,255,0)');
    x.fillStyle=grd; x.beginPath(); x.arc(16,16,16,0,7); x.fill();
    return new THREE.CanvasTexture(c);
  }
  function rateInten(bps){
    if(bps < MIN_BPS) return 0;
    const lo=Math.log10(MIN_BPS), hi=Math.log10(FULL_BPS);
    return Math.max(0, Math.min(1, (Math.log10(bps)-lo)/(hi-lo)));
  }

  // ── cone-tree layout ────────────────────────────────────────────────────────
  function layout(nodes){
    const idx={}; nodes.forEach(n=>{idx[n.id]=n; n._leaves=0;});
    const kids={}; nodes.forEach(n=>kids[n.id]=[]);
    nodes.forEach(n=>{ if(n.parent&&idx[n.parent]) kids[n.parent].push(n.id); });
    const ROOT=adapter.rootId||'wan';
    (function count(id){ const c=kids[id]; if(!c.length){idx[id]._leaves=1;return 1;} let s=0; for(const k of c)s+=count(k); return idx[id]._leaves=s; })(ROOT);
    for(const id in kids) kids[id].sort((a,b)=>idx[b]._leaves-idx[a]._leaves);
    const LAYER=90, TOP=240, RING=82;
    (function place(id,a0,a1,depth){
      const n=idx[id], ang=(a0+a1)/2, r=depth===0?0:depth*RING+15;
      n.x=r*Math.cos(ang); n.z=r*Math.sin(ang); n.y=TOP-depth*LAYER; n.depth=depth;
      const c=kids[id]; if(!c.length) return;
      const total=c.reduce((s,k)=>s+idx[k]._leaves,0)||1, span=a1-a0, pad=Math.min(span*0.04,0.05);
      let cur=a0+pad; const usable=span-pad*2;
      for(const k of c){ const f=idx[k]._leaves/total; place(k,cur,cur+usable*f,depth+1); cur+=usable*f; }
    })(ROOT,0,Math.PI*2,0);
  }

  // ── cinematic camera fly-to ───────────────────────────────────────────────────
  const easeIO = t => t<.5 ? 4*t*t*t : 1 - Math.pow(-2*t+2,3)/2;
  function flyToPoint(target, dist){
    controls.autoRotate=false;
    const et=target.clone();
    let dir=new THREE.Vector3().subVectors(camera.position, et);
    if(dir.lengthSq()<1) dir.set(0,0.5,1);
    dir.normalize(); dir.y=Math.max(dir.y,0.28); dir.normalize();
    const ep=et.clone().add(dir.multiplyScalar(dist));
    const span=new THREE.Vector3().subVectors(ep, camera.position);
    const perp=new THREE.Vector3(-span.z, span.length()*0.12, span.x).normalize().multiplyScalar(span.length()*0.4);
    fly={t:0, dur:2.3, sp:camera.position.clone(), st:controls.target.clone(), ep, et, perp};
  }
  function flyToNode(id, mult){ const n=byId[id]; if(!n) return; flyToPoint(new THREE.Vector3(n.x,n.y,n.z), Math.max(55, n.sz*(mult||9))); }
  function flyToOverview(){
    const b=new THREE.Box3(); for(const id in byId){ const n=byId[id]; b.expandByPoint(new THREE.Vector3(n.x,n.y,n.z)); }
    const c=b.getCenter(new THREE.Vector3()), s=b.getSize(new THREE.Vector3());
    const r=Math.max(s.x,s.y,s.z)*0.62, d=r/Math.tan((camera.fov*Math.PI/180)/2)*1.15;
    flyToPoint(c, d);
  }

  // ── scene build (idempotent: rebuild meshes only on structure change) ─────────
  function buildScene(data){
    layout(data.nodes);
    byId={}; data.nodes.forEach(n=>byId[n.id]=n);
    computeRates(data.nodes);
    const key=data.nodes.map(n=>n.id).sort().join('|');
    if(key!==structKey){
      structKey=key; rebuildMeshes(data); buildParticlePool(data.links);
    } else {
      for(const n of data.nodes) if(meshById[n.id]) meshById[n.id].userData=n;
    }
    updateFilterVisibility();
    if(!framedOnce){ framedOnce=true; frameScene(data.nodes); }
  }
  function rebuildMeshes(data){
    clearGroup(nodeGroup); clearGroup(linkGroup); clearGroup(labelGroup);
    pickables=[]; for(const k in meshById) delete meshById[k];
    for(const n of data.nodes){
      const st = adapter.styleNode(n);                       // {color, geoKey, emissive, halo, label}
      const col = st.color;
      const geo = GEO[st.geoKey] || GEO.client;
      const mat = new THREE.MeshStandardMaterial({ color:col, emissive:col, emissiveIntensity: st.emissive, metalness:0.3, roughness:0.4 });
      const m = new THREE.Mesh(geo, mat);
      m.position.set(n.x,n.y,n.z); m.scale.setScalar(n.sz); m.userData=n;
      nodeGroup.add(m); pickables.push(m); meshById[n.id]=m;
      if(st.halo){
        const halo=new THREE.Mesh(geo, new THREE.MeshBasicMaterial({color:col,wireframe:true,transparent:true,opacity:0.25}));
        halo.position.copy(m.position); halo.scale.setScalar(n.sz*1.35); nodeGroup.add(halo);
      }
      if(st.label){ const lab=makeLabel(n.label, col); lab.position.set(n.x, n.y+n.sz+9, n.z); labelGroup.add(lab); }
    }
    linkLines=[];
    for(const l of data.links){
      const a=byId[l.parent], b=byId[l.child]; if(!a||!b) continue;
      const g=new LineGeometry(); g.setPositions([a.x,a.y,a.z, b.x,b.y,b.z]);
      const base = adapter.linkColor(l);
      const mat=new LineMaterial({ color:base.clone().getHex(), linewidth:1.5, transparent:true, opacity:0.45, worldUnits:false });
      mat.resolution.set(W(), H());
      const line=new Line2(g, mat); line.computeLineDistances(); line.userData=l;
      linkGroup.add(line);
      linkLines.push({line, mat, child:l.child, base});
    }
  }
  function frameScene(nodes){
    const box=new THREE.Box3();
    nodes.forEach(n=>box.expandByPoint(new THREE.Vector3(n.x,n.y,n.z)));
    const center=box.getCenter(new THREE.Vector3());
    const size=box.getSize(new THREE.Vector3());
    const radius=Math.max(size.x,size.y,size.z)*0.62;
    const dist=radius/Math.tan((camera.fov*Math.PI/180)/2)*1.15;
    controls.target.copy(center);
    camera.position.set(center.x, center.y+size.y*0.12, center.z+dist);
    camera.near=dist*0.01; camera.far=dist*8+4000; camera.updateProjectionMatrix();
  }

  // ── rate computation (byte-delta) + persistent particle pool ──────────────────
  function computeRates(nodes){
    const now=performance.now()/1000;
    for(const n of nodes){
      if(n.directRate) continue;
      const p=prevBytes[n.id];
      if(p){ const dt=now-p.t; if(dt>0.5){
        n.upBps   = Math.max(0,(n.txB-p.tx)/dt);
        n.downBps = Math.max(0,(n.rxB-p.rx)/dt);
      }}
      prevBytes[n.id]={tx:n.txB, rx:n.rxB, t:now};
    }
  }
  function buildParticlePool(links){
    linkRefs=[];
    for(const l of links){ const a=byId[l.parent], b=byId[l.child]; if(!a||!b) continue;
      linkRefs.push({ax:a.x,ay:a.y,az:a.z,bx:b.x,by:b.y,bz:b.z,child:l.child,net:l.net}); }
    const parts=[];
    linkRefs.forEach((lr,li)=>{
      for(let s=0;s<SLOTS;s++) parts.push({link:li,dir:1,slot:s,t:Math.random()});
      for(let s=0;s<SLOTS;s++) parts.push({link:li,dir:0,slot:s,t:Math.random()});
    });
    const total=parts.length;
    if(pool){ scene.remove(pool.points); pool.points.geometry.dispose(); pool.points.material.dispose(); pool=null; }
    if(!total) return;
    const pos=new Float32Array(total*3), col=new Float32Array(total*3), sz=new Float32Array(total);
    for(let i=0;i<total;i++){ const c=parts[i].dir?UP_COL:DOWN_COL; col[i*3]=c.r;col[i*3+1]=c.g;col[i*3+2]=c.b; pos[i*3]=pos[i*3+1]=pos[i*3+2]=1e7; sz[i]=0; }
    const g=new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos,3));
    g.setAttribute('color', new THREE.BufferAttribute(col,3));
    g.setAttribute('size', new THREE.BufferAttribute(sz,1));
    const mat=new THREE.ShaderMaterial({
      uniforms:{ map:{value:makeDot()} },
      vertexShader:`
        attribute float size; attribute vec3 color; varying vec3 vColor;
        void main(){ vColor=color; vec4 mv=modelViewMatrix*vec4(position,1.0);
          gl_PointSize = size * (700.0 / -mv.z); gl_Position=projectionMatrix*mv; }`,
      fragmentShader:`
        uniform sampler2D map; varying vec3 vColor;
        void main(){ vec4 t=texture2D(map, gl_PointCoord); if(t.a<0.05) discard;
          gl_FragColor=vec4(vColor,1.0)*t; }`,
      transparent:true, blending:THREE.AdditiveBlending, depthWrite:false });
    pool={points:new THREE.Points(g, mat), parts};
    scene.add(pool.points);
  }
  function updateFlows(dt){
    if(!pool) return;
    const k=Math.min(1, dt*1.6);
    for(const id in byId){
      const n=byId[id]; const s=rateState[id]||(rateState[id]={up:0,down:0});
      s.up  += ((n.upBps||0)  - s.up )*k;
      s.down+= ((n.downBps||0)- s.down)*k;
    }
    const pos=pool.points.geometry.attributes.position.array;
    const szA=pool.points.geometry.attributes.size.array;
    const showAll=activeNets.has('all');
    for(let i=0;i<pool.parts.length;i++){
      const p=pool.parts[i], lr=linkRefs[p.link]; const s=rateState[lr.child]||{up:0,down:0};
      const inten=rateInten(p.dir?s.up:s.down);
      const visNet = showAll || lr.net==='infra' || activeNets.has(lr.net);
      const active = p.slot < Math.round(inten*SLOTS);
      if(!visNet || !active){ pos[i*3]=pos[i*3+1]=pos[i*3+2]=1e7; szA[i]=0; continue; }
      szA[i] = 5 + inten*24;
      p.t += (0.2+inten*0.9)*dt; if(p.t>1) p.t-=1; const t=p.t;
      if(p.dir){ pos[i*3]=lr.bx+(lr.ax-lr.bx)*t; pos[i*3+1]=lr.by+(lr.ay-lr.by)*t; pos[i*3+2]=lr.bz+(lr.az-lr.bz)*t; }
      else     { pos[i*3]=lr.ax+(lr.bx-lr.ax)*t; pos[i*3+1]=lr.ay+(lr.by-lr.ay)*t; pos[i*3+2]=lr.az+(lr.bz-lr.az)*t; }
    }
    pool.points.geometry.attributes.position.needsUpdate=true;
    pool.points.geometry.attributes.size.needsUpdate=true;
    for(const ll of linkLines){
      const s=rateState[ll.child]||{up:0,down:0};
      const inten=rateInten(Math.max(s.up,s.down));
      ll.mat.linewidth = 1.0 + inten*1.4;
      ll.mat.opacity   = 0.3 + inten*0.35;
      ll.mat.color.copy(ll.base).lerp(WHITE_HOT, inten*0.5);
    }
  }

  // ── filter pills (generic over a node "group") ───────────────────────────────
  function buildPills(nodes){
    const vals=adapter.filterValues(nodes);
    const bar=document.getElementById('netfilter'); bar.innerHTML='';
    const mk=(label,net,col)=>{ const p=document.createElement('div'); p.className='pill'+(net==='all'?' active':'');
      p.textContent=label; p.style.background=(col||'#8a97b5')+'22'; p.style.color=col||'#aab4cc'; p.style.borderColor=(col||'#8a97b5')+'55';
      p.onclick=()=>setFilter(net,p); bar.appendChild(p); return p; };
    mk('ALL','all','#aab4cc');
    vals.forEach(v=> mk(v.label, v.value, v.color));
  }
  function setFilter(net,el){
    activeNets = net==='all'?new Set(['all']):new Set([net]);
    document.querySelectorAll('.pill').forEach(p=>p.classList.remove('active'));
    el.classList.add('active');
    updateFilterVisibility();
  }
  function updateFilterVisibility(){
    const showAll=activeNets.has('all');
    const filt = adapter.isFilterable || (n=>n.nodeType==='client');
    for(const id in byId){ const n=byId[id]; if(!filt(n)) continue;
      const v=showAll||activeNets.has(n.network);
      if(meshById[id]) meshById[id].visible=v;
    }
    linkGroup.children.forEach(line=>{ const l=line.userData;
      line.visible = showAll || (l&&l.net==='infra') || (l&&activeNets.has(l.net)); });
  }

  // ── picking + tooltip ─────────────────────────────────────────────────────────
  const ray=new THREE.Raycaster(), mouse=new THREE.Vector2();
  const tip=document.getElementById('tooltip');
  function onMove(e){
    mouse.x=(e.clientX/W())*2-1; mouse.y=-(e.clientY/H())*2+1;
    ray.setFromCamera(mouse,camera);
    const hit=ray.intersectObjects(pickables.filter(m=>m.visible),false)[0];
    if(hit){ const n=hit.object.userData; tip.style.display='block'; tip.style.left=(e.clientX+14)+'px'; tip.style.top=(e.clientY+14)+'px';
      tip.innerHTML=adapter.tooltip(engine, n); document.body.style.cursor='pointer';
    } else { tip.style.display='none'; document.body.style.cursor='default'; }
  }
  function onClick(e){
    mouse.x=(e.clientX/W())*2-1; mouse.y=-(e.clientY/H())*2+1; ray.setFromCamera(mouse,camera);
    const hit=ray.intersectObjects(pickables.filter(m=>m.visible),false)[0];
    if(hit) adapter.openPanel(engine, hit.object.userData); else document.getElementById('panel').classList.remove('on');
  }
  renderer.domElement.addEventListener('mousemove',onMove);
  renderer.domElement.addEventListener('click',onClick);

  // ── animation loop ────────────────────────────────────────────────────────────
  const clock=new THREE.Clock();
  function animate(){
    requestAnimationFrame(animate);
    const dt=Math.min(clock.getDelta(),0.05);
    updateFlows(dt);
    // node behaviour: spin infra; idle glow breathes, active = steady-bright
    const breathe = 0.42 + 0.20*Math.sin(clock.elapsedTime*2.0);
    nodeGroup.children.forEach(o=>{
      const n=o.userData; if(!n||!n.nodeType) return;
      if(n.nodeType==='udm'||n.nodeType==='usw'||n.nodeType==='uap') o.rotation.y+=dt*0.4;
      if(o.material && o.material.emissiveIntensity!==undefined){
        const r=(n.upBps||0)+(n.downBps||0);
        o.material.emissiveIntensity = (r>=MIN_BPS) ? (n.nodeType==='client'?1.0:1.3) : breathe;
      }
    });
    labelGroup.children.forEach(l=>l.quaternion.copy(camera.quaternion));
    adapter.onFrame?.(engine, dt, clock);     // world per-frame overlays (exfil, rings, cam planes)
    if(fly){
      fly.t += dt/fly.dur; const e=easeIO(Math.min(1,fly.t));
      const p=new THREE.Vector3().lerpVectors(fly.sp, fly.ep, e).addScaledVector(fly.perp, Math.sin(e*Math.PI));
      camera.position.copy(p);
      const look=new THREE.Vector3().lerpVectors(fly.st, fly.et, e);
      camera.lookAt(look);
      if(fly.t>=1){ controls.target.copy(fly.et); fly=null; controls.autoRotate=true; controls.autoRotateSpeed=0.28; controls.update(); }
    } else { controls.update(); }
    composer.render();
  }
  addEventListener('resize',()=>{ camera.aspect=W()/H(); camera.updateProjectionMatrix(); renderer.setSize(W(),H()); composer.setSize(W(),H()); linkLines.forEach(ll=>ll.mat.resolution.set(W(),H())); });

  // ── data loop (SSE → polling fallback) ────────────────────────────────────────
  function applyUpdate(graph){ buildScene(graph); adapter.onData(engine, graph); }
  async function fetchGraph(){ const r=await fetch(adapter.endpoints.snapshot); const { data={} } = await r.json(); return adapter.buildGraph(data); }
  function startStream(){
    if(!adapter.endpoints.stream){ return startPolling(); }   // no SSE → poll on refreshS
    let es;
    try{ es=new EventSource(adapter.endpoints.stream); }
    catch(e){ return startPolling(); }
    es.addEventListener(adapter.endpoints.streamEvent||'topology', ev=>{
      try{ applyUpdate(adapter.buildGraph(JSON.parse(ev.data))); window.__stream='sse'; }
      catch(err){ console.warn('stream parse failed', err); }
    });
    es.onerror=()=>{ es.close(); console.warn('SSE dropped — falling back to polling'); window.__stream='poll'; startPolling(); };
  }
  function startPolling(){
    setInterval(async()=>{ try{ applyUpdate(await fetchGraph()); }catch(e){ console.warn('poll failed',e); } }, (adapter.refreshS||10)*1000);
  }

  // ── the engine handle exposed to the world adapter ────────────────────────────
  const engine = {
    THREE, scene, camera, renderer, controls, composer,
    groups:{ node:nodeGroup, link:linkGroup, label:labelGroup, cam:camGroup, alert:alertGroup },
    GEO, MIN_BPS, UP_COL, DOWN_COL,
    // live state accessors
    get byId(){ return byId; }, get pickables(){ return pickables; },
    get pool(){ return pool; }, get linkLines(){ return linkLines; },
    get rateState(){ return rateState; }, get activeNets(){ return activeNets; },
    // helpers
    makeDot, makeLabel, clearGroup, rateInten, fmtB, fmtUp,
    flyToPoint, flyToNode, flyToOverview,
    buildPills, updateFilterVisibility, applyUpdate,
    async boot(){
      try{
        const data=await fetchGraph();
        buildScene(data);
        adapter.onBoot(engine, data);     // pills, stats, POI, overlay loops, etc.
        animate();
        const ld=document.getElementById('loading'); ld.classList.add('gone'); setTimeout(()=>ld.style.display='none',650);
        document.getElementById('cd').textContent='streaming';
        document.getElementById('refresh').style.width='100%';
        window.__ready=true;
        startStream();
      }catch(e){
        const lm=document.getElementById('lmsg'); if(lm){ lm.textContent='Error: '+e.message; lm.style.color='#ff5a5a'; }
        console.error(e); window.__error=e.message;
      }
    },
  };
  return engine;
}
