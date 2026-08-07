// ─────────────────────────────────────────────────────────────────────────────
// World adapter: UniFi network topology.
//
// Everything UniFi-specific lives here — how to fetch the topology, map it to the
// engine's {nodes,links} schema, color/label nodes, and the security overlays
// (conntrack external flows, IPS alerts, suspicious rings, exfil packets, the POI
// dock, camera feed planes). The engine (engine.js) knows none of this; swap this
// file for another adapter and the same renderer draws a different "world".
// ─────────────────────────────────────────────────────────────────────────────
import { createEngine, THREE, fmtB, fmtUp } from './engine.js';

const NET_COLOR = { IoT:'#ff8c2b', Media:'#36c5ff', Zone00:'#9aa6bd', wan:'#5a6b85' };
const DEV_COLOR = { udm:'#ffd700', usw:'#00bfff', uap:'#00e87f', wan:'#5a6b85', camera:'#ff5ed0' };
const netColor = n => NET_COLOR[n] || '#c46bff';
const devColor = t => DEV_COLOR[t] || '#8696b3';

// Common, expected outbound ports (web, DNS, NTP, push, STUN, MQTT). An IoT device
// reaching the internet on one of these is normal; anything else is the red signal.
const COMMON_PORTS = new Set(['443','80','53','123','5228','5223','3478','993','465','587','8883','1883','8443']);

// ── network-world state ───────────────────────────────────────────────────────
let engine;                                   // set after createEngine
let flowsByIp = {};                           // ip -> [{dst,dport,proto,bytes}]
let ipsByKey  = {};                           // mac/ip -> [IDS alert events]
let alertRings= [];                           // {mesh, id, ips?} pulsed each frame
let exfilPool=null, exfilParts=[], exfilPaths=[];
const EXFIL_COL = new THREE.Color(0xff0a1e);  // bright red — threats only
let autoFly=true, flyArmed=false, seenThreats=new Set();
let camPlanes=[], camRev=0;                    // floating camera-feed planes (optional)
const texLoader = new THREE.TextureLoader();

// ── data → graph ──────────────────────────────────────────────────────────────
function buildGraph(data){
  const devices = data.devices || [];
  const clients = Array.isArray(data.clients) ? data.clients : [];
  const deviceMacs = new Set(devices.map(d => d.mac));

  const nodes = [{ id:'wan', label:'Internet / WAN', nodeType:'wan', parent:null, sz:7, desc:'Your ISP uplink' }];

  for (const d of devices) {
    const st = d['system-stats'] || {};
    const up = d.uplink?.uplink_mac;
    const parent = (up && deviceMacs.has(up)) ? up : 'wan';
    nodes.push({
      id:d.mac, label:d.name || d.mac, nodeType:d.type, parent,
      mac:d.mac, model:d.model, firmware:d.version, num_sta:d.num_sta||0,
      uptime:d.uptime||0, state:d.state,
      cpu:parseFloat((st.cpu||'0').toString().trim()), mem:parseFloat((st.mem||'0').toString().trim()),
      txB:(d.tx_bytes||0), rxB:(d.rx_bytes||0),
      upBps:(d.up_bps||0), downBps:(d.down_bps||0), directRate:(d.up_bps!=null||d.down_bps!=null),
      sz: d.type==='udm'?13:d.type==='usw'?8:7,
    });
  }
  for (const c of clients) {
    let parent = c.ap_mac || c.uplink_mac;
    if (!parent || !deviceMacs.has(parent)) parent = 'wan';
    nodes.push({
      id:c.mac, label:c.display_name||c.hostname||c.mac, nodeType:'client', parent,
      mac:c.mac, ip:c.ip||'—', network:c.network_name||'—', model:c.model_name||'—',
      wired:c.is_wired, signal:c.signal||0, rssi:c.rssi||0, wifi_score:c.wifi_experience_score||0,
      txB:(c.tx_bytes||0), rxB:(c.rx_bytes||0),
      upBps:(c.up_bps||0), downBps:(c.down_bps||0), directRate:(c.up_bps!=null||c.down_bps!=null),
      uplink_name:c.last_uplink_name||'—',
      sz:2.4,
    });
  }
  const cameras = Array.isArray(data.cameras) ? data.cameras : [];
  for (const cam of cameras) {
    const parent = (cam.uplink_mac && deviceMacs.has(cam.uplink_mac)) ? cam.uplink_mac : 'wan';
    nodes.push({
      id:cam.mac, label:cam.name||cam.mac, nodeType:'camera', parent,
      mac:cam.mac, camId:cam.id, network:'Cameras', model:'UniFi Protect', wired:cam.is_wired,
      upBps:(cam.up_bps||0), downBps:(cam.down_bps||0), directRate:true,
      sz:3.4,
    });
  }
  const ids = new Set(nodes.map(n=>n.id));
  const links = [];
  for (const n of nodes) if (n.parent && ids.has(n.parent))
    links.push({ child:n.id, parent:n.parent, net: n.nodeType==='client'?n.network:'infra' });

  return { nodes, links, deviceCount:devices.length, clientCount:clients.length };
}

// ── node/link styling ─────────────────────────────────────────────────────────
function styleNode(n){
  const col = new THREE.Color(n.nodeType==='client' ? netColor(n.network) : devColor(n.nodeType));
  return { color:col, geoKey:n.nodeType, emissive: n.nodeType==='client'?0.65:1.1,
           halo: n.nodeType!=='client', label: n.nodeType!=='client' };
}
function linkColor(l){
  return l.net==='infra' ? new THREE.Color(0x2a6a8c) : new THREE.Color(netColor(l.net)).multiplyScalar(0.5);
}
function filterValues(nodes){
  const nets=new Set(); nodes.forEach(n=>{ if(n.nodeType==='client'&&n.network) nets.add(n.network); });
  return [...nets].sort().map(net=>({ label:net, value:net, color:netColor(net) }));
}

// ── tooltip + panel ───────────────────────────────────────────────────────────
function tooltip(eng, n){
  const act=((n.downBps||0)>=eng.MIN_BPS||(n.upBps||0)>=eng.MIN_BPS)
    ? ` · <span style="color:#36c5ff">↓${fmtB(n.downBps||0)}/s</span> <span style="color:#ff6a3d">↑${fmtB(n.upBps||0)}/s</span>` : '';
  return `<b style="color:${n.nodeType==='client'?netColor(n.network):devColor(n.nodeType)}">${n.label}</b>` +
    (n.nodeType==='client'?` · ${n.network} · ${n.wired?'wired':n.signal+' dBm'}`:` · ${n.model||n.nodeType}`) + act;
}
function openPanel(eng, n){
  const MIN=eng.MIN_BPS;
  document.getElementById('pname').textContent=n.label;
  document.getElementById('pmodel').textContent=[n.model,n.nodeType?.toUpperCase()].filter(Boolean).join(' · ');
  const rows=[];
  let preHTML='';
  const ids=ipsForNode(n);
  if(ids.length){
    const sevTxt=s=>s===1?'CRITICAL':s===2?'major':'minor';
    preHTML += `<div style="background:rgba(255,0,51,.14);border:1px solid #ff0033;border-radius:7px;padding:8px 10px;margin-bottom:10px">
      <div style="color:#ff5a5a;font-weight:bold;letter-spacing:1px;font-size:11px">🛡 IDS ALERT · ${ids.length}</div>`
      + ids.slice(0,4).map(e=>`<div style="color:#ffb3c0;font-size:11px;margin-top:5px">
          [${sevTxt(e.severity)}] ${(e.signature||e.category||'alert')}<br>
          <span style="color:#88708a;font-size:10px">${e.kind} · ${e.src_ip||''}${e.dst_ip?(' → '+e.dst_ip):''} · ${e.action||''}</span></div>`).join('')
      + `</div>`;
  }
  if(n.nodeType==='camera'){
    preHTML=`<img src="${location.origin}/api/cameras/${n.camId}/snapshot?r=${camRev}" style="width:100%;border-radius:7px;border:1px solid #ff5ed0;margin-bottom:10px" onerror="this.style.display='none'">`;
    rows.push(['MAC',n.mac]);
    rows.push(['Link', n.wired?'Wired (PoE)':'Wireless']);
    rows.push(['↑ Video upload', fmtB(n.upBps||0)+'/s', (n.upBps||0)>=MIN?'warn':'']);
    rows.push(['↓ Download', fmtB(n.downBps||0)+'/s', (n.downBps||0)>=MIN?'good':'']);
  } else if(n.nodeType!=='client'){
    rows.push(['MAC',n.mac]);
    rows.push(['CPU',n.cpu!=null?n.cpu.toFixed(0)+'%':'—', n.cpu<50?'good':n.cpu<80?'warn':'bad']);
    rows.push(['RAM',n.mem!=null?n.mem.toFixed(0)+'%':'—', n.mem<60?'good':n.mem<80?'warn':'bad']);
    rows.push(['Uptime',fmtUp(n.uptime)]);
    rows.push(['Clients',n.num_sta??'—']);
    rows.push(['↓ Download', fmtB(n.downBps||0)+'/s', (n.downBps||0)>=MIN?'good':'']);
    rows.push(['↑ Upload',   fmtB(n.upBps||0)+'/s',   (n.upBps||0)>=MIN?'warn':'']);
    if(n.firmware) rows.push(['Firmware',n.firmware]);
  } else {
    rows.push(['IP',n.ip]); rows.push(['Network',n.network]); rows.push(['Model',n.model]); rows.push(['Uplink',n.uplink_name]);
    if(n.wired) rows.push(['Link','Wired']);
    else { rows.push(['Signal',n.signal+' dBm', n.rssi>=45?'good':n.rssi>=30?'warn':'bad']);
           rows.push(['Wi-Fi score',n.wifi_score+'%', n.wifi_score>=80?'good':n.wifi_score>=50?'warn':'bad']); }
    const ap = n.wired ? '' : ' ≈';
    rows.push(['↓ Download'+ap, fmtB(n.downBps||0)+'/s', (n.downBps||0)>=MIN?'good':'']);
    rows.push(['↑ Upload'+ap,   fmtB(n.upBps||0)+'/s',   (n.upBps||0)>=MIN?'warn':'']);
    if(!n.wired) rows.push(['(rate)','≈ approx — UniFi samples Wi-Fi clients slowly']);
  }
  const fl = n.ip ? (flowsByIp[n.ip]||[]) : [];
  if(fl.length){
    const susp=isSuspicious(n);
    rows.push([susp?'⚠ EXTERNAL':'EXTERNAL', susp?'IoT reaching internet':fl.length+' connection(s)', susp?'bad':'warn']);
    fl.slice().sort((a,b)=>b.bytes-a.bytes).slice(0,6).forEach(f=>
      rows.push([f.dst+':'+f.dport, fmtB(f.bytes)+' '+f.proto, susp?'bad':'']));
  }
  document.getElementById('prows').innerHTML=preHTML+rows.map(([k,v,c])=>`<div class="prow"><span class="pk">${k}</span><span class="pv ${c||''}">${v}</span></div>`).join('');
  document.getElementById('panel').classList.add('on');
}

// ── HUD stats + debug export ──────────────────────────────────────────────────
function applyStats(eng, data){
  const MIN=eng.MIN_BPS, pool=eng.pool;
  document.getElementById('s-dev').textContent=data.deviceCount;
  document.getElementById('s-cli').textContent=data.clientCount;
  const thru=data.nodes.filter(n=>n.nodeType==='client').reduce((s,n)=>s+(n.upBps||0)+(n.downBps||0),0);
  document.getElementById('s-thru').innerHTML=`<b>throughput</b> ${fmtB(thru)}/s`;
  document.getElementById('s-ts').textContent=new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:true});
  const act=t=>data.nodes.filter(n=>n.nodeType===t && ((n.upBps||0)>=MIN||(n.downBps||0)>=MIN)).length;
  window.__flow={ activeNodes: data.nodes.filter(n=>(n.upBps||0)>=MIN||(n.downBps||0)>=MIN).length,
                  particles: pool?pool.parts.length:0, thruBps: Math.round(thru),
                  cameras: data.nodes.filter(n=>n.nodeType==='camera').length,
                  activeByType:{ camera:act('camera'), usw:act('usw'), uap:act('uap'), udm:act('udm'), client:act('client') },
                  visibleParticles: (function(){ if(!pool)return 0; const a=pool.points.geometry.attributes.position.array; let c=0; for(let i=0;i<pool.parts.length;i++) if(a[i*3]<1e6) c++; return c; })() };
}

// ── security overlays: external flows (conntrack) + IPS alerts ─────────────────
async function loadFlows(){
  try{
    const r=await fetch(location.origin+'/api/flows'); const j=await r.json();
    if(!j.success) return;
    const m={}; for(const f of (j.data.flows||[])){ (m[f.src]=m[f.src]||[]).push(f); }
    flowsByIp=m; updateAlerts();
  }catch(e){ console.warn('flows load failed', e); }
}
async function loadIPS(){
  try{
    const r=await fetch(location.origin+'/api/security/events'); const j=await r.json();
    if(!j.success) return;
    const k={};
    for(const e of (j.data.events||[])){
      if(e.kind!=='ips' && e.kind!=='honeypot') continue;
      if(e.client_mac) (k[e.client_mac.toLowerCase()]=k[e.client_mac.toLowerCase()]||[]).push(e);
      if(e.src_ip)     (k[e.src_ip]=k[e.src_ip]||[]).push(e);
    }
    ipsByKey=k; updateAlerts();
  }catch(e){ console.warn('ips load failed', e); }
}
function ipsForNode(n){
  if(!n) return [];
  return (n.mac && ipsByKey[String(n.mac).toLowerCase()]) || (n.ip && ipsByKey[n.ip]) || [];
}
function isSuspicious(n){
  if(!(n && n.nodeType==='client' && n.ip && n.network==='IoT')) return false;
  return (flowsByIp[n.ip]||[]).some(f => !COMMON_PORTS.has(String(f.dport)));
}
function updateAlerts(){
  const byId=engine.byId, alertGroup=engine.groups.alert;
  for(const a of alertRings){ alertGroup.remove(a.mesh); a.mesh.geometry.dispose(); a.mesh.material.dispose(); }
  alertRings=[];
  let susp=0, ext=0, ids=0; const idsIds=[], flaggedIds=[];
  for(const id in byId){
    const n=byId[id];
    if(n.nodeType==='client' && n.ip && (flowsByIp[n.ip]||[]).length) ext++;
    if(ipsForNode(n).length){
      ids++; idsIds.push(id); flaggedIds.push(id);
      for(const rmul of [2.6, 3.4]){
        const ring=new THREE.Mesh(
          new THREE.TorusGeometry(n.sz*rmul, n.sz*0.30, 8, 28),
          new THREE.MeshBasicMaterial({color:0xff0033, transparent:true, opacity:1, blending:THREE.AdditiveBlending, depthWrite:false}));
        ring.position.set(n.x,n.y,n.z);
        alertGroup.add(ring); alertRings.push({mesh:ring,id,ips:true});
      }
    } else if(isSuspicious(n)){
      susp++; flaggedIds.push(id);
      const ring=new THREE.Mesh(
        new THREE.TorusGeometry(n.sz*2.6, n.sz*0.34, 8, 24),
        new THREE.MeshBasicMaterial({color:0xff2a2a, transparent:true, opacity:0.9, blending:THREE.AdditiveBlending, depthWrite:false}));
      ring.position.set(n.x,n.y,n.z);
      alertGroup.add(ring); alertRings.push({mesh:ring,id,ips:false});
    }
  }
  const el=document.getElementById('s-alert');
  if(el){
    const parts=[];
    if(ids>0)  parts.push(`<span style="color:#ff0033;font-weight:bold">🛡 ${ids} IDS alert${ids>1?'s':''}</span>`);
    if(susp>0) parts.push(`<span style="color:#ff5a5a">⚠ ${susp} IoT→external</span>`);
    if(!parts.length && ext>0) parts.push(`<span style="color:#7d8db0">${ext} devices → internet</span>`);
    el.innerHTML = parts.join('<br>');
  }
  window.__alerts={suspicious:susp, externalTalkers:ext, idsAlerts:ids};
  for(const id of idsIds){
    if(seenThreats.has(id)) continue;
    seenThreats.add(id);
    if(autoFly && flyArmed){ engine.flyToNode(id,7); break; }
  }
  buildPOI(idsIds);
  buildExfil(flaggedIds);
}

// ── exfil packets: a flagged device's traffic routes up the real path, then off ──
function pathToInternet(id){
  const byId=engine.byId;
  const pts=[]; let cur=id, guard=0;
  while(cur && byId[cur] && guard++<12){ const n=byId[cur]; pts.push(new THREE.Vector3(n.x,n.y,n.z)); if(cur==='wan') break; cur=n.parent; }
  const wan=byId['wan'];
  pts.push(new THREE.Vector3(wan?wan.x:0, (wan?wan.y:240)+170, wan?wan.z:0));
  return pts;
}
function buildExfil(flaggedIds){
  const scene=engine.scene, byId=engine.byId;
  if(exfilPool){ scene.remove(exfilPool); exfilPool.geometry.dispose(); exfilPool.material.dispose(); exfilPool=null; }
  exfilParts=[]; exfilPaths=[];
  if(!flaggedIds||!flaggedIds.length) return;
  for(const id of flaggedIds){
    const path=pathToInternet(id); if(path.length<2) continue;
    const pi=exfilPaths.length; exfilPaths.push(path);
    const rate=(byId[id]&&byId[id].upBps)||0;
    const count=Math.max(2, Math.round(engine.rateInten(rate)*12));
    for(let i=0;i<count;i++) exfilParts.push({pi, t:i/count*(path.length-1), speed:0.9+Math.random()*0.4});
  }
  const total=exfilParts.length; if(!total) return;
  const pos=new Float32Array(total*3); for(let i=0;i<total*3;i++) pos[i]=1e7;
  const g=new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(pos,3));
  exfilPool=new THREE.Points(g, new THREE.PointsMaterial({ size:17, sizeAttenuation:true, color:EXFIL_COL,
    map:engine.makeDot(), transparent:true, opacity:0.95, blending:THREE.AdditiveBlending, depthWrite:false }));
  scene.add(exfilPool);
}
function updateExfil(dt){
  if(!exfilPool) return;
  const pos=exfilPool.geometry.attributes.position.array;
  for(let i=0;i<exfilParts.length;i++){
    const p=exfilParts[i], path=exfilPaths[p.pi]; const seg=path.length-1;
    p.t += p.speed*dt; if(p.t>=seg) p.t-=seg;
    const k=Math.floor(p.t), f=p.t-k, a=path[k], b=path[Math.min(k+1,seg)];
    pos[i*3]=a.x+(b.x-a.x)*f; pos[i*3+1]=a.y+(b.y-a.y)*f; pos[i*3+2]=a.z+(b.z-a.z)*f;
  }
  exfilPool.geometry.attributes.position.needsUpdate=true;
}

// ── points-of-interest dock ───────────────────────────────────────────────────
function buildPOI(idsIds){
  const byId=engine.byId;
  const bar=document.getElementById('poi'); if(!bar) return;
  let udm=null, srvRack=null; const cams=[];
  for(const id in byId){ const n=byId[id];
    if(n.nodeType==='udm') udm=id;
    if(n.nodeType==='usw' && /server\s*rack/i.test(n.label||'')) srvRack=id;
    if(n.nodeType==='camera') cams.push(n);
  }
  const pills=[['🌐 Overview', ()=>engine.flyToOverview()]];
  if(udm) pills.push(['📡 Router', ()=>engine.flyToNode(udm,7)]);
  if(srvRack) pills.push(['🗄 Core Switch', ()=>engine.flyToNode(srvRack,8)]);
  if(cams.length) pills.push(['📷 Cameras', ()=>{ const c=new THREE.Vector3(); cams.forEach(n=>c.add(new THREE.Vector3(n.x,n.y,n.z))); c.multiplyScalar(1/cams.length); engine.flyToPoint(c,130); }]);
  bar.innerHTML='';
  for(const [label,fn] of pills){ const el=document.createElement('div'); el.className='poi'; el.textContent=label; el.onclick=fn; bar.appendChild(el); }
  let threatId = (idsIds&&idsIds[0]) || null, threatIps=!!threatId;
  if(!threatId) for(const id in byId){ if(isSuspicious(byId[id])){ threatId=id; break; } }
  if(threatId){ const el=document.createElement('div'); el.className='poi threat'; el.textContent=(threatIps?'🛡 ':'⚠ ')+'Threat'; el.onclick=()=>engine.flyToNode(threatId,7); bar.appendChild(el); }
  const tog=document.createElement('div'); tog.className='poi toggle'+(autoFly?' on':''); tog.textContent='🎯 Auto-fly';
  tog.onclick=()=>{ autoFly=!autoFly; tog.classList.toggle('on',autoFly); }; bar.appendChild(tog);
}

// ── camera feed planes (optional overlay; not enabled by default) ──────────────
async function loadCameras(){
  try{
    const r = await fetch(location.origin + '/api/cameras');
    const wrap = await r.json();
    const data = wrap.data || wrap;
    const cams = Array.isArray(data) ? data : (data.cameras || []);
    return cams.filter(c => (c.state||'').toUpperCase() === 'CONNECTED');
  }catch(e){ console.warn('cameras load failed', e); return []; }
}
function snapURL(id){ return `${location.origin}/api/cameras/${id}/snapshot?r=${camRev}`; }
function buildCameraPlanes(cams){
  const camGroup=engine.groups.cam;
  for(const c of camPlanes){ camGroup.remove(c.mesh); camGroup.remove(c.label); c.mesh.material.map?.dispose?.(); c.mesh.material.dispose(); c.mesh.geometry.dispose(); }
  camPlanes = [];
  if(!cams.length) return;
  const PW=70, PH=39, R=300, Y=315;
  const arc=Math.min(Math.PI*1.5, cams.length*0.5), a0=-arc/2;
  cams.forEach((cam,i)=>{
    const ang = cams.length>1 ? a0 + arc*(i/(cams.length-1)) : 0;
    const x=R*Math.sin(ang), z=R*Math.cos(ang);
    const tex=texLoader.load(snapURL(cam.id)); tex.colorSpace=THREE.SRGBColorSpace;
    const mesh=new THREE.Mesh(new THREE.PlaneGeometry(PW,PH), new THREE.MeshBasicMaterial({map:tex, toneMapped:false, side:THREE.DoubleSide}));
    mesh.position.set(x,Y,z);
    const edges=new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.PlaneGeometry(PW,PH)), new THREE.LineBasicMaterial({color:0x00e87f}));
    edges.position.copy(mesh.position); mesh.userData={cam};
    camGroup.add(mesh); camGroup.add(edges);
    const lab=engine.makeLabel('📹 '+(cam.name||cam.id), '#00e87f'); lab.position.set(x, Y+PH*0.62, z); camGroup.add(lab);
    camPlanes.push({mesh, label:lab, edges, id:cam.id});
  });
}
function refreshCameraTextures(){
  camRev++;
  for(const c of camPlanes){
    const tex=texLoader.load(snapURL(c.id)); tex.colorSpace=THREE.SRGBColorSpace;
    const old=c.mesh.material.map; c.mesh.material.map=tex; c.mesh.material.needsUpdate=true; old?.dispose?.();
  }
}

// ── the adapter + boot ────────────────────────────────────────────────────────
const adapter = {
  endpoints:{ snapshot: location.origin+'/api/topology', stream: location.origin+'/api/topology/stream', streamEvent:'topology' },
  refreshS: 10,
  buildGraph, styleNode, linkColor, filterValues, tooltip, openPanel,
  onData(eng, graph){ applyStats(eng, graph); updateAlerts(); },
  onFrame(eng, dt, clock){
    updateExfil(dt);
    for(const c of camPlanes){ c.mesh.quaternion.copy(eng.camera.quaternion); c.edges.quaternion.copy(eng.camera.quaternion); c.label.quaternion.copy(eng.camera.quaternion); }
    const tnow=clock.elapsedTime;
    for(const a of alertRings){
      const sp = a.ips ? 9 : 5;
      a.mesh.material.opacity = (a.ips?0.6:0.55) + 0.4*Math.sin(tnow*sp);
      a.mesh.scale.setScalar(0.9 + (a.ips?0.28:0.18)*Math.sin(tnow*sp));
      a.mesh.quaternion.copy(eng.camera.quaternion);
    }
  },
  onBoot(eng, graph){
    eng.buildPills(graph.nodes);
    applyStats(eng, graph);
    buildPOI();
    loadFlows();  setInterval(loadFlows, 15000);
    loadIPS();    setInterval(loadIPS, 12000);
    setTimeout(()=>{ flyArmed=true; }, 8000);
  },
};

engine = createEngine(adapter);
engine.boot();
