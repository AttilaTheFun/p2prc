(function(){
  const who = new URLSearchParams(location.search).get("who") || "a";
  const send=(m)=>{try{navigator.sendBeacon('/log', JSON.stringify({who, t:Date.now(), m:String(m).slice(0,3000)}));}catch(e){}};
  window.addEventListener('error',e=>send('error: '+(e.message||e)));
  // ?relay=1: every peer connection relayed through TURN only (no host or
  // STUN path), and each connected one's chosen candidate pair logged as
  // "ice <state> <local type>/<remote type> <protocol>", so a run proves the
  // nodes' TURN carries the link.
  if (new URLSearchParams(location.search).get("relay") === "1" && window.RTCPeerConnection) {
    const Native = window.RTCPeerConnection;
    window.RTCPeerConnection = function(config, ...rest) {
      const pc = new Native({...(config||{}), iceTransportPolicy: 'relay'}, ...rest);
      const report = async () => {
        try {
          const stats = await pc.getStats(); let pair = null;
          stats.forEach(r => { if (r.type === 'transport' && r.selectedCandidatePairId) pair = stats.get(r.selectedCandidatePairId); });
          if (!pair) stats.forEach(r => { if (r.type === 'candidate-pair' && r.state === 'succeeded' && (r.nominated || r.selected)) pair = r; });
          const local = pair && stats.get(pair.localCandidateId), remote = pair && stats.get(pair.remoteCandidateId);
          send('ice ' + pc.connectionState + ' ' + (local ? local.candidateType : '?') + '/' + (remote ? remote.candidateType : '?') + ' ' + (local ? (local.relayProtocol || local.protocol) : '?'));
        } catch (e) { send('ice stats failed: ' + e); }
      };
      pc.addEventListener('connectionstatechange', () => { if (pc.connectionState === 'connected') setTimeout(report, 500); else send('ice ' + pc.connectionState); });
      return pc;
    };
    window.RTCPeerConnection.prototype = Native.prototype;
    for (const k of Object.getOwnPropertyNames(Native)) { try { if (!(k in window.RTCPeerConnection)) window.RTCPeerConnection[k] = Native[k]; } catch (e) {} }
  }
  for (const level of ['log','warn','error']) { const orig=console[level].bind(console); console[level]=(...a)=>{ orig(...a); try{ const t=a.map(x=>typeof x==='string'?x:(x&&x.stack)?String(x.stack):JSON.stringify(x)).join(' '); if(/convo\]|error|fail|wasm|Fatal/i.test(t)) send('console '+t.slice(0,800)); }catch(e){} }; }
  const deepest=(t)=>{let els=[...document.querySelectorAll('body *')].filter(e=>(e.textContent||'').trim()===t); return els[els.length-1];};
  const press=(el)=>{const r=el.getBoundingClientRect(); const o={bubbles:true,cancelable:true,clientX:r.left+r.width/2,clientY:r.top+r.height/2,pointerId:1,isPrimary:true,button:0,buttons:1};
    for(const t of ['pointerdown','mousedown']) el.dispatchEvent(new (t.startsWith('pointer')?PointerEvent:MouseEvent)(t,o));
    o.buttons=0; for(const t of ['pointerup','mouseup','click']) el.dispatchEvent(new (t.startsWith('pointer')?PointerEvent:MouseEvent)(t,o));};
  const tapText=(t)=>{const el=deepest(t); if(!el) return false; const tap=el.closest('[data-tap]'); if(tap) press(tap); else {let a=el; for(let i=0;i<4&&a;i++){press(a); a=a.parentElement;}} return true;};
  const tapAria=(l)=>{const b=document.querySelector('[aria-label="'+l+'"]'); if(!b) return false; const tap=b.closest('[data-tap]')||b; press(tap); return true;};
  const _f=window.fetch.bind(window); window.fetch=async(i,init)=>{ let r; try{ r=await _f(i,init); }catch(e){ const u=typeof i==='string'?i:i.url; send('net-error '+((init&&init.method)||'GET')+' '+String(u).slice(0,90)+' '+e); throw e; } try{ const u=typeof i==='string'?i:i.url; if(u.includes('/rendezvous/')||u.includes('/keypackages/')){ const b=await r.clone().text(); send('net '+((init&&init.method)||'GET')+' '+u.replace(/https:\/\/convo-node-(\d)[^/]*/,'n$1').slice(0,70)+' '+r.status+' '+b.length); } }catch(e){} return r; };
  window.__do=(cmd)=>{
    if(cmd.startsWith('text:')) return tapText(cmd.slice(5));
    if(cmd.startsWith('aria:')) return tapAria(cmd.slice(5));
    if(cmd.startsWith('type:')){ const ta=document.querySelector('textarea'); if(!ta) return false; ta.focus(); Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(ta, cmd.slice(5)); ta.dispatchEvent(new Event('input',{bubbles:true})); return true; }
    if(cmd==='send'){ if(tapAria('Send')) return true; const ta=document.querySelector('textarea'); if(!ta) return false; const tr=ta.getBoundingClientRect(); const b=[...document.querySelectorAll('[data-tap]')].filter(e=>{ if(e.getAttribute('aria-label')||(e.textContent||'').trim()||!e.querySelector('svg')) return false; const r=e.getBoundingClientRect(); return r.x>tr.x && Math.abs((r.y+r.height/2)-(tr.y+tr.height/2))<40; }); if(!b.length) return false; press(b[0]); return true; }
    if(cmd==='row'){ if(document.querySelector('textarea')) return true; const taps=[...document.querySelectorAll('[data-tap]')].filter(e=>/peer-[0-9a-f]{4}/.test(e.textContent||'')); if(taps.length){press(taps[taps.length-1]); return true;} return false; }
    if(cmd.startsWith('js:')){ try{ send('js '+String(eval(cmd.slice(3)))); }catch(e){ send('js error '+e); } return true; }
    if(cmd==='toggled'){ const s=document.querySelector('input[type=checkbox],[role=switch]'); send('toggled '+(s?(s.checked||s.getAttribute('aria-checked')==='true'):'none')); return true; }
    if(cmd==='toggle'){ const s=document.querySelector('input[type=checkbox],[role=switch]'); if(!s) return false; press(s.closest('[data-tap]')||s); return true; }
    if(cmd==='hash'){ send('hash '+location.hash); return true; }
    if(cmd==='dump'){ send('dump '+[...document.querySelectorAll('[aria-label],[data-tap]')].map(e=>(e.getAttribute('aria-label')||'')+':'+(e.textContent||'').trim().slice(0,30)).join(' | ')); return true; }
    return false;
  };
  setInterval(async()=>{ try{ const r=await fetch('/cmd?who='+who); const c=(await r.text()).trim(); if(c) send('cmd '+c+' -> '+window.__do(c)); }catch(e){} },1000);
  setInterval(()=>send('text: '+(document.body.innerText||'').replace(/\s+/g,' ').slice(0,300)),4000);
})();
