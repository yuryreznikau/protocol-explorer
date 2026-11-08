const {chromium}=require('playwright');
(async()=>{
 const b=await chromium.launch(); const p=await b.newPage();
 const errs=[]; p.on('pageerror',e=>errs.push(String(e))); p.on('console',m=>{if(m.type()==='error')errs.push(m.text())});
 await p.goto('http://localhost:8765/'); await p.waitForTimeout(2500);
 const res=await p.evaluate(()=>{
  const {cs,Cr,Xt}=window.__dbg; const out=new Set(); const errors=[];
  const walk=(o,k)=>{ if(k==='wire')return; if(typeof o==='string'){out.add(o);return;} if(Array.isArray(o)){o.forEach(x=>walk(x));return;} if(o&&typeof o==='object') for(const [kk,v] of Object.entries(o)) { if(['id','from','to','color','type','frame','at','tone','nodes','time','src','dst','len','proto'].includes(kk)&&typeof v==='string') continue; walk(v,kk);} };
  Xt.forEach(x=>{out.add(x.full);});
  for(const [id,l] of Object.entries(cs)){ walk(l);
    try{ for(const fr of Cr(l)){ for(const f of fr.fields){out.add(f.name); out.add(f.value); if(f.note)out.add(f.note);} for(const L of fr.layers){out.add(L.name); if(L.summary)out.add(String(L.summary));} } }catch(e){errors.push(id+': '+e.stack.slice(0,400));}
  }
  return {strings:[...out].filter(s=>typeof s==='string'&&s.trim()), errors};
 });
 require('fs').writeFileSync('/tmp/pe/runtime_strings.json', JSON.stringify(res.strings,null,0));
 console.log('strings',res.strings.length,'errors',res.errors, errs.slice(0,5));
 await b.close();
})();
