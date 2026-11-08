const fs=require('fs');
const rs=require('./runtime_strings.json'); const keys=new Set(require('./allkeys.json'));
const ui=require('./uikeys.json');
const pats=[/^[\d,]+ bytes?$/,/^(Ethernet II|IPv4|UDP|TCP) · \d+ bytes$/,/^\d+ \(relative\)$/,/^\d+ \(ephemeral\)$/,/^\d+ TCP segments$/,/^TLS 1\.3 · \d+ records?$/,/^(Application Data|Handshake|Change Cipher Spec), [\d,]+ bytes?$/,/^\d+ zero bytes$/,/␍␊$/,/^[\d,]+ ms uptime$/,/^\d+ (varbinds?|records?)$/];
const seen=new Set(); const list=[];
const add=s=>{ if(seen.has(s))return; seen.add(s); list.push(s); };
// UI keys first (es dictionary order gives context)
for(const k of keys){ if(ui.includes(k)) add(k); }
for(const s of rs){
  if(pats.some(p=>p.test(s))) continue;
  if(keys.has(s)) { add(s); continue; }
  if(!/[A-Za-z][a-z]{2,}/.test(s)) continue;
  if(/^[\w.-]+\.(com|org|net|html|css|png|js)$/.test(s)) continue;
  add(s);
}
fs.writeFileSync('tolist.tsv', list.map((s,i)=>`${i}\t${JSON.stringify(s)}`).join('\n'));
console.log(list.length, list.join('').length);
