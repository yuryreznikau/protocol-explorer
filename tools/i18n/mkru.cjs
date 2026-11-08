const fs=require('fs');
const src={}; for(const l of fs.readFileSync('tolist.tsv','utf8').split('\n')){ if(!l)continue; const i=l.indexOf('\t'); src[l.slice(0,i)]=JSON.parse(l.slice(i+1)); }
const strings={}; let n=0, bad=[];
for(const f of fs.readdirSync('tr').filter(f=>f.startsWith('out_')).sort()){
  for(const l of fs.readFileSync('tr/'+f,'utf8').split('\n')){ if(!l.trim())continue; const i=l.indexOf('\t'); const id=l.slice(0,i), t=l.slice(i+1);
    if(!(id in src)){bad.push(id);continue;}
    // backslash handling: in out files I wrote \\Seen meaning literal \Seen
    strings[src[id]]=t.replace(/\\\\/g,'\\'); n++; }
}
Object.assign(strings, JSON.parse(fs.readFileSync("tr/extra.json","utf8")));
// extra UI keys
Object.assign(strings,{"MONITORING":"МОНИТОРИНГ","Monitoring":"Мониторинг"});
const pats=`[
  [/^([\\d,]+) bytes?$/, (m,a)=>a+" "+pl(a)],
  [/^(Ethernet II|IPv4|UDP|TCP) · (\\d+) bytes$/, (m,a,b)=>a+" · "+b+" "+pl(b)],
  [/^(Application Data|Handshake|Change Cipher Spec), ([\\d,]+) bytes?$/, (m,a,b)=>a+", "+b+" "+pl(b)],
  [/^([\\d,]+) bytes: report\\.pdf, bytes (.+)$/, (m,a,b)=>a+" "+pl(a)+": report.pdf, байты "+b],
  [/^(.+) h later$/, "через $1 ч"],
  [/^(.+) min later$/, "через $1 мин"],
  [/^(.+) s later$/, "через $1 с"],
  [/^(\\S+) \\(relative\\)$/, "$1 (относительный)"],
  [/^(\\d+) \\(ephemeral\\)$/, "$1 (временный)"],
  [/^(\\d+) TCP segments$/, (m,a)=>a+" "+pw(a,"TCP-сегмент","TCP-сегмента","TCP-сегментов")],
  [/^(\\d+) segments$/, (m,a)=>a+" "+pw(a,"сегмент","сегмента","сегментов")],
  [/^(.*), (\\d+) segments$/, (m,s,a)=>s+", "+a+" "+pw(a,"сегмент","сегмента","сегментов")],
  [/^TLS 1\\.3 · (\\d+) records? · bytes (.+) of (.+)$/, (m,a,o,r)=>"TLS 1.3 · "+a+" "+pw(a,"запись","записи","записей")+" · байты "+o+" из "+r],
  [/^TLS 1\\.3 · (\\d+) records?$/, (m,a)=>"TLS 1.3 · "+a+" "+pw(a,"запись","записи","записей")],
  [/^Ethernet padding · (\\d+) bytes?$/, (m,a)=>"Заполнение Ethernet · "+a+" "+pl(a)],
  [/^(\\d+) zero bytes, up to the 300-byte minimum$/, (m,a)=>a+" "+pw(a,"нулевой байт","нулевых байта","нулевых байт")+", до минимума в 300 байт"],
  [/^(\\d+) zero bytes$/, (m,a)=>a+" "+pw(a,"нулевой байт","нулевых байта","нулевых байт")],
  [/^(\\d+) random bytes$/, (m,a)=>a+" "+pw(a,"случайный байт","случайных байта","случайных байт")],
  [/^Seen as it leaves (.+)$/, "Видно на выходе из $1"],
  [/^Option (\\d+)$/, "Опция $1"],
  [/^Field (\\d+)$/, "Поле $1"],
  [/^Flow (\\d+)$/, "Поток $1"],
  [/^value (\\d+), echo (\\d+)$/, "значение $1, эхо $2"],
  [/^20 bytes, plus (\\d+) of options\\.$/, "20 байт плюс $1 байт опций."],
  [/^Windows starts at (\\d+)\\. Set to (\\d+) on purpose here\\.$/, "Windows начинает с $1. Здесь намеренно задано $2."],
  [/^Started at (\\d+); (\\d+) routers? on the way each took 1\\.$/, (m,a,o)=>o==="1"?"Начинался с "+a+"; маршрутизатор на пути отнял 1.":"Начинался с "+a+"; "+o+" "+pw(o,"маршрутизатор","маршрутизатора","маршрутизаторов")+" на пути отняли по 1."],
  [/^all (\\d+) bytes of it$/, (m,a)=>"все его "+a+" "+pl(a)],
  [/^Port (\\d+), TLS from the start$/, "Порт $1, TLS с самого начала"],
  [/^(\\d+), TLS from the start$/, "$1, TLS с самого начала"],
  [/^([\\d,]+) ms uptime$/, "$1 мс работы"],
  [/^(\\d+) varbinds?$/, (m,a)=>a+" varbind"],
  [/^(\\d+) records?$/, (m,a)=>a+" "+pw(a,"запись","записи","записей")],
  [/^(.+) \\(TTL ([\\d,]+) s\\)$/, "$1 (TTL $2 с)"],
  [/^(.+) ×(\\d+)$/, "$1 ×$2"],
  [/^Packet (\\d+)$/, "Пакет $1"],
  [/^(\\d+) ms$/, "$1 мс"],
  [/^([\\d.,]+) s$/, "$1 с"],
]`;
const out=`import { n as t } from "./shared-CAKwAg2C.js";
const pw=(v,a,b,c)=>{const n=Math.abs(parseInt(String(v).replace(/[^\\d]/g,""),10))%100,m=n%10;return n>10&&n<20?c:m===1?a:m>=2&&m<=4?b:c},
pl=(v)=>pw(v,"байт","байта","байт");
const p = { strings: ${JSON.stringify(strings)}, patterns: ${pats}, post: t };
export { p as default };
`;
fs.writeFileSync(require('path').join(__dirname,'../../assets/ru.js'),out);
console.log('strings',n,'bad',bad, out.length);
