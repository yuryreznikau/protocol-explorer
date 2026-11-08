#!/usr/bin/env python3
"""Builds assets/index.js from the readable upstream bundle (tools/upstream.pretty.js).

Changes applied:
  * only application-layer lessons are kept (TCP, UDP, IP, ICMP and TLS removed);
  * SNMP, NetFlow, Syslog/UDP and Syslog/TCP lessons and decoders (src/monitoring.js) are added;
  * the interface languages are Russian and English only, right-to-left support is removed.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
src = (ROOT / "tools" / "upstream.pretty.js").read_text(encoding="utf-8")
monitoring = (ROOT / "src" / "monitoring.js").read_text(encoding="utf-8")


def sub(old, new, count=1):
    global src
    if src.count(old) < 1:
        raise SystemExit(f"pattern not found: {old[:80]!r}")
    src = src.replace(old, new, count)


def sub_re(pattern, new, flags=re.S):
    global src
    src, n = re.subn(pattern, lambda _m: new, src, count=1, flags=flags)
    if n != 1:
        raise SystemExit(f"regex not found: {pattern[:80]!r}")


# 1. language chunks: only Russian is loaded lazily, English is built in
sub_re(r"const __vite__mapDeps = \(.*?\) => i\.map\(\(i\) => d\[i\]\);\n", "")
sub_re(
    r"  Ht = \[\n.*?\n  \];\n",
    """  Ht = [
    {
      code: "ru",
      name: "Русский",
      short: "RU",
      html: "ru",
      load: () => Oe(() => import("./ru.js"), []),
    },
    { code: "en", name: "English", short: "EN", html: "en" },
  ];
""",
)
# default language: saved choice, otherwise Russian unless the browser prefers another language
sub_re(
    r"async function Ol\(\) \{\n  let e = \"fa\";\n  try \{\n    e = localStorage\.getItem\(mr\) \|\| \"fa\";\n  \} catch \{\}",
    """async function Ol() {
  let e = "ru";
  try {
    e =
      localStorage.getItem(mr) ||
      (/^(ru|be|uk|kk)\\b/i.test(navigator.language || "ru") ? "ru" : "en");
  } catch {}""",
)

# 2. no right-to-left layout any more
sub('us = () => Ht.find((e) => e.code === yn).dir === "rtl",', "us = () => !1,")
sub('const Al = () => (document.documentElement.dir === "rtl" ? -1 : 1),', "const Al = () => 1,")
sub('(document.documentElement.dir = o.dir ?? "ltr"),', '(document.documentElement.dir = "ltr"),')

# 3. drop the lessons below the application layer
lines = src.split("\n")
for ident in ["ui", "fi", "mi", "Ti", "wl"]:
    start = lines.index(f"  {ident} = {{")
    end = next(i for i in range(start + 1, len(lines)) if lines[i] in ("  },", "  };"))
    if lines[end] == "  };":
        # last declarator of its chain: the previous one now ends the statement
        prev = start - 1
        assert lines[prev].endswith(","), lines[prev]
        lines[prev] = lines[prev][:-1] + ";"
    del lines[start : end + 1]
src = "\n".join(lines)

# 4. lesson registry, catalogue and sidebar tabs
catalog = [
    ("http", "HTTP", "Hypertext Transfer Protocol", "application"),
    ("https", "HTTPS", "HTTP Secure", "security"),
    ("http2", "HTTP/2", "Hypertext Transfer Protocol Version 2", "application"),
    ("http3", "HTTP/3", "HTTP/3 over QUIC", "application"),
    ("dns", "DNS", "Domain Name System", "application"),
    ("dhcp", "DHCP", "Dynamic Host Configuration", "application"),
    ("smtp", "SMTP", "Simple Mail Transfer Protocol", "application"),
    ("pop3", "POP3", "Post Office Protocol v3", "application"),
    ("imap", "IMAP", "Internet Message Access", "application"),
    ("ftp", "FTP", "File Transfer Protocol", "application"),
    ("ssh", "SSH", "Secure Shell", "security"),
    ("ws", "WebSocket", "WebSocket Protocol", "application"),
    ("mqtt", "MQTT", "Message Queuing Telemetry Transport", "application"),
    ("sse", "SSE", "Server-Sent Events", "application"),
    ("chunked", "Chunked", "HTTP Chunked Transfer Encoding", "application"),
    ("grpc", "gRPC", "gRPC Remote Procedure Calls", "application"),
    ("snmp", "SNMP", "Simple Network Management Protocol", "monitoring"),
    ("netflow", "NetFlow", "Cisco NetFlow v9 / IPFIX", "monitoring"),
    ("syslog-udp", "Syslog/UDP", "Syslog over UDP", "monitoring"),
    ("syslog-tcp", "Syslog/TCP", "Syslog over TCP", "monitoring"),
]
lesson_vars = {
    "http": "pi", "https": "hi", "dns": "wi", "dhcp": "Si", "smtp": "_i", "pop3": "Ki",
    "imap": "Xi", "ftp": "Zi", "ssh": "ul", "http2": "lessonHttp2", "http3": "lessonHttp3",
    "ws": "lessonWs", "mqtt": "lessonMqtt", "sse": "lessonSse", "chunked": "lessonChunked",
    "grpc": "lessonGrpc", "snmp": "lessonSnmp", "netflow": "lessonNetflow",
    "syslog-udp": "lessonSyslogUdp", "syslog-tcp": "lessonSyslogTcp",
}
cs = ",\n".join(f'    "{i}": {lesson_vars[i]}' for i, *_ in catalog)
xt = ",\n".join(
    f'    {{ id: "{i}", name: "{n}", full: "{full}", group: "{g}" }}' for i, n, full, g in catalog
)
sub_re(
    r"const cs = \{\n.*?\n  Xt = \[\n.*?\n  \],\n  _e = \{",
    "// === NETWORK MONITORING LESSONS (src/monitoring.js) ===\n"
    + monitoring
    + f"\nconst cs = {{\n{cs},\n  }},\n  Xt = [\n{xt},\n  ],\n  _e = {{",
)
sub(
    """const Xl = [
  ["all", "ALL"],
  ["core", "CORE"],
  ["application", "APPLICATION"],
  ["security", "SECURITY"],
];""",
    """const Xl = [
  ["all", "ALL"],
  ["application", "APPLICATION"],
  ["security", "SECURITY"],
  ["monitoring", "MONITORING"],
];""",
)

# 5. packet inspector: new payload decoders
sub(
    "  if (t.grpc) return decodeGrpc(t.grpc);\n",
    "  if (t.grpc) return decodeGrpc(t.grpc);\n"
    "  if (t.snmp) return decodeSnmp(t.snmp);\n"
    "  if (t.netflow) return decodeNetflow(t.netflow);\n"
    "  if (t.syslog) return decodeSyslog(t.syslog);\n",
)

# 6. sequence view: translate the second label line (address and role) as well
sub(
    "  const a = (e.labels?.[t] ?? Ge[t])[1];\n  return a || ",
    "  const a = b((e.labels?.[t] ?? Ge[t])[1]);\n  return a || ",
)

sub(
    'text-anchor="${n}">${a}</text>`\n      : "") +',
    'text-anchor="${n}">${b(a)}</text>`\n      : "") +',
)

out = ROOT / "assets" / "index.js"
out.write_text(src, encoding="utf-8")
print(f"wrote {out} ({len(src):,} bytes)")
