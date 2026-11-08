// ==================== NETWORK MONITORING LESSONS: SNMP, NetFlow, Syslog ====================
// This code is injected into the main bundle scope (see tools/build.py), so it can use the
// lesson helpers defined there: u() packet event, N() time, $e() TCP connection,
// O() TCP wire, Je() TCP handshake, be() frame length, f (laptop IP), rt (router LAN IP),
// Ts (router WAN IP) and the byte writer class `me`.

// ---------- SNMP (ASN.1 BER) ----------
const snmpOidNames = {
  "1.3.6.1.2.1.1.1.0": "sysDescr.0",
  "1.3.6.1.2.1.1.3.0": "sysUpTime.0",
  "1.3.6.1.2.1.1.4.0": "sysContact.0",
  "1.3.6.1.2.1.1.5.0": "sysName.0",
  "1.3.6.1.2.1.2.2.1.2": "ifDescr",
  "1.3.6.1.2.1.2.2.1.2.1": "ifDescr.1",
  "1.3.6.1.2.1.2.2.1.2.2": "ifDescr.2",
  "1.3.6.1.2.1.2.2.1.2.3": "ifDescr.3",
  "1.3.6.1.2.1.2.2.1.1.1": "ifIndex.1",
  "1.3.6.1.2.1.31.1.1.1.6": "ifHCInOctets",
  "1.3.6.1.2.1.31.1.1.1.6.1": "ifHCInOctets.1",
  "1.3.6.1.2.1.31.1.1.1.6.2": "ifHCInOctets.2",
  "1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
  "1.3.6.1.2.1.31.1.1.1.10.1": "ifHCOutOctets.1",
  "1.3.6.1.2.1.31.1.1.1.10.2": "ifHCOutOctets.2",
  "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID.0",
  "1.3.6.1.6.3.1.1.5.3": "linkDown",
  "1.3.6.1.2.1.2.2.1.7.2": "ifAdminStatus.2",
  "1.3.6.1.2.1.2.2.1.8.2": "ifOperStatus.2",
  "1.3.6.1.2.1.2.2.1.1.2": "ifIndex.2",
};
const snmpPduTags = {
  get: [0xa0, "GetRequest"],
  getnext: [0xa1, "GetNextRequest"],
  response: [0xa2, "Response"],
  set: [0xa3, "SetRequest"],
  getbulk: [0xa5, "GetBulkRequest"],
  inform: [0xa6, "InformRequest"],
  trap: [0xa7, "SNMPv2-Trap"],
};
const snmpErrors = ["noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType", "wrongLength", "wrongEncoding", "wrongValue", "noCreation", "inconsistentValue", "resourceUnavailable", "commitFailed", "undoFailed", "authorizationError", "notWritable"];
const berLen = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]);
function berInt(v) {
  const out = [];
  let x = BigInt(v);
  if (x === 0n) return [0];
  while (x > 0n) {
    out.unshift(Number(x & 255n));
    x >>= 8n;
  }
  if (out[0] & 0x80) out.unshift(0);
  return out;
}
function berOid(s) {
  const p = s.split(".").map(Number);
  const out = [40 * p[0] + p[1]];
  for (const n of p.slice(2)) {
    const b = [n & 127];
    let x = n >>> 7;
    while (x > 0) {
      b.unshift((x & 127) | 128);
      x >>>= 7;
    }
    out.push(...b);
  }
  return out;
}
const snmpTicks = (t) => {
  const cs = t % 100, s = Math.floor(t / 100), d = Math.floor(s / 86400);
  const hh = String(Math.floor((s % 86400) / 3600)).padStart(2, "0"),
    mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0"),
    ss = String(s % 60).padStart(2, "0");
  return `${t} (${d} d ${hh}:${mm}:${ss}.${String(cs).padStart(2, "0")})`;
};
const snmpOidLabel = (o) => (snmpOidNames[o] ? `${o} (${snmpOidNames[o]})` : o);
// value: [type, v]
function snmpValue([type, v]) {
  const enc = new TextEncoder();
  switch (type) {
    case "null": return { tag: 0x05, bytes: [], show: "NULL (value asked for)" };
    case "int": return { tag: 0x02, bytes: berInt(v), show: `INTEGER ${v}` };
    case "str": return { tag: 0x04, bytes: [...enc.encode(v)], show: `OCTET STRING "${v}"` };
    case "oid": return { tag: 0x06, bytes: berOid(v), show: `OID ${snmpOidLabel(v)}` };
    case "ticks": return { tag: 0x43, bytes: berInt(v), show: `TimeTicks ${snmpTicks(v)}` };
    case "counter64": return { tag: 0x46, bytes: berInt(v), show: `Counter64 ${Number(v).toLocaleString("en-US")}` };
    case "endOfMibView": return { tag: 0x82, bytes: [], show: "endOfMibView (no more objects)" };
    default: throw new Error("snmp type " + type);
  }
}
function snmpTree(t) {
  const [pduTag, pduName] = snmpPduTags[t.pdu];
  const leaf = (tag, bytes, name, value, opts = {}) => ({ tag, bytes, name, value, opts });
  const seq = (tag, name, value, children, opts = {}) => ({ tag, children, name, value, opts });
  const vbs = t.varbinds.map(([oid, val, note]) => {
    const v = snmpValue(val);
    return seq(0x30, "Varbind", snmpOidNames[oid] || oid, [
      leaf(0x06, berOid(oid), "Object ID (OID)", snmpOidLabel(oid), { mono: !0 }),
      leaf(v.tag, v.bytes, "Value", v.show, { mono: !0, note }),
    ]);
  });
  const bulk = t.pdu === "getbulk";
  const errName = snmpErrors[t.errorStatus ?? 0] ?? String(t.errorStatus);
  const pduKids = [
    leaf(0x02, berInt(t.requestId), "Request ID", t.requestId, {
      note: "The manager picks it; the answer carries the same number, so replies can be matched to requests over UDP.",
    }),
    bulk
      ? leaf(0x02, berInt(t.nonRepeaters ?? 0), "Non-repeaters", t.nonRepeaters ?? 0, { note: "How many of the first OIDs to fetch only once." })
      : leaf(0x02, berInt(t.errorStatus ?? 0), "Error status", `${t.errorStatus ?? 0} (${errName})`, t.errorStatus ? { note: "Non-zero means the agent refused the request." } : {}),
    bulk
      ? leaf(0x02, berInt(t.maxRepetitions ?? 0), "Max-repetitions", t.maxRepetitions ?? 0, { note: "How many next objects to return for each remaining OID." })
      : leaf(0x02, berInt(t.errorIndex ?? 0), "Error index", t.errorIndex ?? 0),
    seq(0x30, "Varbind list", `${vbs.length} ${vbs.length === 1 ? "varbind" : "varbinds"}`, vbs, {
      note: "Pairs of object name (OID) and value. In requests the value is NULL.",
    }),
  ];
  return seq(0x30, "SNMP message", "SEQUENCE", [
    leaf(0x02, berInt(t.version ?? 1), "Version", (t.version ?? 1) === 1 ? "1 (SNMPv2c)" : "0 (SNMPv1)", {
      note: "The number on the wire is one less than the version name.",
    }),
    leaf(0x04, [...new TextEncoder().encode(t.community)], "Community", `"${t.community}"`, {
      mono: !0,
      note: "A shared password, sent in plain text. SNMPv3 replaces it with real users, authentication and encryption.",
    }),
    seq(pduTag, "PDU type", `${pduName} (0x${pduTag.toString(16).toUpperCase()})`, pduKids),
  ], { note: "Every SNMP message is ASN.1 BER: type, length, value, nested." });
}
function berSize(n) {
  const body = n.children ? n.children.reduce((a, c) => a + berSize(c), 0) : n.bytes.length;
  return 1 + berLen(body).length + body;
}
function berEmit(s, n, depth) {
  if (n.children) {
    const body = n.children.reduce((a, c) => a + berSize(c), 0);
    s.field(n.name, n.value, () => s.raw([n.tag, ...berLen(body)]), { depth, ...n.opts });
    n.children.forEach((c) => berEmit(s, c, depth + 1));
  } else {
    s.field(n.name, n.value, () => s.raw([n.tag, ...berLen(n.bytes.length), ...n.bytes]), { depth, ...n.opts });
  }
}
const snmpSize = (t) => berSize(snmpTree(t));
function decodeSnmp(t) {
  const s = new me("app", `SNMP · ${snmpPduTags[t.pdu][1]}`);
  s.summary = `v2c · ${snmpPduTags[t.pdu][1]}`;
  berEmit(s, snmpTree(t), 0);
  return s;
}

// ---------- NetFlow v9 ----------
const nfFieldDefs = [
  [8, 4, "IPV4_SRC_ADDR"],
  [12, 4, "IPV4_DST_ADDR"],
  [7, 2, "L4_SRC_PORT"],
  [11, 2, "L4_DST_PORT"],
  [4, 1, "PROTOCOL"],
  [6, 1, "TCP_FLAGS"],
  [2, 4, "IN_PKTS"],
  [1, 4, "IN_BYTES"],
  [22, 4, "FIRST_SWITCHED"],
  [21, 4, "LAST_SWITCHED"],
  [10, 2, "INPUT_SNMP"],
  [14, 2, "OUTPUT_SNMP"],
];
const nfRecLen = nfFieldDefs.reduce((a, [, l]) => a + l, 0);
const nfProto = { 6: "TCP", 17: "UDP", 1: "ICMP" };
const nfFlags = (v) => {
  const n = [[1, "FIN"], [2, "SYN"], [4, "RST"], [8, "PSH"], [16, "ACK"]].filter(([b]) => v & b).map(([, x]) => x);
  return `0x${v.toString(16).padStart(2, "0")}${n.length ? ` (${n.join(", ")})` : ""}`;
};
function nfSize(t) {
  let n = 20;
  if (t.template) n += 4 + 4 + 4 * nfFieldDefs.length;
  if (t.records) {
    const l = 4 + nfRecLen * t.records.length;
    n += l + ((4 - (l % 4)) % 4);
  }
  return n;
}
function decodeNetflow(t) {
  const s = new me("app", t.template ? "NetFlow v9 · Template" : `NetFlow v9 · ${t.records.length} flows`);
  s.summary = `seq ${t.seq}`;
  const count = (t.template ? 1 : 0) + (t.records ? t.records.length : 0);
  s.field("Version", "9", () => s.u16(9), { note: "NetFlow v9 (RFC 3954). IPFIX (RFC 7011) is its standard successor, version 10." });
  s.field("Count", `${count} ${count === 1 ? "record" : "records"}`, () => s.u16(count), { note: "Template and data records in this packet." });
  s.field("System uptime", `${t.uptime} ms`, () => s.u32(t.uptime), { note: "Milliseconds since the router booted. Flow start and end times count from the same clock." });
  s.field("Export time", `${t.unix} (2026-11-08 13:2${t.unixLabel ?? "0"} UTC)`, () => s.u32(t.unix));
  s.field("Sequence number", t.seq, () => s.u32(t.seq), { note: "Counts export packets. A gap tells the collector that packets were lost on the way." });
  s.field("Source ID", t.sourceId ?? 1, () => s.u32(t.sourceId ?? 1), { note: "Which exporting process on the router sent it." });
  if (t.template) {
    const l = 4 + 4 + 4 * nfFieldDefs.length;
    s.field("FlowSet ID", "0 (Template FlowSet)", () => s.u16(0), { depth: 0, note: "ID 0 means: the following describes the layout of data records." });
    s.field("FlowSet length", `${l} bytes`, () => s.u16(l), { depth: 1 });
    s.field("Template ID", "256", () => s.u16(256), { depth: 1, note: "Data FlowSets with ID 256 will use this layout." });
    s.field("Field count", nfFieldDefs.length, () => s.u16(nfFieldDefs.length), { depth: 1 });
    nfFieldDefs.forEach(([type, len, name]) =>
      s.field(`Field ${type}`, `${name}, ${len} ${len === 1 ? "byte" : "bytes"}`, () => s.u16(type).u16(len), { depth: 2, mono: !0 }),
    );
  }
  if (t.records) {
    const l = 4 + nfRecLen * t.records.length, pad = (4 - (l % 4)) % 4;
    s.field("FlowSet ID", "256 (data, uses template 256)", () => s.u16(256), { depth: 0, note: "Without template 256 the collector cannot tell where one field ends and the next begins." });
    s.field("FlowSet length", `${l + pad} bytes`, () => s.u16(l + pad), { depth: 1 });
    t.records.forEach((r, i) => {
      s.field(`Flow ${i + 1}`, `${r.src}:${r.sport} → ${r.dst}:${r.dport} ${nfProto[r.proto]}`, () => {}, { depth: 1, mono: !0 });
      s.field("Source address", r.src, () => s.raw(bt(r.src)), { depth: 2, mono: !0 });
      s.field("Destination address", r.dst, () => s.raw(bt(r.dst)), { depth: 2, mono: !0 });
      s.field("Source port", r.sport, () => s.u16(r.sport), { depth: 2 });
      s.field("Destination port", r.dport, () => s.u16(r.dport), { depth: 2 });
      s.field("Protocol", `${r.proto} (${nfProto[r.proto]})`, () => s.u8(r.proto), { depth: 2 });
      s.field("TCP flags", nfFlags(r.flags ?? 0), () => s.u8(r.flags ?? 0), { depth: 2, note: r.proto === 6 ? "All TCP flags seen in the flow, OR-ed together." : undefined });
      s.field("Packets", r.pkts.toLocaleString("en-US"), () => s.u32(r.pkts), { depth: 2 });
      s.field("Bytes", r.bytes.toLocaleString("en-US"), () => s.u32(r.bytes), { depth: 2, note: "IP bytes, headers included." });
      s.field("First packet", `${r.first} ms uptime`, () => s.u32(r.first), { depth: 2 });
      s.field("Last packet", `${r.last} ms uptime`, () => s.u32(r.last), { depth: 2 });
      s.field("Input interface", `${r.in} (${r.in === 1 ? "lan0" : "wan0"})`, () => s.u16(r.in), { depth: 2, note: "The same ifIndex numbers SNMP uses." });
      s.field("Output interface", `${r.out} (${r.out === 1 ? "lan0" : "wan0"})`, () => s.u16(r.out), { depth: 2 });
    });
    if (pad) s.field("Padding", `${pad} zero bytes`, () => s.raw(Array(pad).fill(0)), { depth: 1 });
  }
  return s;
}

// ---------- Syslog ----------
const sysFacilities = { 0: "kern", 1: "user", 3: "daemon", 4: "auth", 10: "authpriv", 16: "local0", 20: "local4", 23: "local7" };
const sysSeverities = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
const sysPriText = (p) => `${p} = ${sysFacilities[p >> 3] ?? p >> 3} (${p >> 3}) × 8 + ${sysSeverities[p & 7]} (${p & 7})`;
function sysLine(m) {
  if (m.format === "3164") return `<${m.pri}>${m.ts} ${m.host} ${m.tag}: ${m.msg}`;
  return `<${m.pri}>1 ${m.ts} ${m.host} ${m.app} ${m.procid ?? "-"} ${m.msgid ?? "-"} ${m.sd ?? "-"} ${m.msg}`;
}
const sysBytes = (m) => new TextEncoder().encode(sysLine(m)).length;
const sysFramed = (m, octet) => (octet ? `${sysBytes(m)} `.length + sysBytes(m) : sysBytes(m));
const sysSize = (t) => (t.messages ?? [t.message]).reduce((a, m) => a + sysFramed(m, t.octet), 0);
function sysEmit(s, m, octet, depth) {
  if (octet) s.field("Message length", `${sysBytes(m)} bytes`, () => s.ascii(`${sysBytes(m)} `), { depth, mono: !0, note: "Octet counting (RFC 6587): the byte count and a space come first, so the receiver knows exactly where each message ends in the TCP stream." });
  s.field("PRI", sysPriText(m.pri), () => s.ascii(`<${m.pri}>`), { depth, mono: !0, note: "Facility × 8 + severity, in angle brackets. Severity 0 is the most urgent, 7 the least." });
  if (m.format === "3164") {
    s.field("Timestamp", m.ts, () => s.ascii(m.ts + " "), { depth, mono: !0, note: "BSD format (RFC 3164): no year, no time zone, no fractions of a second." });
    s.field("Hostname", m.host, () => s.ascii(m.host + " "), { depth, mono: !0 });
    s.field("Tag", m.tag, () => s.ascii(m.tag + ": "), { depth, mono: !0, note: "Program name and process ID." });
  } else {
    s.field("Version", "1 (RFC 5424)", () => s.ascii("1 "), { depth, mono: !0 });
    s.field("Timestamp", m.ts, () => s.ascii(m.ts + " "), { depth, mono: !0, note: "Full date, milliseconds and time zone (Z = UTC)." });
    s.field("Hostname", m.host, () => s.ascii(m.host + " "), { depth, mono: !0 });
    s.field("App name", m.app, () => s.ascii(m.app + " "), { depth, mono: !0 });
    s.field("Process ID", m.procid ?? "-", () => s.ascii((m.procid ?? "-") + " "), { depth, mono: !0 });
    s.field("Message ID", m.msgid ?? "- (none)", () => s.ascii((m.msgid ?? "-") + " "), { depth, mono: !0 });
    s.field("Structured data", m.sd ?? "- (none)", () => s.ascii((m.sd ?? "-") + " "), { depth, mono: !0, note: m.sd ? "Machine-readable key=value pairs; the @32473 part is a private enterprise number." : undefined });
  }
  s.field("Message", m.msg, () => s.ascii(m.msg), { depth, mono: !0 });
}
function decodeSyslog(t) {
  const list = t.messages ?? [t.message];
  const s = new me("app", list.length > 1 ? `Syslog · ${list.length} messages` : `Syslog · ${sysSeverities[list[0].pri & 7]}`);
  s.summary = t.octet ? "octet counting" : list[0].format === "3164" ? "RFC 3164" : "RFC 5424";
  if (list.length === 1) sysEmit(s, list[0], t.octet, 0);
  else
    list.forEach((m, i) => {
      s.field(`Message ${i + 1}`, `${sysFacilities[m.pri >> 3]}.${sysSeverities[m.pri & 7]}`, () => {}, { depth: 0 });
      sysEmit(s, m, t.octet, 1);
    });
  return s;
}

// ---------- SNMP lesson ----------
const SNMP_COMM = "public";
const snmpRow = (time, src, dst, sport, dport, info, msg) => ({
  time: N(time),
  src,
  dst,
  proto: "SNMP",
  info,
  len: `${Me + De + 8 + snmpSize(msg)} B`,
  wire: { udp: { sport, dport, data: { snmp: msg } } },
});
const snmpQ = (time, msg, info) => snmpRow(time, f, rt, 50123, 161, info, msg);
const snmpA = (time, msg, info) => snmpRow(time, rt, f, 161, 50123, info, msg);
const SNMP_DESCR = "Linux gw1 6.6.52 #1 SMP armv8l";
const snmpGet1 = { community: SNMP_COMM, pdu: "get", requestId: 1804289383, varbinds: [["1.3.6.1.2.1.1.1.0", ["null"]], ["1.3.6.1.2.1.1.3.0", ["null"]]] };
const snmpGet1r = { ...snmpGet1, pdu: "response", varbinds: [["1.3.6.1.2.1.1.1.0", ["str", SNMP_DESCR]], ["1.3.6.1.2.1.1.3.0", ["ticks", 123456700], "Hundredths of a second since the agent started."]] };
const snmpNext1 = { community: SNMP_COMM, pdu: "getnext", requestId: 1804289384, varbinds: [["1.3.6.1.2.1.2.2.1.2", ["null"]]] };
const snmpNext1r = { ...snmpNext1, pdu: "response", varbinds: [["1.3.6.1.2.1.2.2.1.2.1", ["str", "lan0"]]] };
const snmpNext2 = { community: SNMP_COMM, pdu: "getnext", requestId: 1804289385, varbinds: [["1.3.6.1.2.1.2.2.1.2.1", ["null"]]] };
const snmpNext2r = { ...snmpNext2, pdu: "response", varbinds: [["1.3.6.1.2.1.2.2.1.2.2", ["str", "wan0"]]] };
const snmpBulk = { community: SNMP_COMM, pdu: "getbulk", requestId: 1804289386, nonRepeaters: 1, maxRepetitions: 2, varbinds: [["1.3.6.1.2.1.1.3.0", ["null"]], ["1.3.6.1.2.1.31.1.1.1.6", ["null"]], ["1.3.6.1.2.1.31.1.1.1.10", ["null"]]] };
const snmpBulkr = {
  ...snmpBulk,
  pdu: "response",
  nonRepeaters: undefined,
  maxRepetitions: undefined,
  errorStatus: 0,
  errorIndex: 0,
  varbinds: [
    ["1.3.6.1.2.1.1.3.0", ["ticks", 123457950]],
    ["1.3.6.1.2.1.31.1.1.1.6.1", ["counter64", 48213377102], "64-bit counter: bytes received on lan0 since boot."],
    ["1.3.6.1.2.1.31.1.1.1.10.1", ["counter64", 912884310577]],
    ["1.3.6.1.2.1.31.1.1.1.6.2", ["counter64", 913552087411]],
    ["1.3.6.1.2.1.31.1.1.1.10.2", ["counter64", 49010264881]],
  ],
};
const snmpSetRo = { community: SNMP_COMM, pdu: "set", requestId: 1804289387, varbinds: [["1.3.6.1.2.1.1.4.0", ["str", "noc@example.com"]]] };
const snmpSetRor = { ...snmpSetRo, pdu: "response", errorStatus: 6, errorIndex: 1 };
const snmpSetRw = { ...snmpSetRo, community: "n0c-Wr1te", requestId: 1804289388 };
const snmpSetRwr = { ...snmpSetRw, pdu: "response" };
const snmpLost = { community: SNMP_COMM, pdu: "get", requestId: 1804289389, varbinds: [["1.3.6.1.2.1.1.3.0", ["null"]]] };
const snmpLostr = { ...snmpLost, pdu: "response", varbinds: [["1.3.6.1.2.1.1.3.0", ["ticks", 123470400]]] };
const snmpTrap = {
  community: SNMP_COMM,
  pdu: "trap",
  requestId: 912,
  varbinds: [
    ["1.3.6.1.2.1.1.3.0", ["ticks", 123480055], "When it happened, in agent uptime."],
    ["1.3.6.1.6.3.1.1.4.1.0", ["oid", "1.3.6.1.6.3.1.1.5.3"], "Which event this is: linkDown."],
    ["1.3.6.1.2.1.2.2.1.1.2", ["int", 2]],
    ["1.3.6.1.2.1.2.2.1.7.2", ["int", 1], "1 = up: nobody switched it off on purpose."],
    ["1.3.6.1.2.1.2.2.1.8.2", ["int", 2], "2 = down: the link is lost."],
  ],
};
const lessonSnmp = {
  id: "snmp",
  name: "SNMP",
  title: "Polling and Traps",
  layer: 7,
  nodes: ["client", "router"],
  latency: { "client-router": 0.002 },
  labels: {
    client: ["NMS", "192.168.1.10 · SNMP manager"],
    router: ["Router", "192.168.1.1 · SNMP agent"],
  },
  legend: [
    ["amber", "Request (manager)"],
    ["violet", "Response (agent)"],
    ["teal", "Trap (agent)"],
  ],
  overview: {
    full: "Simple Network Management Protocol",
    description:
      "SNMP lets a monitoring station read and change the state of network devices. The device runs an agent that exposes counters and settings as a tree of numbered objects (the MIB). The manager polls them over UDP, and the agent can also push alerts, called traps, when something happens.",
    facts: [
      ["Layer", "Application (Layer 7)"],
      ["Ports", "UDP 161 (agent), 162 (traps)"],
      ["Transport", "UDP"],
      ["Encoding", "ASN.1 BER"],
      ["Versions", "v1, v2c (community), v3 (users, encryption)"],
      ["Defined In", "RFC 3411–3418"],
    ],
  },
  outro: {
    title: "Device under watch",
    desc: "Polled on schedule, alerting on its own",
    text: "The manager read the router’s name, uptime and traffic counters, walked its interface table, was refused a change with the read-only community and allowed it with the write one, recovered from a lost request by retrying, and got a trap the moment a link went down. Press REPLAY to watch it again.",
    facts: [
      ["Requests", "Get, GetNext, GetBulk, Set"],
      ["Agent push", "SNMPv2-Trap to port 162"],
      ["Reliability", "Manager retries on timeout"],
      ["Security", "v2c: plain text; use v3 authPriv"],
    ],
  },
  start: { nodes: ["client"], frame: "client" },
  steps: [
    {
      title: "Manager and Agent",
      desc: "Who asks and who answers",
      detail:
        "The laptop runs a network monitoring system (NMS), the SNMP manager. The router runs an SNMP agent on UDP port 161. Everything the agent can report has a numeric name, an OID, such as 1.3.6.1.2.1.1.3.0 for sysUpTime.",
      facts: [
        ["Manager", "192.168.1.10 (NMS)"],
        ["Agent", "192.168.1.1, UDP 161"],
        ["MIB-2 root", "1.3.6.1.2.1"],
      ],
      events: [
        { type: "show", nodes: ["router"], frame: "local" },
        { type: "note", at: "router", text: "AGENT LISTENING ON UDP 161", tone: "teal" },
      ],
    },
    {
      title: "GetRequest",
      desc: "Read named objects",
      detail:
        "The manager asks for two objects by OID: sysDescr.0 and sysUpTime.0. It sends the community string “public”, which acts as a read-only password. The values in a request are NULL; the agent fills them in and answers with the same request ID.",
      facts: [
        ["Community", "public (read-only)"],
        ["Asked for", "sysDescr.0, sysUpTime.0"],
        ["Uptime", "123456700 ticks ≈ 14 days"],
      ],
      events: [
        u("client", "router", "amber", "GET", ["sysDescr.0", "sysUpTime.0"], snmpQ(0, snmpGet1, "get-request 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.3.0")),
        u("router", "client", "violet", "RESPONSE", [SNMP_DESCR, "uptime 14 d 06:56"], snmpA(0.003, snmpGet1r, "get-response 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.3.0")),
      ],
    },
    {
      title: "GetNext: Walking a Table",
      desc: "Step through the interface list",
      detail:
        "The manager doesn’t know how many interfaces the router has, so it walks the ifDescr column: GetNext returns the first object after the OID given. Feeding each answer back in visits the whole table, one round trip per row. This is what snmpwalk does.",
      facts: [
        ["Column", "ifDescr (1.3.6.1.2.1.2.2.1.2)"],
        ["Row 1", "lan0"],
        ["Row 2", "wan0"],
      ],
      events: [
        u("client", "router", "amber", "GETNEXT", ["after ifDescr"], snmpQ(0.21, snmpNext1, "get-next-request 1.3.6.1.2.1.2.2.1.2")),
        u("router", "client", "violet", "RESPONSE", ["ifDescr.1 = lan0"], snmpA(0.213, snmpNext1r, "get-response 1.3.6.1.2.1.2.2.1.2.1")),
        u("client", "router", "amber", "GETNEXT", ["after ifDescr.1"], snmpQ(0.215, snmpNext2, "get-next-request 1.3.6.1.2.1.2.2.1.2.1"), { quick: !0 }),
        u("router", "client", "violet", "RESPONSE", ["ifDescr.2 = wan0"], snmpA(0.218, snmpNext2r, "get-response 1.3.6.1.2.1.2.2.1.2.2"), { quick: !0 }),
      ],
    },
    {
      title: "GetBulk: Traffic Counters",
      desc: "Many rows in one round trip",
      detail:
        "SNMPv2c adds GetBulk: one request returns several next objects at once. Non-repeaters = 1 fetches sysUpTime once; max-repetitions = 2 returns two rows of the in and out byte counters. Polling them every minute and taking the difference gives the traffic graph.",
      facts: [
        ["Non-repeaters", "1 (sysUpTime)"],
        ["Max-repetitions", "2 (both interfaces)"],
        ["Counters", "ifHCInOctets, ifHCOutOctets (64-bit)"],
      ],
      events: [
        u("client", "router", "amber", "GETBULK", ["non-rep 1, max-rep 2", "ifHCIn/OutOctets"], snmpQ(0.42, snmpBulk, "getBulkRequest N=1 M=2")),
        u("router", "client", "violet", "RESPONSE", ["5 varbinds", "byte counters for lan0, wan0"], snmpA(0.424, snmpBulkr, "get-response 5 varbinds")),
      ],
    },
    {
      title: "SetRequest",
      desc: "Change a value, with the right password",
      detail:
        "Set writes a value. With the read-only community the agent answers error-status noAccess (6) and error-index 1, pointing at the first varbind. Sent again with the write community, the change of sysContact succeeds. In v2c both communities cross the network in plain text.",
      facts: [
        ["Object", "sysContact.0"],
        ["With “public”", "noAccess (6)"],
        ["With write community", "noError, value stored"],
      ],
      events: [
        u("client", "router", "amber", "SET", ["sysContact.0 = noc@example.com", "community public"], snmpQ(0.63, snmpSetRo, "set-request 1.3.6.1.2.1.1.4.0")),
        u("router", "client", "violet", "RESPONSE", ["noAccess (6)", "error-index 1"], snmpA(0.633, snmpSetRor, "get-response noAccess 1.3.6.1.2.1.1.4.0")),
        { type: "note", at: "router", text: "READ-ONLY COMMUNITY", tone: "amber" },
        u("client", "router", "amber", "SET", ["same value", "write community"], snmpQ(0.65, snmpSetRw, "set-request 1.3.6.1.2.1.1.4.0")),
        u("router", "client", "violet", "RESPONSE", ["noError"], snmpA(0.653, snmpSetRwr, "get-response 1.3.6.1.2.1.1.4.0")),
      ],
    },
    {
      title: "Lost Request, Retry",
      desc: "UDP gives no guarantees",
      detail:
        "The next poll is lost on the way. UDP doesn’t notice, so the manager relies on its own timer: after 1 s with no response it sends the request again, same request ID. Typical managers retry a few times before marking the device unreachable.",
      facts: [
        ["Timeout", "1 s"],
        ["Retry", "Same request ID 1804289389"],
        ["Then", "Usually 3–5 retries max"],
      ],
      events: [
        u("client", "router", "amber", "GET", ["sysUpTime.0"], snmpQ(0.84, snmpLost, "get-request 1.3.6.1.2.1.1.3.0"), { lost: !0 }),
        { type: "note", at: "client", text: "NO RESPONSE IN 1 S", tone: "amber" },
        u("client", "router", "amber", "RETRY", ["same request ID"], snmpQ(1.84, snmpLost, "get-request 1.3.6.1.2.1.1.3.0 (retry)")),
        u("router", "client", "violet", "RESPONSE", ["sysUpTime.0"], snmpA(1.843, snmpLostr, "get-response 1.3.6.1.2.1.1.3.0")),
      ],
    },
    {
      title: "Trap: Link Down",
      desc: "The agent speaks first",
      detail:
        "The WAN cable is unplugged. The agent doesn’t wait to be polled: it sends an SNMPv2-Trap to the manager’s UDP port 162 with the event OID linkDown and the interface’s index and status. A trap is never acknowledged; InformRequest is the variant that is.",
      facts: [
        ["To", "192.168.1.10, UDP 162"],
        ["Event", "linkDown (1.3.6.1.6.3.1.1.5.3)"],
        ["Interface", "ifIndex 2 (wan0)"],
      ],
      events: [
        { type: "note", at: "router", text: "WAN0 LINK LOST", tone: "amber" },
        u("router", "client", "teal", "TRAP", ["linkDown", "ifIndex 2, oper down"], snmpRow(2.4, rt, f, 49731, 162, "snmpV2-trap 1.3.6.1.6.3.1.1.5.3 (linkDown)", snmpTrap)),
        { type: "note", at: "client", text: "ALERT: GW1 WAN0 DOWN", tone: "green" },
      ],
    },
  ],
};

// ---------- NetFlow lesson ----------
const NF_COLL = "203.0.113.50";
const NF_UNIX = 1794144000;
const nfRecords = [
  { src: f, dst: "203.0.113.10", sport: 52411, dport: 443, proto: 6, flags: 0x1b, pkts: 18, bytes: 2214, first: 1209300, last: 1211450, in: 1, out: 2 },
  { src: "203.0.113.10", dst: f, sport: 443, dport: 52411, proto: 6, flags: 0x1b, pkts: 16, bytes: 14890, first: 1209318, last: 1211452, in: 2, out: 1 },
  { src: f, dst: "8.8.8.8", sport: 61744, dport: 53, proto: 17, flags: 0, pkts: 1, bytes: 61, first: 1209100, last: 1209100, in: 1, out: 2 },
  { src: f, dst: "198.51.100.80", sport: 50312, dport: 22, proto: 6, flags: 0x1a, pkts: 42, bytes: 5880, first: 1209500, last: 1240100, in: 1, out: 2 },
];
const nfMore = [
  { src: f, dst: "198.51.100.80", sport: 50312, dport: 22, proto: 6, flags: 0x18, pkts: 120, bytes: 16030, first: 1240100, last: 1300100, in: 1, out: 2 },
  { src: "198.51.100.80", dst: f, sport: 22, dport: 50312, proto: 6, flags: 0x18, pkts: 118, bytes: 30412, first: 1240120, last: 1300090, in: 2, out: 1 },
];
const nfRow = (time, info, msg) => ({
  time: N(time),
  src: Ts,
  dst: NF_COLL,
  proto: "CFLOW",
  info,
  len: `${Me + De + 8 + nfSize(msg)} B`,
  wire: { udp: { sport: 49152, dport: 2055, data: { netflow: msg } } },
});
const nfTpl = { template: !0, uptime: 1241000, unix: NF_UNIX + 1, unixLabel: "0", seq: 7311 };
const nfData1 = { records: nfRecords, uptime: 1241020, unix: NF_UNIX + 1, unixLabel: "0", seq: 7312 };
const nfData2 = { records: nfMore.slice(0, 1), uptime: 1301000, unix: NF_UNIX + 61, unixLabel: "1", seq: 7313 };
const nfData3 = { records: nfMore.slice(1), uptime: 1301020, unix: NF_UNIX + 61, unixLabel: "1", seq: 7314 };
const lessonNetflow = {
  id: "netflow",
  name: "NetFlow",
  title: "Who Talked to Whom",
  layer: 7,
  nodes: ["client", "router", "internet", "web"],
  latency: { "client-router": 0.002, "router-web": 0.014, "client-web": 0.016, "client-internet": 0.008 },
  labels: {
    router: ["Router", "198.51.100.7 · flow exporter"],
    web: ["NetFlow Collector", NF_COLL],
  },
  legend: [
    ["slate", "User traffic"],
    ["teal", "Template"],
    ["blue", "Flow records"],
  ],
  overview: {
    full: "Cisco NetFlow v9 / IPFIX",
    description:
      "NetFlow summarises traffic instead of copying it. The router groups packets into flows, by addresses, ports and protocol, counts their packets and bytes, and when a flow ends sends a compact record to a collector over UDP. The collector shows who talked to whom, how much and when, without ever seeing the content.",
    facts: [
      ["Layer", "Application (Layer 7)"],
      ["Default Port", "UDP 2055 (also 9995, 4739 for IPFIX)"],
      ["Transport", "UDP"],
      ["Flow key", "Src/dst IP, ports, protocol, interface"],
      ["Format", "Templates + data records"],
      ["Defined In", "RFC 3954 (v9), RFC 7011 (IPFIX)"],
    ],
  },
  outro: {
    title: "Traffic accounted",
    desc: "Metadata for every conversation",
    text: "The router turned the laptop’s web, DNS and SSH traffic into flow records, described their layout once with a template, and exported them to the collector. A lost export packet showed up as a gap in the sequence numbers: those flows are simply missing from the statistics. Press REPLAY to watch it again.",
    facts: [
      ["Flows exported", "6 (one per direction)"],
      ["Record size", `${nfRecLen} bytes per flow`],
      ["Loss handling", "Detected by sequence, not resent"],
      ["Privacy", "Headers only, no payload"],
    ],
  },
  start: { nodes: ["client"], frame: "client" },
  steps: [
    {
      title: "Traffic Through the Router",
      desc: "Packets become flows",
      detail:
        "The laptop opens an HTTPS page, asks DNS for a name and starts an SSH session. Every packet passing the router is matched against its flow cache by the 5-tuple and interface. A new key starts a flow; matching packets add to its packet and byte counters.",
      facts: [
        ["Flow key", "src, dst, sport, dport, protocol"],
        ["Cache", "3 new flows (plus replies)"],
        ["Sampling", "None: every packet counted"],
      ],
      events: [
        { type: "show", nodes: ["router", "internet"], frame: "path" },
        {
          type: "stream",
          from: "client",
          to: "internet",
          color: "slate",
          label: "3 NEW FLOWS",
          payload: ["HTTPS, DNS, SSH"],
          packets: [
            u("client", "internet", "slate", "SYN :443", [], { time: N(0), src: f, dst: "203.0.113.10", proto: "TCP", info: "52411 → 443 [SYN] Seq=0", len: "66 B", wire: O($e(f, 52411, "203.0.113.10", 443), f, "S") }),
            u("client", "internet", "slate", "DNS", [], { time: N(0.004), src: f, dst: "8.8.8.8", proto: "DNS", info: "Standard query A www.example.com", len: "75 B", wire: { udp: { sport: 61744, dport: 53, data: { dns: { id: 31810, rd: !0, q: ["www.example.com", "A"] } } } } }),
            u("client", "internet", "slate", "SYN :22", [], { time: N(0.008), src: f, dst: "198.51.100.80", proto: "TCP", info: "50312 → 22 [SYN] Seq=0", len: "66 B", wire: O($e(f, 50312, "198.51.100.80", 22), f, "S") }),
          ],
        },
        { type: "note", at: "router", text: "FLOW CACHE: 4 ENTRIES", tone: "teal" },
      ],
    },
    {
      title: "Template FlowSet",
      desc: "Describe the record layout first",
      detail:
        "NetFlow v9 records have no fixed format. Before any data, the router exports a template: ID 256, twelve fields, each as a type number and length. The collector stores it per exporter and source ID and uses it to parse every record that refers to 256.",
      facts: [
        ["Template ID", "256"],
        ["Fields", `12, ${nfRecLen} bytes per record`],
        ["To", `${NF_COLL}, UDP 2055`],
      ],
      events: [
        { type: "show", nodes: ["web"], frame: "path" },
        u("router", "web", "teal", "TEMPLATE", ["ID 256, 12 fields"], nfRow(1.2, "NetFlow/IPFIX flow (9): FlowSet 0 (Template ID 256)", nfTpl)),
        { type: "note", at: "web", text: "TEMPLATE 256 STORED", tone: "green" },
      ],
    },
    {
      title: "Data FlowSet",
      desc: "Finished flows are exported",
      detail:
        "A flow is exported when it ends (TCP FIN or RST), when it has been idle for the inactive timeout (15 s), or every active timeout (1–30 min) for long ones. Here four flows go in one packet: HTTPS each way, DNS, and the first part of SSH. Flows are one-way, so a conversation makes two.",
      facts: [
        ["Records", "4 flows in one packet"],
        ["Largest", "HTTPS reply: 16 packets, 14,890 bytes"],
        ["Timeouts", "Inactive 15 s, active 60 s here"],
      ],
      events: [
        u("router", "web", "blue", "DATA ×4", ["HTTPS ↔, DNS, SSH", "seq 7312"], nfRow(1.22, "NetFlow/IPFIX flow (9): FlowSet 256, 4 flows", nfData1)),
        { type: "note", at: "web", text: "4 FLOWS DECODED", tone: "green" },
      ],
    },
    {
      title: "Lost Export Packet",
      desc: "A gap in the sequence",
      detail:
        "A minute later the active timeout exports the ongoing SSH session in two packets. The first is lost: UDP has no retransmission and NetFlow none of its own. The collector sees sequence 7314 right after 7312, counts one lost packet, and those 120 packets of traffic never appear in the reports.",
      facts: [
        ["Sent", "seq 7313 (lost), 7314"],
        ["Collector sees", "Gap of 1 packet"],
        ["Remedy", "Reliable transport: SCTP/TCP in IPFIX"],
      ],
      events: [
        u("router", "web", "blue", "DATA", ["SSH, laptop → server", "seq 7313"], nfRow(61.2, "NetFlow/IPFIX flow (9): FlowSet 256, 1 flow", nfData2), { lost: !0 }),
        u("router", "web", "blue", "DATA", ["SSH, server → laptop", "seq 7314"], nfRow(61.22, "NetFlow/IPFIX flow (9): FlowSet 256, 1 flow", nfData3)),
        { type: "note", at: "web", text: "SEQUENCE GAP: 1 LOST", tone: "amber" },
      ],
    },
    {
      title: "Template Refresh",
      desc: "Collectors may restart",
      detail:
        "If the collector restarts, it forgets the templates and can only drop data FlowSets it can’t parse. So exporters resend templates on a schedule, for example every 20 packets or every few minutes, and after that the collector decodes everything again.",
      facts: [
        ["Resend", "Every 20 packets or 30 min"],
        ["Without it", "Data can’t be decoded"],
        ["Same", "Template ID 256"],
      ],
      events: [
        { type: "note", at: "web", text: "COLLECTOR RESTARTED", tone: "amber" },
        u("router", "web", "teal", "TEMPLATE", ["ID 256 again"], nfRow(90, "NetFlow/IPFIX flow (9): FlowSet 0 (Template ID 256)", { ...nfTpl, uptime: 1330000, unix: NF_UNIX + 90, unixLabel: "1", seq: 7315 })),
        { type: "note", at: "web", text: "TEMPLATE 256 STORED", tone: "green" },
      ],
    },
  ],
};

// ---------- Syslog lessons ----------
const SYS_SRV = "203.0.113.60";
const sysUdpRow = (time, src, sport, msg, info) => ({
  time: N(time),
  src,
  dst: SYS_SRV,
  proto: "Syslog",
  info,
  len: `${Me + De + 8 + sysSize({ message: msg })} B`,
  wire: { udp: { sport, dport: 514, data: { syslog: { message: msg } } } },
});
const sysRouterInfo = (m) => `${sysFacilities[m.pri >> 3]}.${sysSeverities[m.pri & 7]}: ${m.msg}`;
const sysM1 = { format: "3164", pri: 190, ts: "Nov  8 16:20:01", host: "gw1", tag: "dhcpd[811]", msg: "DHCPACK on 192.168.1.10 to 00:00:5e:00:53:10 via lan0" };
const sysM2 = { format: "5424", pri: 14, ts: "2026-11-08T13:20:05.412Z", host: "laptop", app: "backup", procid: "3121", msgid: "JOB42", sd: '[job@32473 id="42" files="1832"]', msg: "Nightly backup finished in 312 s" };
const sysFail = (n, ts) => ({ format: "3164", pri: 84, ts, host: "gw1", tag: "sshd[2301]", msg: `Failed password for root from 192.0.2.66 port ${40110 + n} ssh2` });
const sysCrit = { format: "3164", pri: 82, ts: "Nov  8 16:21:42", host: "gw1", tag: "sshd[2301]", msg: "error: maximum authentication attempts exceeded for root from 192.0.2.66" };
const lessonSyslogUdp = {
  id: "syslog-udp",
  name: "Syslog/UDP",
  title: "Fire and Forget",
  layer: 7,
  nodes: ["client", "router", "internet", "web"],
  latency: { "client-router": 0.002, "router-web": 0.014, "client-web": 0.016 },
  labels: {
    router: ["Router gw1", "198.51.100.7"],
    web: ["Syslog Server", SYS_SRV],
  },
  legend: [
    ["amber", "From the router"],
    ["blue", "From the laptop"],
  ],
  overview: {
    full: "Syslog over UDP",
    description:
      "Syslog is the common way for routers, servers and applications to send log messages to a central server. Each message carries a priority (facility and severity), a timestamp, the host name and free text. The classic transport is UDP port 514: one message per datagram, no handshake and no acknowledgement.",
    facts: [
      ["Layer", "Application (Layer 7)"],
      ["Default Port", "UDP 514"],
      ["Transport", "UDP"],
      ["Formats", "RFC 3164 (BSD), RFC 5424"],
      ["Priority", "Facility × 8 + severity"],
      ["Defined In", "RFC 5424, RFC 5426"],
    ],
  },
  outro: {
    title: "Logs collected, mostly",
    desc: "Cheap, fast and lossy",
    text: "The router and the laptop sent their logs in both message formats, each as a single datagram. During a burst one message was lost, and neither side could know: UDP syslog has no acknowledgements. The server still raised an alert on the critical message. Press REPLAY to watch it again.",
    facts: [
      ["Messages", "7 sent, 6 stored"],
      ["Overhead", "8-byte UDP header, no handshake"],
      ["Lost", "1, silently"],
      ["For reliability", "Syslog over TCP or TLS"],
    ],
  },
  start: { nodes: ["client"], frame: "client" },
  steps: [
    {
      title: "Priority: Facility and Severity",
      desc: "One number says who and how bad",
      detail:
        "Every syslog message starts with a priority in angle brackets: facility × 8 + severity. The facility names the source (kern, auth, daemon, local0–local7), the severity runs from 0 emerg to 7 debug. So <190> is local7 (23 × 8 = 184) plus info (6).",
      facts: [
        ["<190>", "local7.info"],
        ["<84>", "authpriv.warning"],
        ["<82>", "authpriv.crit"],
      ],
      events: [
        { type: "show", nodes: ["router", "internet", "web"], frame: "path" },
        { type: "note", at: "web", text: "LISTENING ON UDP 514", tone: "teal" },
      ],
    },
    {
      title: "BSD Format (RFC 3164)",
      desc: "The router’s DHCP log",
      detail:
        "The router logs that it gave the laptop an address. It uses the old BSD format: priority, a timestamp without year or time zone, the host name and a tag with the program name, then the text. One message, one UDP datagram.",
      facts: [
        ["PRI", "190 = local7.info"],
        ["Host, tag", "gw1, dhcpd[811]"],
        ["From", "198.51.100.7 → 203.0.113.60:514"],
      ],
      events: [
        u("router", "web", "amber", "<190> DHCPACK", ["local7.info", "gw1 dhcpd[811]"], sysUdpRow(0, Ts, 514, sysM1, sysRouterInfo(sysM1))),
        { type: "note", at: "web", text: "STORED", tone: "green" },
      ],
    },
    {
      title: "Structured Format (RFC 5424)",
      desc: "The laptop’s backup job",
      detail:
        "A backup program on the laptop logs in the modern format: version 1, an ISO 8601 timestamp with milliseconds and time zone, app name, process ID, message ID and structured data, machine-readable key=value pairs in square brackets.",
      facts: [
        ["PRI", "14 = user.info"],
        ["App, msgid", "backup, JOB42"],
        ["Structured data", 'job@32473 id="42" files="1832"'],
      ],
      events: [
        u("client", "web", "blue", "<14> BACKUP DONE", ["RFC 5424", "[job@32473 …]"], sysUdpRow(4.2, f, 51514, sysM2, sysRouterInfo(sysM2))),
        { type: "note", at: "web", text: "STORED", tone: "green" },
      ],
    },
    {
      title: "Burst and Silent Loss",
      desc: "Nobody notices a missing message",
      detail:
        "Someone is guessing the router’s SSH password. It logs every failure, four messages within two seconds. The second one is dropped on the way. There is no acknowledgement and no sequence number, so neither the router nor the server knows it is missing.",
      facts: [
        ["Sent", "3 × authpriv.warning, 1 × crit"],
        ["Lost", "1 (port 40112)"],
        ["Detected", "Never"],
      ],
      events: [
        {
          type: "stream",
          from: "router",
          to: "web",
          color: "amber",
          label: "4 MESSAGES",
          payload: ["Failed password ×3", "the second is lost"],
          packets: [
            u("router", "web", "amber", "<84>", [], sysUdpRow(98.1, Ts, 514, sysFail(1, "Nov  8 16:21:40"), sysRouterInfo(sysFail(1)))),
            u("router", "web", "amber", "<84>", [], sysUdpRow(98.6, Ts, 514, sysFail(2, "Nov  8 16:21:41"), sysRouterInfo(sysFail(2))), { lost: !0 }),
            u("router", "web", "amber", "<84>", [], sysUdpRow(99.2, Ts, 514, sysFail(3, "Nov  8 16:21:41"), sysRouterInfo(sysFail(3)))),
            u("router", "web", "amber", "<82>", [], sysUdpRow(99.9, Ts, 514, sysCrit, sysRouterInfo(sysCrit))),
          ],
        },
        { type: "note", at: "internet", text: "1 MESSAGE LOST", tone: "amber" },
      ],
    },
    {
      title: "Filtering by Severity",
      desc: "Critical messages raise an alert",
      detail:
        "The server files messages by facility and severity. A rule such as authpriv.crit and above sends an alert to the on-call engineer. The <82> message matches; the warnings are only stored. A real server would also count the gap only if the messages had numbers, which UDP syslog doesn’t have.",
      facts: [
        ["Rule", "authpriv.crit → alert"],
        ["Matched", "<82> max auth attempts"],
        ["Stored", "6 of 7 messages"],
      ],
      events: [
        { type: "camera", frame: "path" },
        { type: "note", at: "web", text: "ALERT: SSH BRUTE FORCE ON GW1", tone: "green" },
      ],
    },
  ],
};

const SYS_CONN = $e(Ts, 41514, SYS_SRV, 514);
const sysT1 = { format: "5424", pri: 86, ts: "2026-11-08T13:22:10.004Z", host: "gw1", app: "sshd", procid: "2301", msg: "Accepted publickey for admin from 192.168.1.10 port 50312 ssh2" };
const sysT2 = { format: "5424", pri: 30, ts: "2026-11-08T13:22:10.120Z", host: "gw1", app: "dnsmasq", procid: "915", msg: "query[A] www.example.com from 192.168.1.10" };
const sysT3 = { format: "5424", pri: 28, ts: "2026-11-08T13:22:31.870Z", host: "gw1", app: "firewall", procid: "1024", msgid: "DROP", sd: '[fw@32473 src="192.0.2.66" dport="23"]', msg: "Dropped inbound telnet" };
const sysBatch = { octet: !0, messages: [sysT1, sysT2] };
const sysSingle = { octet: !0, messages: [sysT3] };
const sysB1 = sysSize(sysBatch), sysB2 = sysSize(sysSingle);
const sysTcpRow = (time, from, info, len, wire, proto = "Syslog") => ({ time: N(time), src: from, dst: from === Ts ? SYS_SRV : Ts, proto, info, len: `${len} B`, wire });
const lessonSyslogTcp = {
  id: "syslog-tcp",
  name: "Syslog/TCP",
  title: "Reliable Log Streams",
  layer: 7,
  nodes: ["client", "router", "internet", "web"],
  latency: { "client-router": 0.002, "router-web": 0.014, "client-web": 0.016 },
  labels: {
    router: ["Router gw1", "198.51.100.7"],
    web: ["Syslog Server", SYS_SRV],
  },
  legend: [
    ["green", "TCP"],
    ["amber", "Syslog messages"],
    ["violet", "ACK from server"],
  ],
  overview: {
    full: "Syslog over TCP",
    description:
      "Over TCP, syslog becomes a stream: the sender opens one connection and writes message after message. TCP acknowledges and resends lost data, so nothing disappears silently. Because a stream has no message boundaries, each message is prefixed with its length in bytes (octet counting).",
    facts: [
      ["Layer", "Application (Layer 7)"],
      ["Default Port", "TCP 514 (6514 with TLS)"],
      ["Transport", "TCP"],
      ["Framing", "Octet counting or newline"],
      ["Format", "RFC 5424"],
      ["Defined In", "RFC 6587, RFC 5425 (TLS)"],
    ],
  },
  outro: {
    title: "Every message delivered",
    desc: "Ordered, acknowledged, resent when lost",
    text: "The router opened a TCP connection to the log server, sent two messages in one segment framed by their byte counts, and when a segment was lost TCP resent it, so the server received every message in order. In production the same stream usually runs inside TLS on port 6514. Press REPLAY to watch it again.",
    facts: [
      ["Messages", "3 sent, 3 stored"],
      ["Retransmissions", "1, by TCP"],
      ["Framing", "Length prefix per message"],
      ["Secure variant", "TLS, TCP 6514 (RFC 5425)"],
    ],
  },
  start: { nodes: ["client"], frame: "client" },
  steps: [
    {
      title: "TCP Connection",
      desc: "Open the log stream once",
      detail:
        "The router’s syslog daemon (rsyslog) opens a TCP connection to the server’s port 514 with the usual three-way handshake. The connection stays open, and messages are written into it as they happen.",
      facts: [
        ["Server", `${SYS_SRV}:514`],
        ["Client port", "41514"],
        ["Handshake", "SYN → SYN-ACK → ACK"],
      ],
      events: [
        { type: "show", nodes: ["router", "internet", "web"], frame: "path" },
        ...Je({ from: "router", to: "web", src: Ts, dst: SYS_SRV, sport: 41514, dport: 514, t: [0, 0.028, 0.056], quick: !1, linux: !0 }),
      ],
    },
    {
      title: "Octet-Counted Messages",
      desc: "Two messages, one segment",
      detail:
        "Two log lines are ready at once, so they travel in the same TCP segment. Each starts with its length in bytes and a space, then the message itself. The server reads the number, takes exactly that many bytes, and knows where the next message starts, even if a message contains a newline.",
      facts: [
        ["Messages", "authpriv.info, daemon.info"],
        ["Framing", "“LEN ” + message"],
        ["Segment", `${sysB1} bytes of syslog`],
      ],
      events: [
        u("router", "web", "amber", "2 MESSAGES", ["sshd: Accepted publickey", "dnsmasq: query[A]"], sysTcpRow(0.06, Ts, `41514 → 514 [PSH, ACK] Seq=1 Ack=1 Len=${sysB1}`, be(sysB1 + 12), O(SYS_CONN, Ts, "PA", { syslog: sysBatch }))),
        u("web", "router", "violet", "ACK", [`ack=${sysB1 + 1}`], sysTcpRow(0.088, SYS_SRV, `514 → 41514 [ACK] Seq=1 Ack=${sysB1 + 1}`, 66, O(SYS_CONN, SYS_SRV, "A"), "TCP"), { quick: !0 }),
        { type: "note", at: "web", text: "2 MESSAGES STORED", tone: "green" },
      ],
    },
    {
      title: "Lost Segment",
      desc: "TCP notices what UDP couldn’t",
      detail:
        "The firewall logs a dropped telnet attempt. The segment is lost on the way, so no ACK comes back. The router keeps the bytes in its send buffer and starts the retransmission timer instead of forgetting them.",
      facts: [
        ["Message", "daemon.warning, firewall DROP"],
        ["Bytes in flight", `${sysB2}`],
        ["Waiting for", `ACK ${sysB1 + sysB2 + 1}`],
      ],
      events: [
        u("router", "web", "amber", "FIREWALL DROP", ["<28> telnet blocked"], sysTcpRow(21.8, Ts, `41514 → 514 [PSH, ACK] Seq=${sysB1 + 1} Ack=1 Len=${sysB2}`, be(sysB2 + 12), O(SYS_CONN, Ts, "PA", { syslog: sysSingle })), { lost: !0 }),
        { type: "note", at: "router", text: "NO ACK: RTO TIMER RUNNING", tone: "amber" },
      ],
    },
    {
      title: "Retransmission",
      desc: "Same bytes, sent again",
      detail:
        "About 200 ms later the timer fires and TCP resends the same bytes with the same sequence number. This time they arrive; the server ACKs all of them, and the message is stored in order after the previous two.",
      facts: [
        ["Timer", "RTO ≈ 200 ms"],
        ["Resent", `Seq ${sysB1 + 1}, ${sysB2} bytes`],
        ["Result", "No log lost"],
      ],
      events: [
        u("router", "web", "amber", "RESEND", ["same Seq, same bytes"], sysTcpRow(22.01, Ts, `[TCP Retransmission] 41514 → 514 [PSH, ACK] Seq=${sysB1 + 1} Ack=1 Len=${sysB2}`, be(sysB2 + 12), O(SYS_CONN, Ts, "PA", { syslog: sysSingle }, { seq: sysB1 + 1 }))),
        u("web", "router", "violet", "ACK", [`ack=${sysB1 + sysB2 + 1}`], sysTcpRow(22.038, SYS_SRV, `514 → 41514 [ACK] Seq=1 Ack=${sysB1 + sysB2 + 1}`, 66, O(SYS_CONN, SYS_SRV, "A"), "TCP"), { quick: !0 }),
        { type: "note", at: "web", text: "STORED, IN ORDER", tone: "green" },
      ],
    },
  ],
};
