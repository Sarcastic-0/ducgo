// ducgo packet sniffer - per-OS capture backends, shared local analysis.
//   windows: inbox pktmon (ETL -> etl2txt UTF-16 text, deleted after parse)
//   linux:   tcpdump or dumpcap (pcap file -> `tcpdump -n -l -v -r` text read
//            back in-memory, parsed directly; pcap deleted after parse)
//   darwin:  system tcpdump (same pcap -> text path as Linux)
// Capture needs privilege (Administrator on Windows, sudo/root on
// Linux/macOS). Parsing needs none. Every spawned OS command is
// timeout-guarded. Only the tool data dir is written.
// The analyzer (analyze/summarizeCapture) is backend-agnostic and untouched.
import { spawnSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { platform as detectPlatform, isAdmin as platformIsAdmin, hasCmd } from './platform.js';

export const SNIFF_SPAWN_TIMEOUT_MS = 15000;
export const HIGH_INTEGRITY_SID = 'S-1-16-12288';

// Detection thresholds (exported so tests pin them).
export const T = {
  SCAN_PORTS: 15, // one src -> N distinct dst ports (TCP)
  SCAN_SYNS: 10, // unanswered SYNs from one src
  SWEEP_IPS: 20, // one src -> N distinct dst IPs
  FLOOD_PACKETS: 1000, // one flow -> N packets in a window
  FLOOD_BYTES: 50 * 1024 * 1024, // one flow -> N bytes in a window
  DNS_SUBDOMAINS: 30, // distinct subdomains under one parent
  DNS_NAME_LEN: 60, // single query name longer than this
  ARP_STORM: 25, // who-has for one IP more than this
};

export function pktmonExe() {
  const p = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'PktMon.exe');
  try {
    return fs.existsSync(p) ? p : null;
  } catch {
    return null;
  }
}

export function isAdmin(plat = detectPlatform()) {
  if (plat === 'windows') {
    try {
      const r = spawnSync('whoami', ['/groups'], { encoding: 'utf8', timeout: 8000, windowsHide: true });
      return r.status === 0 && String(r.stdout || '').includes(HIGH_INTEGRITY_SID);
    } catch {
      return false;
    }
  }
  return platformIsAdmin(plat);
}

function runPktmon(args, timeoutMs = SNIFF_SPAWN_TIMEOUT_MS) {
  const exe = pktmonExe();
  if (!exe) return { ok: false, stdout: '', stderr: '', error: 'PktMon.exe not found (needs Windows 10 1809+ / 11)' };
  try {
    const r = spawnSync(exe, args, { encoding: 'utf8', timeout: timeoutMs, windowsHide: true });
    if (r.error) return { ok: false, stdout: '', stderr: '', error: String(r.error.message || r.error) };
    if (r.status !== 0) {
      return { ok: false, stdout: String(r.stdout || ''), stderr: String(r.stderr || ''), error: `pktmon ${args[0]} exited ${r.status}` };
    }
    return { ok: true, stdout: String(r.stdout || ''), stderr: String(r.stderr || ''), error: '' };
  } catch (e) {
    return { ok: false, stdout: '', stderr: '', error: String((e && e.message) || e) };
  }
}

export function driverStatus(plat = detectPlatform()) {
  if (plat === 'windows') {
    const exe = pktmonExe();
    if (!exe) return { present: false, admin: false, platform: plat, backend: 'pktmon', exe: null, detail: 'PktMon.exe not found' };
    const admin = isAdmin(plat);
    const st = runPktmon(['status']);
    return { present: true, admin, platform: plat, backend: 'pktmon', exe, detail: admin ? (st.ok ? 'driver ready' : st.error) : 'needs an elevated (Administrator) terminal' };
  }
  const be = captureBackend(plat);
  const admin = isAdmin(plat);
  return {
    present: be.available, admin, platform: plat, backend: be.kind, exe: be.exe,
    detail: be.available
      ? (admin ? 'driver ready' : 'needs root - re-run with sudo')
      : be.detail,
  };
}

// ---------- POSIX capture backends (tcpdump / dumpcap) ----------
export const TCPDUMP_INSTALL_HINT_LINUX = 'install tcpdump: sudo apt install tcpdump (Debian/Ubuntu) / sudo dnf install tcpdump (Fedora) - or wireshark-cli for dumpcap';

// First capture tool on PATH for POSIX (tcpdump preferred, dumpcap fallback).
// Windows intentionally returns null here (pktmon path is separate).
export function findPacketExe(plat = detectPlatform()) {
  if (plat === 'windows') return null;
  if (hasCmd('tcpdump', plat)) return 'tcpdump';
  if (hasCmd('dumpcap', plat)) return 'dumpcap';
  return null;
}

// Backend descriptor for doctor/sysinfo/sniff-check + capture dispatch.
// Shape: { platform, kind, exe, available, needsRoot, installHint, detail }.
export function captureBackend(plat = detectPlatform()) {
  if (plat === 'windows') {
    const exe = pktmonExe();
    return {
      platform: plat, kind: 'pktmon', exe, available: !!exe, needsRoot: true,
      installHint: 'needs Windows 10 1809+ / 11 (PktMon.exe inbox)',
      detail: exe ? 'driver ready' : 'PktMon.exe not found (needs Windows 10 1809+ / 11)',
    };
  }
  if (plat === 'darwin') {
    const exe = findPacketExe(plat);
    return {
      platform: plat, kind: exe === 'dumpcap' ? 'dumpcap' : 'tcpdump', exe,
      available: !!exe, needsRoot: true,
      installHint: 'tcpdump ships with macOS; capture needs sudo (re-run with sudo)',
      detail: exe ? 'driver ready' : 'tcpdump not found on PATH (ships with macOS - check PATH)',
    };
  }
  const exe = findPacketExe(plat);
  return {
    platform: plat, kind: exe === 'dumpcap' ? 'dumpcap' : 'tcpdump', exe,
    available: !!exe, needsRoot: true,
    installHint: TCPDUMP_INSTALL_HINT_LINUX,
    detail: exe ? 'driver ready' : `no capture tool on PATH (${TCPDUMP_INSTALL_HINT_LINUX})`,
  };
}

export function startCapture(etlPath, pktSize = 0) {
  runPktmon(['stop']); // best-effort: clear any stale session
  return runPktmon(['start', '--capture', '--pkt-size', String(pktSize), '--file-name', etlPath]);
}

export function stopCapture() {
  return runPktmon(['stop']);
}

export function convertEtl(etlPath, txtPath) {
  return runPktmon(['etl2txt', etlPath, '--out', txtPath]);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// One capture window: start -> wait -> stop (always) -> convert.
export async function captureWindow({ etlPath, seconds, pktSize = 0 }) {
  const st = startCapture(etlPath, pktSize);
  if (!st.ok) return { ok: false, txtPath: null, error: st.error || st.stderr };
  try {
    await sleep(Math.max(1, seconds) * 1000);
  } finally {
    stopCapture();
  }
  const txtPath = etlPath.replace(/\.etl$/i, '.txt');
  const cv = convertEtl(etlPath, txtPath);
  if (!cv.ok) return { ok: false, txtPath: null, error: cv.error || cv.stderr || 'etl2txt failed' };
  return { ok: true, txtPath, error: '' };
}

// ---------- POSIX pcap capture (tcpdump / dumpcap) ----------
// Captures YOUR OWN machine's traffic on the default interface to a pcap
// file. Needs root (run with sudo). Loopback-only traffic is out of scope
// for the default interface - capture it manually (`tcpdump -i lo`) and
// parse the pcap with `tcpdump -n -l -v -r` + the same parser.
// Returns { ok, pcapPath|null, error } with clean guidance, never throws.
export async function capturePcapWindow({ pcapPath, seconds, snaplen = 0, exe = null, plat = detectPlatform() }) {
  const tool = exe || findPacketExe(plat);
  if (!tool) {
    const be = captureBackend(plat);
    return { ok: false, pcapPath: null, error: `No capture tool on PATH (${be.installHint})` };
  }
  const secs = Math.max(1, Math.floor(Number(seconds) || 0));
  const snap = String(snaplen === undefined || snaplen === null ? 0 : snaplen);
  try {
    fs.mkdirSync(path.dirname(pcapPath), { recursive: true });
  } catch (e) {
    return { ok: false, pcapPath: null, error: `Cannot create capture dir: ${String((e && e.message) || e).slice(0, 160)}` };
  }
  if (tool === 'dumpcap') {
    // dumpcap stops itself after the autostop duration.
    try {
      const r = spawnSync(tool, ['-i', 'any', '-a', `duration:${secs}`, '-s', snap, '-w', pcapPath],
        { encoding: 'utf8', timeout: (secs + 20) * 1000, windowsHide: true });
      if (r.error) return { ok: false, pcapPath: null, error: String(r.error.message || r.error).slice(0, 200) };
      if (!pcapOk(pcapPath)) {
        return { ok: false, pcapPath: null, error: dumpcapHint(String(r.stderr || ''), plat) };
      }
      return { ok: true, pcapPath, error: '' };
    } catch (e) {
      return { ok: false, pcapPath: null, error: String((e && e.message) || e).slice(0, 200) };
    }
  }
  // tcpdump: run detached, wait, SIGINT (flush + close pcap), SIGKILL fallback.
  let stderr = '';
  let child = null;
  try {
    child = spawn(tool, ['-n', '-U', '-s', snap, '-w', pcapPath], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (e) {
    return { ok: false, pcapPath: null, error: String((e && e.message) || e).slice(0, 200) };
  }
  try {
    if (child.stderr) child.stderr.on('data', (c) => { stderr += String(c); });
    child.on('error', () => {});
    await sleep(secs * 1000);
  } finally {
    try { child.kill('SIGINT'); } catch { /* ignore */ }
    await sleep(900);
    try { child.kill('SIGKILL'); } catch { /* ignore */ }
    await new Promise((res) => {
      let done = false;
      const fin = () => { if (!done) { done = true; res(); } };
      try { child.on('close', fin); child.on('exit', fin); } catch { fin(); }
      setTimeout(fin, 3000);
    });
  }
  if (!pcapOk(pcapPath)) {
    return { ok: false, pcapPath: null, error: tcpdumpHint(stderr, plat) };
  }
  return { ok: true, pcapPath, error: '' };
}

function pcapOk(pcapPath) {
  try {
    const st = fs.statSync(pcapPath);
    return st.isFile() && st.size > 24; // bigger than the bare pcap global header
  } catch {
    return false;
  }
}
function sudoHint(plat) {
  return plat === 'windows'
    ? 're-open the terminal as Administrator, then retry'
    : 're-run with sudo, e.g. sudo node src/cli.js sniff --duration 15';
}
function tcpdumpHint(stderr, plat) {
  const s = String(stderr || '');
  if (/permission|operation not permitted|denied|you don't have permission/i.test(s)) {
    return `tcpdump captured nothing (permission denied) - ${sudoHint(plat)}`;
  }
  if (/no such device|no suitable device|can't open|error/i.test(s)) {
    return `tcpdump captured nothing (${s.slice(0, 140) || 'no packets on the default interface'}) - ${sudoHint(plat)}`;
  }
  return `tcpdump captured nothing (no packets on the default interface in this window) - ${sudoHint(plat)}`;
}
function dumpcapHint(stderr, plat) {
  const s = String(stderr || '');
  if (/permission|denied|can't open/i.test(s)) {
    return `dumpcap captured nothing (permission denied) - ${sudoHint(plat)}`;
  }
  return `dumpcap captured nothing (${s.slice(0, 140) || 'no packets captured'}) - ${sudoHint(plat)}`;
}

// Convert a pcap file to text IN MEMORY (`tcpdump -n -l -v -r`) for the
// shared parser. No intermediate .txt file is written.
// Returns { ok, text, error }.
export function readPcapText(pcapPath, exe = null, plat = detectPlatform()) {
  const tool = exe || findPacketExe(plat) || 'tcpdump';
  try {
    const r = spawnSync(tool, ['-n', '-l', '-v', '-r', pcapPath],
      { encoding: 'utf8', timeout: SNIFF_SPAWN_TIMEOUT_MS, windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
    if (r.error) return { ok: false, text: '', error: String(r.error.message || r.error).slice(0, 200) };
    if (r.status !== 0) {
      return { ok: false, text: '', error: `${tool} -r exited ${r.status}: ${String(r.stderr || '').slice(0, 200)}` };
    }
    return { ok: true, text: String(r.stdout || ''), error: '' };
  } catch (e) {
    return { ok: false, text: '', error: String((e && e.message) || e).slice(0, 200) };
  }
}

// tcpdump `-n -l -v` stdout shares the IPv4 `a.b.c.d.port > e.f.g.h.port:`
// line shapes (plus `A? name` DNS with -v) with etl2txt, so it flows through
// the same parser and the shared analyze() is reused untouched.
export function parseTcpdumpText(text) {
  return parseEtlText(text);
}

// etl2txt writes UTF-16 LE (BOM FFFE). Node must decode it explicitly -
// reading it as UTF-8 yields NUL-separated text no regex can match.
export function readEtlText(txtPath) {
  const buf = fs.readFileSync(txtPath);
  let text = buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe ? buf.toString('utf16le') : buf.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text;
}

// Wrapped lines (not starting a new "[..].." event) belong to the previous event.
// tcpdump (`-n -l -v`) lines start with a `HH:MM:SS.micro` timestamp and are
// likewise joined with their indented continuations. ETL matching is first,
// so Windows parsing is byte-identical.
export function joinWrappedLines(text) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    if (/^\s*\[[0-9A-Fa-f]{2}\]/.test(raw)) out.push(raw.trim());
    else if (/^\d{1,2}:\d{2}:\d{2}(\.\d+)?\s/.test(raw.trim())) out.push(raw.trim());
    else if (raw.trim() !== '' && out.length > 0) out[out.length - 1] += ' ' + raw.trim();
  }
  return out;
}

const RE_TCP = /(\d{1,3}(?:\.\d{1,3}){3})\.(\d+) > (\d{1,3}(?:\.\d{1,3}){3})\.(\d+): Flags \[([^\]]*)\]/;
const RE_FLOW = /(\d{1,3}(?:\.\d{1,3}){3})\.(\d+) > (\d{1,3}(?:\.\d{1,3}){3})\.(\d+):/;
const RE_SIZE = /OriginalSize (\d+)/;
const RE_DIR = /Direction (Rx|Tx)/;
const RE_DNS_Q = /\b(A|AAAA|MX|TXT|NS|CNAME|PTR|SOA|SRV)\? ([A-Za-z0-9_.*-]+\.?)/;
const RE_ARP_REQ = /who-has (\S+) tell/;
const RE_ARP_REP = /Reply (\S+) is-at (\S+)/;
const RE_HTTP_REQ = /\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S{1,300}) HTTP\/[\d.]+/;
const RE_HOST = /Host: (\S+)/;
const RE_BASIC = /Authorization: Basic (\S+)/;
const RE_PASSWD = /(password|passwd|pwd)=([^&\s]{1,80})/i;

export function isPrivateIp(ip) {
  const m = String(ip).split('.').map(Number);
  if (m.length !== 4 || m.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  if (m[0] === 10 || m[0] === 127) return true;
  if (m[0] === 172 && m[1] >= 16 && m[1] <= 31) return true;
  if (m[0] === 192 && m[1] === 168) return true;
  if (m[0] === 169 && m[1] === 254) return true;
  return false;
}

export function parentDomain(name) {
  const parts = String(name || '').replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return String(name || '').toLowerCase();
  return parts.slice(-2).join('.');
}

export function labelEntropy(s) {
  const str = String(s || '');
  if (str.length === 0) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function parseEtlText(text) {
  const events = joinWrappedLines(text);
  const flows = new Map(); // key -> {sip,sport,dip,dport,proto,packets,bytes,rx,tx,syns}
  const dns = new Map(); // name -> {count, qtypes:Set, dstPorts:Set}
  const arpReq = new Map(); // ip -> {count, tellers:Set}
  const arpRep = new Map(); // ip -> Set(mac)
  const http = []; // {flow, method, target, host}
  const basics = []; // {flow}
  let packets = 0;
  let tcp = 0;
  let udp = 0;
  let dirRx = 0;
  let dirTx = 0;

  const flowKey = (sip, sport, dip, dport, proto) => `${sip}:${sport}>${dip}:${dport}/${proto}`;
  const touchFlow = (sip, sport, dip, dport, proto, bytes, dir, syn) => {
    const k = flowKey(sip, sport, dip, dport, proto);
    let f = flows.get(k);
    if (!f) {
      f = { key: k, sip, sport, dip, dport, proto, packets: 0, bytes: 0, rx: 0, tx: 0, syns: 0 };
      flows.set(k, f);
    }
    f.packets += 1;
    f.bytes += bytes;
    if (dir === 'Rx') f.rx += 1;
    else if (dir === 'Tx') f.tx += 1;
    if (syn) f.syns += 1;
    return f;
  };

  for (const ev of events) {
    const dirM = ev.match(RE_DIR);
    const dir = dirM ? dirM[1] : null;
    if (dir === 'Rx') dirRx += 1;
    else if (dir === 'Tx') dirTx += 1;
    const sizeM = ev.match(RE_SIZE);
    // tcpdump lines carry `length N` instead of `OriginalSize N` - used only
    // as a fallback so ETL byte accounting is byte-identical.
    const lenM = sizeM ? null : ev.match(/[, ]length (\d+)/);
    const bytes = sizeM ? Number(sizeM[1]) || 0 : lenM ? Number(lenM[1]) || 0 : 0;

    const tm = ev.match(RE_TCP);
    if (tm) {
      packets += 1;
      tcp += 1;
      const flags = tm[5] || '';
      const synOnly = flags === 'S';
      touchFlow(tm[1], Number(tm[2]), tm[3], Number(tm[4]), 'tcp', bytes, dir, synOnly);
    } else {
      const fm = ev.match(RE_FLOW);
      if (fm && /UDP, length \d+/.test(ev)) {
        packets += 1;
        udp += 1;
        touchFlow(fm[1], Number(fm[2]), fm[3], Number(fm[4]), 'udp', bytes, dir, false);
      }
    }

    const dq = ev.match(RE_DNS_Q);
    if (dq) {
      const name = dq[2].toLowerCase();
      let d = dns.get(name);
      if (!d) {
        d = { name, count: 0, qtypes: new Set(), dstPorts: new Set() };
        dns.set(name, d);
      }
      d.count += 1;
      d.qtypes.add(dq[1]);
      const fm2 = ev.match(RE_FLOW);
      if (fm2) d.dstPorts.add(Number(fm2[4]));
    }

    const ar = ev.match(RE_ARP_REQ);
    if (ar) {
      const ip = ar[1].replace(/,$/, '');
      let a = arpReq.get(ip);
      if (!a) {
        a = { ip, count: 0, tellers: new Set() };
        arpReq.set(ip, a);
      }
      a.count += 1;
      const tellM = ev.match(/tell (\S+)/);
      if (tellM) a.tellers.add(tellM[1].replace(/,$/, ''));
    }
    const ap = ev.match(RE_ARP_REP);
    if (ap) {
      const ip = ap[1];
      let s = arpRep.get(ip);
      if (!s) {
        s = new Set();
        arpRep.set(ip, s);
      }
      s.add(ap[2].replace(/,$/, ''));
    }

    const hq = ev.match(RE_HTTP_REQ);
    if (hq) {
      const fm3 = ev.match(RE_FLOW);
      const hostM = ev.match(RE_HOST);
      http.push({
        flow: fm3 ? `${fm3[1]}:${fm3[2]}>${fm3[3]}:${fm3[4]}` : '?',
        method: hq[1],
        target: hq[2],
        host: hostM ? hostM[1] : '',
      });
    }
    if (RE_BASIC.test(ev)) {
      const fm4 = ev.match(RE_FLOW);
      basics.push({ flow: fm4 ? `${fm4[1]}:${fm4[2]}>${fm4[3]}:${fm4[4]}` : '?' });
    }
    const pm = ev.match(RE_PASSWD);
    if (pm && /GET|POST/i.test(ev)) {
      const fm5 = ev.match(RE_FLOW);
      basics.push({ flow: fm5 ? `${fm5[1]}:${fm5[2]}>${fm5[3]}:${fm5[4]}` : '?', field: pm[1] });
    }
  }

  return { packets, tcp, udp, dirRx, dirTx, flows, dns, arpReq, arpRep, http, basics };
}

// ---------- anomaly analysis (pure, fully testable) ----------

export function analyze(parsed) {
  const anomalies = [];
  const add = (severity, title, detail) => anomalies.push({ severity, title, detail });
  const bySrcPorts = new Map(); // sip -> {ports:Set, syns, total, ips:Set}
  const extIps = new Set();

  for (const f of parsed.flows.values()) {
    let s = bySrcPorts.get(f.sip);
    if (!s) {
      s = { ports: new Set(), syns: 0, total: 0, ips: new Set() };
      bySrcPorts.set(f.sip, s);
    }
    if (f.proto === 'tcp') s.ports.add(f.dport);
    s.syns += f.syns;
    s.total += f.packets;
    s.ips.add(f.dip);
    if (!isPrivateIp(f.dip)) extIps.add(f.dip);
    if (f.packets >= T.FLOOD_PACKETS || f.bytes >= T.FLOOD_BYTES) {
      add('medium', 'heavy flow', `${f.key} moved ${f.packets} packets / ${(f.bytes / 1048576).toFixed(1)} MB in one window`);
    }
  }

  for (const [sip, s] of bySrcPorts) {
    if (s.ports.size >= T.SCAN_PORTS) {
      add('high', 'possible port scan', `${sip} touched ${s.ports.size} distinct TCP ports`);
    }
    if (s.syns >= T.SCAN_SYNS && s.syns >= Math.max(1, s.total / 3)) {
      add('high', 'possible SYN scan', `${sip} sent ${s.syns} unanswered SYNs`);
    }
    if (s.ips.size >= T.SWEEP_IPS) {
      add('high', 'possible network sweep', `${sip} contacted ${s.ips.size} distinct IPs`);
    }
  }

  const byParent = new Map(); // parent -> Set(sub)
  for (const d of parsed.dns.values()) {
    const parent = parentDomain(d.name);
    let s = byParent.get(parent);
    if (!s) {
      s = new Set();
      byParent.set(parent, s);
    }
    s.add(d.name);
    if (d.name.replace(/\.$/, '').length > T.DNS_NAME_LEN) {
      add('high', 'possible DNS tunneling', `over-long query: ${d.name.slice(0, 80)} (${d.count}x)`);
    } else {
      const labels = d.name.replace(/\.$/, '').split('.');
      const longest = labels.reduce((a, b) => (a.length >= b.length ? a : b), '');
      if (longest.length > 30 && labelEntropy(longest) > 4.0) {
        add('high', 'possible DNS tunneling', `high-entropy label in ${d.name.slice(0, 80)} (${d.count}x)`);
      }
    }
    for (const p of d.dstPorts) {
      if (p !== 53) add('medium', 'DNS on odd port', `${d.name} queried over port ${p}`);
    }
  }
  for (const [parent, subs] of byParent) {
    if (subs.size >= T.DNS_SUBDOMAINS) {
      add('high', 'possible DNS tunneling', `${subs.size} distinct subdomains under ${parent}`);
    }
  }

  for (const [ip, macs] of parsed.arpRep) {
    if (macs.size >= 2) {
      add('high', 'possible ARP spoofing', `${ip} claimed by ${macs.size} MACs (${Array.from(macs).slice(0, 4).join(', ')})`);
    }
  }
  for (const a of parsed.arpReq.values()) {
    if (a.count >= T.ARP_STORM) {
      add('medium', 'ARP storm', `${a.count} who-has requests for ${a.ip}`);
    }
  }

  for (const b of parsed.basics) {
    add('high', 'cleartext credential on the wire', `HTTP auth material in flow ${b.flow}${b.field ? ` (field ${b.field}=...)` : ''} - value NOT stored`);
  }

  const order = { high: 0, medium: 1, low: 2 };
  anomalies.sort((a, b) => (order[a.severity] ?? 2) - (order[b.severity] ?? 2));
  return { anomalies, extContacts: extIps.size };
}

export function summarizeCapture(parsed, { seconds = 0, etlPath = '', kept = false } = {}) {
  const flows = Array.from(parsed.flows.values()).sort((a, b) => b.bytes - a.bytes);
  const { anomalies, extContacts } = analyze(parsed);
  const dnsList = Array.from(parsed.dns.values())
    .map((d) => ({ name: d.name, count: d.count, qtypes: Array.from(d.qtypes), ports: Array.from(d.dstPorts) }))
    .sort((a, b) => b.count - a.count);
  return {
    id: `cap-${Date.now().toString(36)}`,
    time: new Date().toISOString(),
    seconds,
    etlPath: kept ? etlPath : '',
    packets: parsed.packets,
    tcp: parsed.tcp,
    udp: parsed.udp,
    rx: parsed.dirRx,
    tx: parsed.dirTx,
    flows: flows.length,
    extContacts,
    dnsQueries: dnsList.reduce((a, d) => a + d.count, 0),
    dnsNames: dnsList.length,
    topFlows: flows.slice(0, 25).map((f) => ({ key: f.key, packets: f.packets, bytes: f.bytes })),
    dnsTop: dnsList.slice(0, 50),
    anomalies: anomalies.slice(0, 50),
    highs: anomalies.filter((a) => a.severity === 'high').length,
    mediums: anomalies.filter((a) => a.severity === 'medium').length,
  };
}

// ---------- capture summaries store (bounded) ----------

const MAX_CAPTURES = 20;

export function capturesPath(dataDir) {
  return path.join(dataDir, 'captures.jsonl');
}

export function saveCaptureSummary(dataDir, summary) {
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    const p = capturesPath(dataDir);
    let lines = [];
    try {
      lines = fs.readFileSync(p, 'utf8').split('\n').filter((l) => l.trim() !== '');
    } catch {
      lines = [];
    }
    lines.push(JSON.stringify(summary));
    while (lines.length > MAX_CAPTURES) lines.shift();
    fs.writeFileSync(p, lines.join('\n') + '\n', 'utf8');
    return true;
  } catch {
    return false;
  }
}

export function readLastCapture(dataDir) {
  try {
    const lines = fs.readFileSync(capturesPath(dataDir), 'utf8').split('\n').filter((l) => l.trim() !== '');
    if (lines.length === 0) return null;
    return JSON.parse(lines[lines.length - 1]);
  } catch {
    return null;
  }
}

export function capturesDir(dataDir) {
  return path.join(dataDir, 'captures');
}
