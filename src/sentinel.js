// ducgo v3 - network sentinel (proactive, honest, stdlib-only).
// Read-only Windows queries via child_process + parsing. No packet capture:
// real sniffing needs a companion such as Npcap / Wireshark (documented in
// README). This module never modifies system state - it only reads OS tables
// and writes baselines under the tool data dir (MIRAGENET_DIR).
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as net from 'node:net';
import * as dns from 'node:dns';
import { spawnSync } from 'node:child_process';

export const SENTINEL_VERSION = '3.0.4';
export const CMD_TIMEOUT_MS = 8000;
export const DNS_HOSTS = ['example.com', 'github.com', 'microsoft.com', 'cloudflare-dns.com'];
export const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 18080, 2222, 2323];

export function baselinePath(dataDir) {
  return path.join(dataDir, 'sentinel-baseline.json');
}
export function integrityPath(dataDir) {
  return path.join(dataDir, 'integrity.json');
}

// ---------- generic OS runner (read-only, timeout, clean errors) ----------
export function runOs(cmd, args = [], timeoutMs = CMD_TIMEOUT_MS) {
  try {
    const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: timeoutMs, windowsHide: true, shell: false });
    if (r.error) {
      const msg = String((r.error && r.error.message) || r.error);
      if (String(r.error.code || '').includes('TIMEDOUT') || /timed out/i.test(msg)) {
        return { ok: false, stdout: '', stderr: '', timedOut: true, error: `Timed out after ${timeoutMs}ms: ${cmd}` };
      }
      return { ok: false, stdout: '', stderr: '', timedOut: false, error: `${cmd} failed: ${msg.slice(0, 200)}` };
    }
    if (typeof r.status === 'number' && r.status !== 0 && !String(r.stdout || '').trim()) {
      return { ok: false, stdout: String(r.stdout || ''), stderr: String(r.stderr || ''), timedOut: false, error: `${cmd} exited ${r.status}: ${String(r.stderr || '').slice(0, 200)}` };
    }
    return { ok: true, stdout: String(r.stdout || ''), stderr: String(r.stderr || ''), timedOut: false, error: '' };
  } catch (e) {
    return { ok: false, stdout: '', stderr: '', timedOut: false, error: `${cmd} failed: ${String((e && e.message) || e).slice(0, 200)}` };
  }
}

// ---------- MAC normalize ----------
export function normalizeMac(mac) {
  return String(mac || '').trim().toLowerCase().replace(/-/g, ':');
}

// ---------- netstat parser ----------
// Handles Windows `netstat -ano` tables (TCP + UDP, IPv4/IPv6).
// Returns { listeners: [{proto, local, port, pid}], conns: [{proto, local, remote, remoteIp, remotePort, state, pid}] }.
export function parseNetstat(text) {
  const listeners = [];
  const conns = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    if (/^active connections/i.test(line)) continue;
    if (/^proto\b/i.test(line)) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 3) continue;
    const proto = parts[0].toUpperCase();
    if (proto !== 'TCP' && proto !== 'UDP') continue;
    const local = parts[1] || '';
    const foreign = parts[2] || '';
    let state = '';
    let pid = '';
    if (proto === 'TCP') {
      state = (parts[3] || '').toUpperCase();
      pid = parts[4] || '';
    } else {
      // UDP has no STATE column: PID is parts[3] (or parts[4] on some builds).
      pid = parts[3] || '';
      if (pid && !/^\d+$/.test(pid) && parts[4] && /^\d+$/.test(parts[4])) pid = parts[4];
      state = '';
    }
    const port = extractPort(local);
    const isListening = state === 'LISTENING' || (proto === 'UDP' && (foreign === '*:*' || foreign === '*'));
    if (isListening) {
      listeners.push({ proto, local, port, pid: /^\d+$/.test(pid) ? Number(pid) : 0 });
    } else if (proto === 'TCP') {
      const rp = extractPort(foreign);
      const rip = extractIp(foreign);
      conns.push({
        proto, local, remote: foreign, remoteIp: rip, remotePort: rp,
        state: state || 'UNKNOWN', pid: /^\d+$/.test(pid) ? Number(pid) : 0,
      });
    }
  }
  return { listeners, conns };
}

function extractPort(addr) {
  const s = String(addr || '');
  if (s === '*:*' || s === '*') return 0;
  // Strip brackets for IPv6 like [::]:80
  const m = s.match(/:(\d+)$/);
  if (!m) return 0;
  const n = Number(m[1]);
  return Number.isInteger(n) ? n : 0;
}
function extractIp(addr) {
  const s = String(addr || '');
  if (s === '*:*' || s === '*') return '*';
  const idx = s.lastIndexOf(':');
  if (idx === -1) return s;
  let host = s.slice(0, idx);
  host = host.replace(/^\[(.*)\]$/, '$1');
  return host || '*';
}

// ---------- arp parser ----------
// Parses Windows `arp -a` (one or more interfaces).
// Returns [{ ip, mac, type, iface }]. MACs kept raw + normalized compare helper.
export function parseArp(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  let iface = '';
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const ifm = raw.match(/Interface:\s*([0-9a-fA-F.\-:]+)/);
    if (ifm) { iface = ifm[1]; continue; }
    if (/^internet address/i.test(line)) continue;
    if (/^interface:/i.test(line)) continue;
    // Match: IP + MAC (dash or colon) + type
    const m = line.match(/(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})\s+(\S+)/);
    if (m) {
      out.push({ ip: m[1], mac: m[2].toLowerCase(), type: m[3].toLowerCase(), iface });
    }
  }
  return out;
}

// Diff two arp maps (plain objects ip->mac raw). MAC compare normalized.
export function diffArp(baselineMap, currentList) {
  const base = baselineMap || {};
  const cur = {};
  for (const e of currentList || []) cur[e.ip] = e.mac;
  const added = [];
  const changed = [];
  const gone = [];
  for (const [ip, mac] of Object.entries(cur)) {
    if (!(ip in base)) added.push({ ip, mac });
    else if (normalizeMac(base[ip]) !== normalizeMac(mac)) {
      changed.push({ ip, oldMac: base[ip], newMac: mac });
    }
  }
  for (const ip of Object.keys(base)) {
    if (!(ip in cur)) gone.push({ ip, oldMac: base[ip] });
  }
  return { added, changed, gone };
}

// ---------- tasklist parser ----------
// Parses `tasklist /FO CSV /NH` into Map(pid -> image name).
export function parseTasklist(text) {
  const map = new Map();
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    // CSV: "name","pid",...
    const fields = [];
    const re = /"([^"]*)"|([^,]+)/g;
    let m;
    while ((m = re.exec(line)) !== null) {
      fields.push(m[1] !== undefined ? m[1] : (m[2] || '').trim());
    }
    if (fields.length < 2) continue;
    const name = String(fields[0] || '').trim();
    const pid = Number(String(fields[1] || '').trim());
    if (name && Number.isInteger(pid) && pid > 0) {
      if (!map.has(pid)) map.set(pid, name);
    }
  }
  return map;
}

// ---------- netsh wlan parser ----------
// Parses `netsh wlan show networks mode=bssid`.
// Returns [{ ssid, auth, encryption, bssids: [{ bssid, signal, radio, channel }] }].
export function parseNetshWlan(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  let cur = null;
  let curBssid = null;
  const pushBssid = () => {
    if (cur && curBssid && curBssid.bssid) {
      cur.bssids.push({ ...curBssid });
    }
    curBssid = null;
  };
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const ssidM = line.match(/^SSID\s+\d+\s*:\s*(.*)$/i);
    if (ssidM) {
      if (cur) { pushBssid(); out.push(cur); }
      cur = { ssid: ssidM[1].trim(), auth: '', encryption: '', bssids: [] };
      curBssid = null;
      continue;
    }
    if (!cur) continue;
    const authM = line.match(/^Authentication\s*:\s*(.*)$/i);
    if (authM) { cur.auth = authM[1].trim(); continue; }
    const encM = line.match(/^Encryption\s*:\s*(.*)$/i);
    if (encM) { cur.encryption = encM[1].trim(); continue; }
    const bssidM = line.match(/^BSSID\s+\d+\s*:\s*([0-9a-fA-F: -]{17,})/i);
    if (bssidM) {
      pushBssid();
      curBssid = { bssid: bssidM[1].trim().toLowerCase(), signal: '', radio: '', channel: '' };
      continue;
    }
    if (curBssid) {
      const sigM = line.match(/^Signal\s*:\s*(.*)$/i);
      if (sigM) { curBssid.signal = sigM[1].trim(); continue; }
      const radioM = line.match(/^Radio type\s*:\s*(.*)$/i);
      if (radioM) { curBssid.radio = radioM[1].trim(); continue; }
      const chM = line.match(/^Channel\s*:\s*(.*)$/i);
      if (chM) { curBssid.channel = chM[1].trim(); continue; }
    }
  }
  if (cur) { pushBssid(); out.push(cur); }
  return out;
}

function isOpenAuth(auth) {
  return /^\s*open\s*$/i.test(String(auth || '').trim());
}
function isSecuredAuth(auth) {
  return /wpa|wpa2|wpa3|wep|802\.1x|enterprise/i.test(String(auth || ''));
}

// Evil-twin heuristics (documented as heuristics, not proof):
// - duplicate SSID with BSSIDs not seen in baseline = possible evil twin / new AP
// - same SSID seen both secured and Open = flag open twin of a known network
export function detectEvilTwin(baselineWifi, currentWifi) {
  const baseBySsid = new Map();
  for (const n of baselineWifi || []) {
    const set = new Set((n.bssids || []).map((b) => normalizeMac(b.bssid)));
    if (!baseBySsid.has(n.ssid)) baseBySsid.set(n.ssid, { bssids: new Set(), auths: new Set() });
    const e = baseBySsid.get(n.ssid);
    for (const b of set) e.bssids.add(b);
    if (n.auth) e.auths.add(String(n.auth));
  }
  const alerts = [];
  const seen = new Map(); // ssid -> { bssids:Set, auths:Set }
  for (const n of currentWifi || []) {
    if (!seen.has(n.ssid)) seen.set(n.ssid, { bssids: new Set(), auths: new Set(), entries: [] });
    const e = seen.get(n.ssid);
    for (const b of n.bssids || []) e.bssids.add(normalizeMac(b.bssid));
    if (n.auth) e.auths.add(String(n.auth));
    e.entries.push(n);
  }
  for (const [ssid, e] of seen) {
    const base = baseBySsid.get(ssid);
    // Open twin of a known secured network
    const hasOpen = [...e.auths].some((a) => isOpenAuth(a));
    const baseSecured = base && [...base.auths].some((a) => isSecuredAuth(a));
    const curSecured = [...e.auths].some((a) => isSecuredAuth(a));
    if (hasOpen && (curSecured || baseSecured)) {
      alerts.push({ kind: 'open-twin', ssid, detail: `SSID "${ssid}" seen both secured and Open - possible evil twin` });
    }
    // New BSSIDs vs baseline
    if (base) {
      const fresh = [...e.bssids].filter((b) => !base.bssids.has(b));
      if (fresh.length > 0 && e.bssids.size > 1) {
        alerts.push({ kind: 'new-bssid', ssid, detail: `SSID "${ssid}" shows ${e.bssids.size} BSSID(s), ${fresh.length} new vs baseline (${fresh.slice(0, 3).join(', ')})` });
      } else if (fresh.length > 0 && e.bssids.size === 1) {
        alerts.push({ kind: 'bssid-change', ssid, detail: `SSID "${ssid}" BSSID changed vs baseline (now ${[...e.bssids][0]})` });
      }
    } else if (e.bssids.size > 1) {
      alerts.push({ kind: 'multi-bssid', ssid, detail: `SSID "${ssid}" advertises ${e.bssids.size} BSSIDs (first seen - verify they are yours)` });
    }
  }
  return alerts;
}

export function diffListeners(baseline, current) {
  const key = (l) => `${String(l.proto || '').toUpperCase()}:${Number(l.port || 0)}`;
  const bset = new Set((baseline || []).map(key));
  const cset = new Set((current || []).map(key));
  const added = (current || []).filter((l) => !bset.has(key(l)));
  const gone = (baseline || []).filter((l) => !cset.has(key(l)));
  return { added, gone };
}

// ---------- hosts file ----------
export function getHostsPath() {
  const root = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
  return path.join(root, 'System32', 'drivers', 'etc', 'hosts');
}
export function sha256String(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}
export function sha256File(fp) {
  const h = crypto.createHash('sha256');
  h.update(fs.readFileSync(fp));
  return h.digest('hex');
}
export function readHostsHash() {
  const fp = getHostsPath();
  try {
    const raw = fs.readFileSync(fp, 'utf8');
    return { ok: true, path: fp, hash: sha256String(raw), size: Buffer.byteLength(raw, 'utf8'), error: '' };
  } catch (e) {
    return { ok: false, path: fp, hash: '', size: 0, error: String((e && e.message) || e).slice(0, 200) };
  }
}

// ---------- live OS snapshots (best-effort, always timeout-guarded) ----------
export function getNetstatSnapshot() {
  const r = runOs('netstat', ['-ano'], CMD_TIMEOUT_MS);
  if (!r.ok) return { ok: false, error: r.error, listeners: [], conns: [] };
  try {
    const p = parseNetstat(r.stdout);
    return { ok: true, error: '', listeners: p.listeners, conns: p.conns };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 200), listeners: [], conns: [] };
  }
}
export function getArpTable() {
  const r = runOs('arp', ['-a'], CMD_TIMEOUT_MS);
  if (!r.ok) return { ok: false, error: r.error, entries: [] };
  try {
    return { ok: true, error: '', entries: parseArp(r.stdout) };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 200), entries: [] };
  }
}
export function getWifiNetworks() {
  const r = runOs('netsh', ['wlan', 'show', 'networks', 'mode=bssid'], CMD_TIMEOUT_MS);
  if (!r.ok) return { ok: false, error: r.error, networks: [] };
  try {
    return { ok: true, error: '', networks: parseNetshWlan(r.stdout) };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 200), networks: [] };
  }
}
export function getTasklistMap() {
  const r = runOs('tasklist', ['/FO', 'CSV', '/NH'], CMD_TIMEOUT_MS);
  if (!r.ok) return { ok: false, error: r.error, map: new Map() };
  try {
    return { ok: true, error: '', map: parseTasklist(r.stdout) };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e).slice(0, 200), map: new Map() };
  }
}

function lookupOne(host, timeoutMs = 5000) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) { done = true; resolve({ host, ok: false, ips: [], error: 'timeout' }); }
    }, timeoutMs);
    try {
      dns.lookup(host, { all: true }, (err, addrs) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (err) resolve({ host, ok: false, ips: [], error: String((err && err.message) || err).slice(0, 120) });
        else resolve({ host, ok: true, ips: (addrs || []).map((a) => a.address), error: '' });
      });
    } catch (e) {
      if (!done) { done = true; clearTimeout(timer); resolve({ host, ok: false, ips: [], error: String((e && e.message) || e).slice(0, 120) }); }
    }
  });
}
export async function resolveDnsList(hosts = DNS_HOSTS) {
  const out = {};
  for (const h of hosts) {
    const r = await lookupOne(h, 5000);
    out[h] = r.ok ? [...new Set(r.ips)].sort() : [];
  }
  return out;
}
export function diffDns(baselineDns, currentDns) {
  const changes = [];
  const keys = new Set([...Object.keys(baselineDns || {}), ...Object.keys(currentDns || {})]);
  for (const k of keys) {
    const a = [...new Set(baselineDns?.[k] || [])].sort().join(',');
    const b = [...new Set(currentDns?.[k] || [])].sort().join(',');
    if (a !== b) changes.push({ host: k, oldIps: baselineDns?.[k] || [], newIps: currentDns?.[k] || [] });
  }
  return changes;
}

function probePort(host, port, timeoutMs = 400) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (open) => { if (!done) { done = true; resolve(open); } };
    try {
      const s = net.connect({ host, port, timeout: timeoutMs }, () => { try { s.destroy(); } catch { /* ignore */ } finish(true); });
      s.on('timeout', () => { try { s.destroy(); } catch { /* ignore */ } finish(false); });
      s.on('error', () => { try { s.destroy(); } catch { /* ignore */ } finish(false); });
      s.on('close', () => finish(false));
      setTimeout(() => { try { s.destroy(); } catch { /* ignore */ } finish(false); }, timeoutMs + 200);
    } catch { finish(false); }
  });
}
// Self-scan loopback only (127.0.0.1). Never touches remote hosts.
export async function scanLoopbackPorts(host = '127.0.0.1', ports = COMMON_PORTS, perPortMs = 400) {
  const open = [];
  for (const p of ports) {
    const isOpen = await probePort(host, p, perPortMs);
    if (isOpen) open.push(p);
  }
  return open;
}

// Quick snapshot: fast local tables only (loopback-safe, listen-loop friendly).
export function collectQuickSnapshot() {
  const ns = getNetstatSnapshot();
  const arpR = getArpTable();
  const hosts = readHostsHash();
  const arpMap = {};
  for (const e of arpR.entries || []) arpMap[e.ip] = e.mac;
  return {
    at: new Date().toISOString(),
    listeners: ns.ok ? ns.listeners : [],
    conns: ns.ok ? ns.conns : [],
    netstatOk: ns.ok, netstatError: ns.error || '',
    arp: arpMap, arpEntries: arpR.entries || [],
    arpOk: arpR.ok, arpError: arpR.error || '',
    hostsHash: hosts.ok ? hosts.hash : '', hostsSize: hosts.ok ? hosts.size : 0,
    hostsOk: hosts.ok, hostsError: hosts.error || '', hostsPath: hosts.path,
  };
}

// Full snapshot: quick + wifi + dns + loopback port scan (used by baseline/check).
export async function collectFullSnapshot() {
  const quick = collectQuickSnapshot();
  const wifi = getWifiNetworks();
  const dnsMap = await resolveDnsList();
  const openPorts = await scanLoopbackPorts('127.0.0.1', COMMON_PORTS, 350);
  return {
    ...quick,
    wifi: wifi.ok ? wifi.networks : [], wifiOk: wifi.ok, wifiError: wifi.error || '',
    dns: dnsMap,
    openPorts,
  };
}

// ---------- baselines (own data dir only) ----------
export function loadBaseline(dataDir) {
  try {
    const raw = fs.readFileSync(baselinePath(dataDir), 'utf8');
    const j = JSON.parse(raw);
    if (!j || typeof j !== 'object') return null;
    return j;
  } catch { return null; }
}
export function saveBaseline(dataDir, snap) {
  fs.mkdirSync(dataDir, { recursive: true });
  const payload = { savedAt: new Date().toISOString(), version: SENTINEL_VERSION, ...snap };
  fs.writeFileSync(baselinePath(dataDir), JSON.stringify(payload, null, 2), 'utf8');
  return payload;
}
export function baselineExists(dataDir) {
  try { return fs.existsSync(baselinePath(dataDir)); } catch { return false; }
}

// Diff a fresh snapshot vs a stored baseline. Returns { alerts: [strings], details: {...} }.
export function diffSnapshot(baseline, snap) {
  const alerts = [];
  const details = { newListeners: [], goneListeners: [], arpAdded: [], arpChanged: [], arpGone: [], wifi: [], hostsChanged: false, dnsChanged: [] };
  if (!baseline) return { alerts: ['No baseline yet.'], details };
  // listeners
  const dl = diffListeners(baseline.listeners || [], snap.listeners || []);
  details.newListeners = dl.added;
  details.goneListeners = dl.gone;
  for (const l of dl.added) alerts.push(`New listener: ${l.proto} port ${l.port} (pid ${l.pid || '?'})`);
  // arp
  const da = diffArp(baseline.arp || {}, snap.arpEntries || Object.entries(snap.arp || {}).map(([ip, mac]) => ({ ip, mac })));
  details.arpAdded = da.added;
  details.arpChanged = da.changed;
  details.arpGone = da.gone;
  for (const a of da.added) alerts.push(`New ARP entry: ${a.ip} -> ${a.mac} (new device or first seen)`);
  for (const c of da.changed) alerts.push(`ARP MAC change: ${c.ip} ${c.oldMac} -> ${c.newMac} (possible spoofing - verify)`);
  // wifi (only when both sides present)
  if (Array.isArray(baseline.wifi) && Array.isArray(snap.wifi)) {
    const twins = detectEvilTwin(baseline.wifi, snap.wifi);
    details.wifi = twins;
    for (const t of twins) alerts.push(t.detail);
  }
  // hosts
  if (baseline.hostsHash && snap.hostsHash && baseline.hostsHash !== snap.hostsHash) {
    details.hostsChanged = true;
    alerts.push(`Hosts file changed (hash ${String(baseline.hostsHash).slice(0, 12)}.. -> ${String(snap.hostsHash).slice(0, 12)}..) - verify`);
  }
  // dns
  if (baseline.dns && snap.dns) {
    const dc = diffDns(baseline.dns, snap.dns);
    details.dnsChanged = dc;
    for (const d of dc) alerts.push(`DNS change: ${d.host} [${(d.oldIps || []).join(', ') || '-'}] -> [${(d.newIps || []).join(', ') || '-'}]`);
  }
  // open ports (loopback self-scan)
  if (Array.isArray(baseline.openPorts) && Array.isArray(snap.openPorts)) {
    const bset = new Set(baseline.openPorts);
    for (const p of snap.openPorts) {
      if (!bset.has(p)) alerts.push(`New local open port: 127.0.0.1:${p} (self-scan)`);
    }
  }
  return { alerts, details };
}

// ---------- threat score (0-100, transparent factors) ----------
export function computeThreatScore(events, nowMs = Date.now()) {
  const evs = Array.isArray(events) ? events : [];
  const day = 24 * 3600 * 1000;
  const inLast = (ms) => {
    const t = new Date(ms).getTime?.() ?? NaN;
    void t;
    return true;
  };
  void inLast;
  const recent24 = evs.filter((e) => {
    try { return nowMs - new Date(e.time).getTime() <= day && nowMs - new Date(e.time).getTime() >= 0; } catch { return false; }
  });
  const recent7 = evs.filter((e) => {
    try { return nowMs - new Date(e.time).getTime() <= 7 * day && nowMs - new Date(e.time).getTime() >= 0; } catch { return false; }
  });
  const factors = [];
  let score = 0;
  const countSev = (s) => recent24.filter((e) => String(e.severity || '').toLowerCase() === s).length;
  const crit = countSev('critical');
  if (crit > 0) {
    const pts = Math.min(30, 20 + (crit >= 3 ? 10 : 0));
    factors.push({ factor: 'critical events (24h)', detail: `${crit} critical`, points: pts });
    score += pts;
  } else factors.push({ factor: 'critical events (24h)', detail: '0', points: 0 });
  const duress = recent7.filter((e) => e.type === 'duress').length;
  if (duress > 0) {
    factors.push({ factor: 'duress PIN used (7d)', detail: `${duress} duress event(s)`, points: 30 });
    score += 30;
  } else factors.push({ factor: 'duress PIN used (7d)', detail: 'none', points: 0 });
  const high = countSev('high');
  if (high > 0) {
    const pts = Math.min(20, high * 5);
    factors.push({ factor: 'high-severity touches (24h)', detail: `${high} event(s)`, points: pts });
    score += pts;
  } else factors.push({ factor: 'high-severity touches (24h)', detail: '0', points: 0 });
  const sent = recent24.filter((e) => e.type === 'sentinel').length;
  if (sent > 0) {
    const pts = Math.min(20, sent * 5);
    factors.push({ factor: 'sentinel alerts (24h)', detail: `${sent} sentinel event(s)`, points: pts });
    score += pts;
  } else factors.push({ factor: 'sentinel alerts (24h)', detail: '0', points: 0 });
  const trapTouches = recent24.filter((e) => String(e.trap || '').startsWith('honey-tcp') || String(e.trap || '').startsWith('canary')).length;
  if (trapTouches > 0) {
    const pts = Math.min(15, trapTouches * 5);
    factors.push({ factor: 'trap touches (24h)', detail: `${trapTouches} honey/canary`, points: pts });
    score += pts;
  } else factors.push({ factor: 'trap touches (24h)', detail: '0', points: 0 });
  const loginAttempts = recent24.filter((e) => e.loginAttempted === true || e.type === 'honey-http').length;
  if (loginAttempts > 0) {
    const pts = Math.min(10, loginAttempts * 2);
    factors.push({ factor: 'fake-login attempts (24h)', detail: `${loginAttempts} attempt(s)`, points: pts });
    score += pts;
  } else factors.push({ factor: 'fake-login attempts (24h)', detail: '0', points: 0 });
  score = Math.max(0, Math.min(100, Math.round(score)));
  const level = score >= 75 ? 'high' : score >= 50 ? 'elevated' : score >= 20 ? 'guarded' : 'low';
  return { score, level, factors, counts: { total: evs.length, last24: recent24.length, last7: recent7.length } };
}

// ---------- file integrity (arbitrary paths, sha256) ----------
export function loadIntegrity(dataDir) {
  try {
    const raw = fs.readFileSync(integrityPath(dataDir), 'utf8');
    const j = JSON.parse(raw);
    if (!j || typeof j !== 'object' || !j.files || typeof j.files !== 'object') return { files: {} };
    return { files: j.files };
  } catch { return { files: {} }; }
}
export function saveIntegrity(dataDir, state) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(integrityPath(dataDir), JSON.stringify({ savedAt: new Date().toISOString(), version: SENTINEL_VERSION, files: state.files || {} }, null, 2), 'utf8');
}
export function integrityAdd(dataDir, filePath) {
  const abs = path.resolve(String(filePath || ''));
  const st = loadIntegrity(dataDir);
  let stat = null;
  try { stat = fs.statSync(abs); } catch (e) {
    return { ok: false, error: `Cannot read: ${filePath} (${String((e && e.message) || e).slice(0, 120)})` };
  }
  if (!stat.isFile()) return { ok: false, error: `Not a file: ${filePath}` };
  let hash = '';
  try { hash = sha256File(abs); } catch (e) {
    return { ok: false, error: `Cannot hash: ${String((e && e.message) || e).slice(0, 120)}` };
  }
  const isUpdate = !!st.files[abs];
  st.files[abs] = { sha256: hash, size: stat.size, addedAt: st.files[abs]?.addedAt || new Date().toISOString(), updatedAt: new Date().toISOString() };
  saveIntegrity(dataDir, st);
  return { ok: true, path: abs, hash, updated: isUpdate };
}
export function integrityRemove(dataDir, filePath) {
  const abs = path.resolve(String(filePath || ''));
  const st = loadIntegrity(dataDir);
  if (!st.files[abs]) return { ok: false, error: `Not watched: ${filePath}` };
  delete st.files[abs];
  saveIntegrity(dataDir, st);
  return { ok: true, path: abs };
}
export function integrityVerify(dataDir) {
  const st = loadIntegrity(dataDir);
  const changed = [];
  const missing = [];
  const okFiles = [];
  for (const [fp, rec] of Object.entries(st.files)) {
    try {
      const cur = sha256File(fp);
      if (cur !== rec.sha256) changed.push({ path: fp, oldHash: rec.sha256, newHash: cur });
      else okFiles.push({ path: fp });
    } catch {
      missing.push({ path: fp });
    }
  }
  return { changed, missing, okFiles, total: Object.keys(st.files).length };
}
export function integrityRefresh(dataDir) {
  const st = loadIntegrity(dataDir);
  let refreshed = 0;
  const gone = [];
  for (const fp of Object.keys(st.files)) {
    try {
      const h = sha256File(fp);
      const stat = fs.statSync(fp);
      st.files[fp] = { sha256: h, size: stat.size, addedAt: st.files[fp]?.addedAt || new Date().toISOString(), updatedAt: new Date().toISOString() };
      refreshed++;
    } catch { gone.push(fp); }
  }
  saveIntegrity(dataDir, st);
  return { refreshed, gone, total: Object.keys(st.files).length };
}
