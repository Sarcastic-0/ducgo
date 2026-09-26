// ducgo v3 - data directory: config.json + events.jsonl. Stdlib only.
// Default data dir is ~/.miragenet on every OS (Windows: %USERPROFILE%\.miragenet).
// MIRAGENET_DIR overrides it (used by the selftest and scripting so tests
// never touch the real store).
//
// Event-log encryption (at rest, AES-256-GCM, stdlib only):
//   keyP = PBKDF2(normalPIN, encSalt, 200k, sha256, 32B)
//   keyD = PBKDF2(duressPIN, encSalt, 200k, sha256, 32B)
//   encSalt = 16 random bytes hex, stored in config.json (public salt).
//   envelope per line: {v:1, k:'p'|'d', iv:hex12B, ct:hex(ciphertext+16B tag)}.
//   Normal session knows keyP + unwrapped keyD (wrapped at setup with keyP,
//   stored as config.encWrapped {iv,ct}). Duress session knows only keyD,
//   writes k:'d' lines. Normal reads try keyP then keyD (transparent).
//   Mixed files (plaintext + encrypted lines) read transparently per line.
//   Honest limits: auth_failure events (failed PIN, no key) and demo events
//   (no PIN) are written plaintext even when encryption is ON (mixed file).
//   PINs are never logged. Change-pin/duress re-wraps + re-encrypts.
//   vm sandbox, atime, geoip, alerts documented in README + about/tips.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { dataDir as platformDataDir } from './platform.js';

export const DEFAULT_PORTS = [2222, 2323, 8080];
export const DEFAULT_HTTP_PORT = 18080;
export const ENC_ITERATIONS = 200_000;

export function getDataDir() {
  const override = process.env.MIRAGENET_DIR;
  if (override && override.trim()) return path.resolve(override.trim());
  return platformDataDir();
}

export function ensureDataDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function configPath(dataDir) {
  return path.join(dataDir, 'config.json');
}

export function eventsPath(dataDir) {
  return path.join(dataDir, 'events.jsonl');
}

export function alertsPath(dataDir, cfg) {
  try {
    const c = cfg || loadConfig(dataDir);
    const p = c['alerts-file'] || c.alertsFile || '';
    if (p && String(p).trim()) return path.resolve(String(p).trim());
  } catch { /* fall through */ }
  return path.join(dataDir, 'alerts.log');
}

export function loadConfig(dataDir) {
  const cfg = {
    ports: [...DEFAULT_PORTS],
    httpPort: DEFAULT_HTTP_PORT,
    watchDirs: [],
    disabled: [],
    banners: {},
    stealthBanners: {},
    httpTitle: 'Admin Login',
    notes: {},
    plugins: {},
    aliases: {},
    macros: {},
    encryption: 'off',
    encSalt: '',
    encWrapped: null,
    alerts: 'off',
    'alerts-file': '',
    geoipDb: '',
  };
  try {
    const j = JSON.parse(fs.readFileSync(configPath(dataDir), 'utf8'));
    if (j && typeof j === 'object') {
      if (Array.isArray(j.ports)) {
        const p = j.ports.filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535).slice(0, 20);
        if (p.length > 0) cfg.ports = p;
      }
      if (Number.isInteger(j.httpPort) && j.httpPort >= 1 && j.httpPort <= 65535) cfg.httpPort = j.httpPort;
      if (Array.isArray(j.watchDirs)) cfg.watchDirs = [...new Set(j.watchDirs.map(String))];
      if (Array.isArray(j.disabled)) cfg.disabled = [...new Set(j.disabled.map(String))].slice(0, 40);
      if (j.banners && typeof j.banners === 'object' && !Array.isArray(j.banners)) {
        for (const [k, v] of Object.entries(j.banners)) {
          if (String(v).length <= 500) cfg.banners[String(k)] = String(v);
        }
      }
      if (j.stealthBanners && typeof j.stealthBanners === 'object' && !Array.isArray(j.stealthBanners)) {
        for (const [k, v] of Object.entries(j.stealthBanners)) {
          const s = String(v).toLowerCase();
          if (['ssh', 'ftp', 'telnet'].includes(s)) cfg.stealthBanners[String(k)] = s;
        }
      }
      if (typeof j.httpTitle === 'string' && j.httpTitle.length > 0 && j.httpTitle.length <= 120) {
        cfg.httpTitle = j.httpTitle;
      }
      if (j.notes && typeof j.notes === 'object' && !Array.isArray(j.notes)) {
        for (const [k, v] of Object.entries(j.notes)) {
          if (Array.isArray(v)) cfg.notes[String(k)] = v.filter((n) => n && typeof n === 'object').slice(0, 200);
        }
      }
      if (j.plugins && typeof j.plugins === 'object' && !Array.isArray(j.plugins)) {
        for (const [k, v] of Object.entries(j.plugins)) {
          if (v && typeof v === 'object' && !Array.isArray(v)) {
            const e = {
              enabled: !!v.enabled,
              file: String(v.file || k + '.js').slice(0, 200),
              sha256: typeof v.sha256 === 'string' ? v.sha256.slice(0, 128) : '',
              name: typeof v.name === 'string' ? v.name.slice(0, 120) : String(k).slice(0, 120),
              version: typeof v.version === 'string' ? v.version.slice(0, 40) : '',
              commands: Array.isArray(v.commands) ? v.commands.map(String).slice(0, 20) : [],
            };
            if (v.unsafe === true) e.unsafe = true;
            cfg.plugins[String(k).slice(0, 120)] = e;
          }
        }
      }
      if (j.aliases && typeof j.aliases === 'object' && !Array.isArray(j.aliases)) {
        for (const [k, v] of Object.entries(j.aliases)) {
          if (typeof v === 'string' && String(k).length > 0 && String(k).length <= 80) {
            cfg.aliases[String(k)] = String(v).slice(0, 2000);
          }
        }
      }
      if (j.macros && typeof j.macros === 'object' && !Array.isArray(j.macros)) {
        for (const [k, v] of Object.entries(j.macros)) {
          if (typeof v === 'string' && String(k).length > 0 && String(k).length <= 80) {
            cfg.macros[String(k)] = String(v).slice(0, 4000);
          }
        }
      }
      if (typeof j.encryption === 'string' && ['on', 'off'].includes(j.encryption)) cfg.encryption = j.encryption;
      if (typeof j.encSalt === 'string' && /^[0-9a-f]{32}$/i.test(j.encSalt)) cfg.encSalt = j.encSalt.toLowerCase();
      if (j.encWrapped && typeof j.encWrapped === 'object' && typeof j.encWrapped.iv === 'string' && typeof j.encWrapped.ct === 'string') {
        if (/^[0-9a-f]+$/i.test(j.encWrapped.iv) && /^[0-9a-f]+$/i.test(j.encWrapped.ct)) {
          cfg.encWrapped = { iv: j.encWrapped.iv.toLowerCase(), ct: j.encWrapped.ct.toLowerCase() };
        }
      }
      if (typeof j.alerts === 'string' && ['off', 'beep', 'file', 'both'].includes(j.alerts)) cfg.alerts = j.alerts;
      if (typeof j['alerts-file'] === 'string') cfg['alerts-file'] = String(j['alerts-file']).slice(0, 500);
      if (typeof j.alertsFile === 'string' && !cfg['alerts-file']) cfg['alerts-file'] = String(j.alertsFile).slice(0, 500);
      if (typeof j.geoipDb === 'string') cfg.geoipDb = String(j.geoipDb).slice(0, 500);
      // Preserve unknown future keys? No - strict schema keeps file clean.
    }
  } catch {
    /* missing or corrupt config -> defaults */
  }
  return cfg;
}

export function saveConfig(dataDir, cfg) {
  ensureDataDir(dataDir);
  fs.writeFileSync(configPath(dataDir), JSON.stringify(cfg, null, 2), 'utf8');
}

export function addWatchDir(dataDir, dir) {
  const cfg = loadConfig(dataDir);
  const abs = path.resolve(dir);
  if (!cfg.watchDirs.includes(abs)) {
    cfg.watchDirs.push(abs);
    saveConfig(dataDir, cfg);
  }
  return cfg;
}

export function removeWatchDir(dataDir, dir) {
  const cfg = loadConfig(dataDir);
  const abs = path.resolve(dir);
  cfg.watchDirs = cfg.watchDirs.filter((d) => path.resolve(d) !== abs && d !== dir);
  saveConfig(dataDir, cfg);
  return cfg;
}

export function authPath(dataDir) {
  return path.join(dataDir, 'auth.json');
}

export function dirSize(dataDir) {
  let total = 0;
  const files = {};
  for (const name of ['auth.json', 'config.json', 'events.jsonl']) {
    try {
      const st = fs.statSync(path.join(dataDir, name));
      files[name] = st.size;
      total += st.size;
    } catch {
      files[name] = 0;
    }
  }
  return { total, files };
}

export function addAttackerNote(dataDir, ip, text) {
  const cfg = loadConfig(dataDir);
  const key = String(ip);
  if (!cfg.notes[key]) cfg.notes[key] = [];
  cfg.notes[key].push({ time: new Date().toISOString(), text: String(text).slice(0, 500) });
  cfg.notes[key] = cfg.notes[key].slice(-200);
  saveConfig(dataDir, cfg);
  return cfg.notes[key].length;
}

export function getAttackerNotes(dataDir, ip) {
  const cfg = loadConfig(dataDir);
  if (ip) return { [String(ip)]: cfg.notes[String(ip)] || [] };
  return cfg.notes;
}

// ---------- event-log encryption (AES-256-GCM, stdlib only) ----------
export function deriveEncKey(pin, saltHex) {
  return crypto.pbkdf2Sync(String(pin || ''), Buffer.from(String(saltHex || ''), 'hex'), ENC_ITERATIONS, 32, 'sha256');
}

export function ensureEncSalt(dataDir) {
  const cfg = loadConfig(dataDir);
  if (cfg.encSalt && /^[0-9a-f]{32}$/i.test(cfg.encSalt)) return cfg.encSalt;
  cfg.encSalt = crypto.randomBytes(16).toString('hex');
  saveConfig(dataDir, cfg);
  return cfg.encSalt;
}

export function isEncryptionEnabled(dataDir) {
  try {
    const cfg = loadConfig(dataDir);
    return cfg.encryption === 'on' && !!cfg.encSalt;
  } catch { return false; }
}

function aesEncryptToHex(plainBuf, keyBuf) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const ct = Buffer.concat([c.update(plainBuf), c.final()]);
  const tag = c.getAuthTag();
  return { iv: iv.toString('hex'), ct: Buffer.concat([ct, tag]).toString('hex') };
}

function aesDecryptFromHex(ivHex, ctHex, keyBuf) {
  const iv = Buffer.from(ivHex, 'hex');
  const raw = Buffer.from(ctHex, 'hex');
  if (raw.length < 17) throw new Error('short ciphertext');
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(0, raw.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

export function encryptEventEnvelope(ev, keyBuf, keyId) {
  const plain = Buffer.from(JSON.stringify(ev), 'utf8');
  const { iv, ct } = aesEncryptToHex(plain, keyBuf);
  return JSON.stringify({ v: 1, k: keyId === 'd' ? 'd' : 'p', iv, ct });
}

export function isEncryptedEnvelope(obj) {
  return !!obj && typeof obj === 'object' && obj.v === 1 && (obj.k === 'p' || obj.k === 'd') && typeof obj.iv === 'string' && typeof obj.ct === 'string';
}

export function decryptEnvelopeToEvent(env, keyBuf) {
  const raw = aesDecryptFromHex(env.iv, env.ct, keyBuf);
  return JSON.parse(raw.toString('utf8'));
}

export function wrapDuressKey(keyP, keyD) {
  const { iv, ct } = aesEncryptToHex(Buffer.from(keyD), keyP);
  return { iv, ct };
}

export function unwrapDuressKey(keyP, wrapped) {
  const raw = aesDecryptFromHex(wrapped.iv, wrapped.ct, keyP);
  if (raw.length !== 32) throw new Error('bad wrapped key length');
  return Buffer.from(raw);
}

// Session key cache: set after successful requireAuth so appendEvent/readEvents
// handle both formats transparently without changing every call site.
// _sessDir guards cross-dir leakage (tests use many scratch dirs).
let _sessDir = null;
let _sessKeyP = null;
let _sessKeyD = null;

export function setSessionKeys(dir, keyP, keyD) {
  _sessDir = dir ? path.resolve(String(dir)) : null;
  _sessKeyP = keyP ? Buffer.from(keyP) : null;
  _sessKeyD = keyD ? Buffer.from(keyD) : null;
}

export function clearSessionKeys() {
  _sessDir = null;
  _sessKeyP = null;
  _sessKeyD = null;
}

export function getSessionKeys() {
  return { dir: _sessDir, keyP: _sessKeyP, keyD: _sessKeyD };
}

function sessionKeysFor(dir) {
  try {
    if (!_sessDir) return { keyP: null, keyD: null };
    if (path.resolve(String(dir)) !== _sessDir) return { keyP: null, keyD: null };
    return { keyP: _sessKeyP, keyD: _sessKeyD };
  } catch { return { keyP: null, keyD: null }; }
}

// Derive + cache session keys after auth. role 'normal' unwraps keyD via
// config.encWrapped (best-effort); role 'duress' caches only keyD.
export function unlockEvents(dataDir, pin, role) {
  try {
    const cfg = loadConfig(dataDir);
    if (cfg.encryption !== 'on' || !cfg.encSalt) {
      setSessionKeys(dataDir, null, null);
      return { ok: true, encrypted: false };
    }
    if (role === 'duress') {
      const keyD = deriveEncKey(pin, cfg.encSalt);
      setSessionKeys(dataDir, null, keyD);
      return { ok: true, encrypted: true };
    }
    const keyP = deriveEncKey(pin, cfg.encSalt);
    let keyD = null;
    try {
      if (cfg.encWrapped && cfg.encWrapped.iv && cfg.encWrapped.ct) {
        keyD = unwrapDuressKey(keyP, cfg.encWrapped);
      }
    } catch { keyD = null; }
    setSessionKeys(dataDir, keyP, keyD);
    return { ok: true, encrypted: true };
  } catch {
    setSessionKeys(dataDir, null, null);
    return { ok: false, encrypted: false };
  }
}

// Setup helper: called when both PINs are known (setup). Generates salt,
// derives both keys, stores wrapped duress key, enables encryption ON.
// Default ON for new setups.
export function setupEventEncryption(dataDir, normalPin, duressPin) {
  const salt = ensureEncSalt(dataDir);
  const keyP = deriveEncKey(normalPin, salt);
  const keyD = deriveEncKey(duressPin, salt);
  const wrapped = wrapDuressKey(keyP, keyD);
  const cfg = loadConfig(dataDir);
  cfg.encSalt = salt;
  cfg.encWrapped = wrapped;
  cfg.encryption = 'on';
  saveConfig(dataDir, cfg);
  setSessionKeys(dataDir, keyP, keyD);
  return { ok: true, salt };
}

// Re-wrap duress key after normal PIN change (old keyD available via session
// or re-derived if old normal PIN given). Caller must have unlocked first.
export function rewrapAfterNormalPinChange(dataDir, newNormalPin) {
  const cfg = loadConfig(dataDir);
  if (!cfg.encSalt) return { ok: true, rewrapped: false };
  const { keyD } = sessionKeysFor(dataDir);
  const keyPNew = deriveEncKey(newNormalPin, cfg.encSalt);
  let keyDWrapped = keyD;
  if (!keyDWrapped && cfg.encWrapped) {
    // No session keyD (legacy): cannot re-derive without duress PIN. Keep old wrapped
    // (it was wrapped with old keyP and is now stale). Documented limit: run
    // change-duress after change-pin to re-establish wrapping, or re-enable encryption.
    const c2 = loadConfig(dataDir);
    c2.encWrapped = c2.encWrapped || null;
    saveConfig(dataDir, c2);
    setSessionKeys(dataDir, keyPNew, null);
    return { ok: true, rewrapped: false, stale: true };
  }
  if (keyDWrapped) {
    cfg.encWrapped = wrapDuressKey(keyPNew, keyDWrapped);
    saveConfig(dataDir, cfg);
  }
  setSessionKeys(dataDir, keyPNew, keyDWrapped);
  return { ok: true, rewrapped: !!keyDWrapped };
}

export function rewrapAfterDuressPinChange(dataDir, newDuressPin) {
  const cfg = loadConfig(dataDir);
  if (!cfg.encSalt) return { ok: true, rewrapped: false };
  const { keyP } = sessionKeysFor(dataDir);
  if (!keyP) return { ok: false, error: 'normal session required' };
  const keyDNew = deriveEncKey(newDuressPin, cfg.encSalt);
  cfg.encWrapped = wrapDuressKey(keyP, keyDNew);
  saveConfig(dataDir, cfg);
  setSessionKeys(dataDir, keyP, keyDNew);
  return { ok: true, rewrapped: true };
}

// ---------- local alerting (no network, stdlib only) ----------
// Config: alerts off|beep|file|both (default off), alerts-file path
// (default <dataDir>/alerts.log). Trigger: high-severity trap touches +
// high sentinel/pcap anomalies (severity high|critical, type honey-tcp,
// banner-grab, honey-http, canary, sentinel, pcap). beep = \x07 best-effort;
// file = one JSON line per alert {alertAt,time,type,trap,ip,detail,severity}
// for local SIEM tailing. Email/SMS/webhooks would break local-only /
// zero-deps and belong in separate optional plugins, not core.
export const ALERT_TYPES = new Set(['honey-tcp', 'banner-grab', 'honey-http', 'canary', 'sentinel', 'pcap']);

export function shouldAlert(ev) {
  if (!ev || typeof ev !== 'object') return false;
  const sev = String(ev.severity || '').toLowerCase();
  if (sev !== 'high' && sev !== 'critical') return false;
  return ALERT_TYPES.has(String(ev.type || ''));
}

export function alertSchema() {
  return '{alertAt,time,type,trap,ip,detail,severity} one JSON object per line';
}

export function maybeAlert(dataDir, ev) {
  let cfg = null;
  try { cfg = loadConfig(dataDir); } catch { return { alerted: false }; }
  const mode = cfg.alerts || 'off';
  if (mode === 'off') return { alerted: false };
  if (!shouldAlert(ev)) return { alerted: false };
  const rec = {
    alertAt: new Date().toISOString(),
    time: ev.time || new Date().toISOString(),
    type: String(ev.type || ''),
    trap: String(ev.trap || ''),
    ip: String(ev.ip || ''),
    detail: String(ev.detail || '').slice(0, 400),
    severity: String(ev.severity || ''),
  };
  if (mode === 'beep' || mode === 'both') {
    try { process.stdout.write('\x07'); } catch { /* best-effort */ }
  }
  if (mode === 'file' || mode === 'both') {
    try {
      ensureDataDir(dataDir);
      fs.appendFileSync(alertsPath(dataDir, cfg), JSON.stringify(rec) + '\n', 'utf8');
    } catch { /* best-effort */ }
  }
  return { alerted: true, record: rec };
}

export function appendEvent(dataDir, ev) {
  ensureDataDir(dataDir);
  let line = JSON.stringify(ev);
  try {
    const cfg = loadConfig(dataDir);
    if (cfg.encryption === 'on' && cfg.encSalt) {
      const { keyP, keyD } = sessionKeysFor(dataDir);
      if (keyP) {
        line = encryptEventEnvelope(ev, keyP, 'p');
      } else if (keyD) {
        line = encryptEventEnvelope(ev, keyD, 'd');
      } // else: no session (demo/auth_failure) -> plaintext (mixed file, documented)
    }
  } catch { line = JSON.stringify(ev); }
  fs.appendFileSync(eventsPath(dataDir), line + '\n', 'utf8');
  try { maybeAlert(dataDir, ev); } catch { /* alerts best-effort */ }
}

// optsOrPin: undefined (session cache) | string normal PIN | {pin, duressPin}.
// Without keys, encrypted lines are skipped (plaintext still returned).
// Mixed files (plaintext + encrypted) read transparently per line.
export function readEvents(dataDir, optsOrPin) {
  const out = [];
  let raw = '';
  try { raw = fs.readFileSync(eventsPath(dataDir), 'utf8'); }
  catch { return out; }
  let extraKeyP = null;
  let extraKeyD = null;
  try {
    if (typeof optsOrPin === 'string' && optsOrPin) {
      const cfg = loadConfig(dataDir);
      if (cfg.encSalt) {
        extraKeyP = deriveEncKey(optsOrPin, cfg.encSalt);
        if (cfg.encWrapped) {
          try { extraKeyD = unwrapDuressKey(extraKeyP, cfg.encWrapped); } catch { extraKeyD = null; }
        }
      }
    } else if (optsOrPin && typeof optsOrPin === 'object') {
      const cfg = loadConfig(dataDir);
      if (cfg.encSalt) {
        if (optsOrPin.pin) {
          extraKeyP = deriveEncKey(optsOrPin.pin, cfg.encSalt);
          if (cfg.encWrapped) {
            try { extraKeyD = unwrapDuressKey(extraKeyP, cfg.encWrapped); } catch { extraKeyD = null; }
          }
        }
        if (optsOrPin.duressPin && !extraKeyD) {
          try { extraKeyD = deriveEncKey(optsOrPin.duressPin, cfg.encSalt); } catch { extraKeyD = null; }
        }
        if (optsOrPin.keyP) extraKeyP = Buffer.from(optsOrPin.keyP);
        if (optsOrPin.keyD) extraKeyD = Buffer.from(optsOrPin.keyD);
      }
    }
  } catch { /* fall through to session */ }
  const sess = sessionKeysFor(dataDir);
  const keyP = extraKeyP || sess.keyP;
  const keyD = extraKeyD || sess.keyD;
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let obj = null;
    try { obj = JSON.parse(t); } catch { continue; }
    if (isEncryptedEnvelope(obj)) {
      let done = false;
      if (keyP) {
        try { out.push(decryptEnvelopeToEvent(obj, keyP)); done = true; } catch { /* try duress */ }
      }
      if (!done && keyD) {
        try { out.push(decryptEnvelopeToEvent(obj, keyD)); done = true; } catch { /* skip */ }
      }
      // no keys or both failed -> skip (do not leak ciphertext as event)
      continue;
    }
    out.push(obj);
  }
  return out;
}

// Decrypt every line possible with given PIN(s) for export. Returns {events, skipped}.
export function readEventsDecrypted(dataDir, pin, duressPin) {
  const evs = readEvents(dataDir, { pin, duressPin });
  return evs;
}

// Re-encrypt current file with current session normal key (k:'p').
// Used by `config-set encryption on`. Reads plaintext + decryptable lines,
// writes all back encrypted. Returns {ok, total, encrypted}.
export function reencryptFileWithSession(dataDir) {
  const sess = sessionKeysFor(dataDir);
  if (!sess.keyP) return { ok: false, error: 'normal session required' };
  const cfg = loadConfig(dataDir);
  if (!cfg.encSalt) return { ok: false, error: 'no encryption salt' };
  let raw = '';
  try { raw = fs.readFileSync(eventsPath(dataDir), 'utf8'); } catch { return { ok: true, total: 0, encrypted: 0 }; }
  const events = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let obj = null;
    try { obj = JSON.parse(t); } catch { continue; }
    if (isEncryptedEnvelope(obj)) {
      let ev = null;
      if (sess.keyP) { try { ev = decryptEnvelopeToEvent(obj, sess.keyP); } catch { /* try D */ } }
      if (!ev && sess.keyD) { try { ev = decryptEnvelopeToEvent(obj, sess.keyD); } catch { /* skip */ } }
      if (ev) events.push(ev);
      continue;
    }
    events.push(obj);
  }
  const lines = events.map((e) => encryptEventEnvelope(e, sess.keyP, 'p'));
  ensureDataDir(dataDir);
  fs.writeFileSync(eventsPath(dataDir), lines.length > 0 ? lines.join('\n') + '\n' : '', 'utf8');
  return { ok: true, total: events.length, encrypted: lines.length };
}

function csvCell(v) {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

export function eventsToCsv(events) {
  const rows = [['time', 'type', 'trap', 'ip', 'detail', 'severity']];
  for (const e of events) rows.push([e.time, e.type, e.trap, e.ip, e.detail, e.severity]);
  return rows.map((r) => r.map(csvCell).join(',')).join('\n') + '\n';
}

// ---------- geoip (offline only, no network calls ever) ----------
// User-supplied DB file (JSON {ranges:[{from,to,country,city?}]} IPv4, or CSV
// from,to,country,city). Path stored in config.geoipDb. .mmdb (MaxMind)
// needs external conversion: use mmdb-dump
// (https://github.com/maxmind/mmdb-dump or `mmdblookup --file GeoLite2-City.mmdb --ip 1.2.3.4`)
// to export ranges to JSON/CSV, then `ducgo geoip-load` the result.
export function ipToInt(ip) {
  const parts = String(ip || '').trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

export function loadGeoDbFile(filePath) {
  const raw = fs.readFileSync(path.resolve(filePath), 'utf8');
  const trimmed = raw.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const j = JSON.parse(raw);
    const arr = Array.isArray(j) ? j : j.ranges;
    if (!Array.isArray(arr)) throw new Error('JSON DB must be {ranges:[{from,to,country,city?}]}');
    return normalizeGeoRanges(arr);
  }
  return parseGeoCsv(raw);
}

function normalizeGeoRanges(arr) {
  const out = [];
  for (const r of arr) {
    if (!r || typeof r !== 'object') continue;
    const from = ipToInt(r.from);
    const to = ipToInt(r.to);
    if (from === null || to === null || to < from) continue;
    const country = String(r.country || '').slice(0, 80);
    if (!country) continue;
    out.push({ fromInt: from, toInt: to, from: String(r.from), to: String(r.to), country, city: String(r.city || '').slice(0, 80) });
    if (out.length > 100000) break;
  }
  if (out.length === 0) throw new Error('no valid ranges (need from,to,country IPv4)');
  out.sort((a, b) => a.fromInt - b.fromInt);
  return { ranges: out };
}

function parseGeoCsv(raw) {
  const lines = String(raw).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) throw new Error('empty CSV');
  let start = 0;
  if (/from/i.test(lines[0]) && /to/i.test(lines[0])) start = 1;
  const arr = [];
  for (let i = start; i < lines.length; i++) {
    const parts = lines[i].split(',').map((s) => s.trim());
    if (parts.length < 3) continue;
    arr.push({ from: parts[0], to: parts[1], country: parts[2], city: parts[3] || '' });
  }
  return normalizeGeoRanges(arr);
}

export function lookupGeoIp(ip, db) {
  const n = ipToInt(ip);
  if (n === null || !db || !Array.isArray(db.ranges)) return null;
  for (const r of db.ranges) {
    if (n >= r.fromInt && n <= r.toInt) return { country: r.country, city: r.city || '' };
  }
  return null;
}

export function loadGeoDbForDir(dataDir) {
  try {
    const cfg = loadConfig(dataDir);
    const p = cfg.geoipDb || '';
    if (!p) return { ok: false, db: null, error: 'no geo DB loaded' };
    const db = loadGeoDbFile(p);
    return { ok: true, db, error: '' };
  } catch (e) {
    return { ok: false, db: null, error: String((e && e.message) || e).slice(0, 200) };
  }
}

export function isLocalIp(ip) {
  const n = ipToInt(ip);
  if (n === null) return true;
  const a = (n >>> 24) & 255;
  const b = (n >>> 16) & 255;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

// Confidence 0-100, transparent weights (documented in README + tips):
//   base 50
//   RFC1918/local (likely NAT/internal): -30
//   single touch (touches==1, uncertain): +10
//   touches across 3+ distinct trap types: +25
//   matches canary token (detail has MIRAGETOKEN or trap starts with canary): +20
//   capped 0-100. Reasons returned for display.
export function geoConfidence(ip, touches, distinctTraps, hasCanaryHit) {
  let score = 50;
  const reasons = ['base 50'];
  if (isLocalIp(ip)) { score -= 30; reasons.push('RFC1918/local -30 (likely NAT)'); }
  if (Number(touches) === 1) { score += 10; reasons.push('single touch +10 (uncertain)'); }
  if (Number(distinctTraps) >= 3) { score += 25; reasons.push('3+ trap types +25'); }
  if (hasCanaryHit) { score += 20; reasons.push('canary token +20'); }
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, reasons };
}
