// MirageNet v2 — data directory: config.json + events.jsonl. Stdlib only.
// Default data dir is %USERPROFILE%\.miragenet. MIRAGENET_DIR overrides it
// (used by the selftest and scripting so tests never touch the real store).
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export const DEFAULT_PORTS = [2222, 2323, 8080];
export const DEFAULT_HTTP_PORT = 18080;

export function getDataDir() {
  const override = process.env.MIRAGENET_DIR;
  if (override && override.trim()) return path.resolve(override.trim());
  return path.join(os.homedir(), '.miragenet');
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

export function loadConfig(dataDir) {
  const cfg = {
    ports: [...DEFAULT_PORTS],
    httpPort: DEFAULT_HTTP_PORT,
    watchDirs: [],
    disabled: [],
    banners: {},
    httpTitle: 'Admin Login',
    notes: {},
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
      if (typeof j.httpTitle === 'string' && j.httpTitle.length > 0 && j.httpTitle.length <= 120) {
        cfg.httpTitle = j.httpTitle;
      }
      if (j.notes && typeof j.notes === 'object' && !Array.isArray(j.notes)) {
        for (const [k, v] of Object.entries(j.notes)) {
          if (Array.isArray(v)) cfg.notes[String(k)] = v.filter((n) => n && typeof n === 'object').slice(0, 200);
        }
      }
      // Preserve unknown future keys? No — strict schema keeps file clean.
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

export function appendEvent(dataDir, ev) {
  ensureDataDir(dataDir);
  fs.appendFileSync(eventsPath(dataDir), JSON.stringify(ev) + '\n', 'utf8');
}

export function readEvents(dataDir) {
  const out = [];
  try {
    const raw = fs.readFileSync(eventsPath(dataDir), 'utf8');
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try {
        out.push(JSON.parse(t));
      } catch {
        /* skip corrupt lines */
      }
    }
  } catch {
    /* no log file yet -> empty history */
  }
  return out;
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
