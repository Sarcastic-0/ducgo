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
  const cfg = { ports: [...DEFAULT_PORTS], httpPort: DEFAULT_HTTP_PORT, watchDirs: [] };
  try {
    const j = JSON.parse(fs.readFileSync(configPath(dataDir), 'utf8'));
    if (j && typeof j === 'object') {
      if (Array.isArray(j.ports)) {
        const p = j.ports.filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535).slice(0, 20);
        if (p.length > 0) cfg.ports = p;
      }
      if (Number.isInteger(j.httpPort) && j.httpPort >= 1 && j.httpPort <= 65535) cfg.httpPort = j.httpPort;
      if (Array.isArray(j.watchDirs)) cfg.watchDirs = [...new Set(j.watchDirs.map(String))];
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
