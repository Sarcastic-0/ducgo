// MirageNet v2 - honey TCP / honey HTTP / canary watch. Stdlib only.
// 100% passive/defensive: this module only listens on local ports, serves a
// fake login page, and watches files. It never scans, probes, or attacks.
import * as net from 'node:net';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export const CLOSE_AFTER_MS = 5000;
export const MAX_BANNER_BYTES = 256;

export function uid() {
  return crypto.randomBytes(8).toString('hex');
}

export function nowISO() {
  return new Date().toISOString();
}

export function makeEvent(type, trap, ip, detail, severity, meta) {
  const ev = { id: uid(), time: nowISO(), type, trap, ip, detail, severity };
  if (meta && typeof meta === 'object') ev.meta = meta;
  return ev;
}

export function makeDuressEvent() {
  return makeEvent(
    'duress',
    'duress-pin',
    '127.0.0.1',
    'Duress PIN was used - operator may be under pressure. Decoy view shown.',
    'critical',
    { silent: true }
  );
}

const DEMO_IPS = ['185.220.70.4', '45.148.10.88', '103.99.0.25', '91.240.118.41'];
const DEMO_TRAPS = ['honey-tcp:2222', 'honey-tcp:2323', 'honey-tcp:8080', 'honey-http:18080', 'canary:aws-keys.txt'];

// Clearly-labeled synthetic event so reviewers can see the output format.
export function createDemoEvent() {
  const ip = DEMO_IPS[Math.floor(Math.random() * DEMO_IPS.length)];
  const trap = DEMO_TRAPS[Math.floor(Math.random() * DEMO_TRAPS.length)];
  const detail = trap.startsWith('canary')
    ? `DEMO - simulated canary touch on ${trap}`
    : `DEMO - simulated probe on ${trap} from ${ip}`;
  return makeEvent('sim', trap, ip, detail, 'high', { demo: true });
}

export const FAKE_LOGIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Admin Login</title>
<style>body{font-family:Arial,sans-serif;background:#0b1220;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#111c33;padding:32px;border-radius:12px;width:320px;box-shadow:0 10px 40px rgba(0,0,0,.5)}
h2{margin:0 0 16px}input{width:100%;padding:10px;margin:6px 0;border-radius:6px;border:1px solid #334155;background:#0b1220;color:#fff;box-sizing:border-box}
button{width:100%;padding:10px;margin-top:10px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-weight:bold;cursor:pointer}</style>
</head><body><div class="card"><h2>Admin Login</h2>
<form method="POST" action="/login"><input name="username" placeholder="Username" autocomplete="off"><input name="password" type="password" placeholder="Password"><button type="submit">Sign in</button></form>
<p style="font-size:11px;color:#64748b">Restricted area. All access is logged.</p></div></body></html>`;

function fakeBanner(port, stealthKind) {
  // Stealth banners are IMITATIONS for deception (not real services):
  // they mimic common Nmap signatures to blend in. Marked as imitations.
  if (stealthKind === 'ssh') return 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n'; // imitation, not real OpenSSH
  if (stealthKind === 'ftp') return '220 FileZilla Server 1.7.0\r\n'; // imitation, not real FileZilla
  if (stealthKind === 'telnet') return 'Welcome to Microsoft Telnet Service\r\n'; // imitation, not real MS Telnet
  if (port === 2222) return 'SSH-2.0-OpenSSH_9.2 MirageNet\r\n';
  if (port === 2323) return 'Welcome to Telnet service. Login: ';
  return 'HTTP/1.1 200 OK\r\nServer: MirageNet/1.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
}

// Stealth banner catalog (imitations, documented as such).
export const STEALTH_BANNERS = {
  ssh: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n',
  ftp: '220 FileZilla Server 1.7.0\r\n',
  telnet: 'Welcome to Microsoft Telnet Service\r\n',
};

export function stealthBannerFor(kind) {
  const k = String(kind || '').toLowerCase();
  return STEALTH_BANNERS[k] || null;
}

// Fingerprint a grabbed banner against Nmap-style signatures + honeypot
// giveaways. Returns {verdict:'PASS'|'WARN', reasons:[...]}.
// PASS: matches a known stealth imitation (ssh/ftp/telnet above).
// WARN: empty, contains honey/ducgo/mirage/default texts, or unknown.
export function fingerprintBanner(bannerText) {
  const reasons = [];
  const s = String(bannerText || '');
  if (!s.trim()) {
    return { verdict: 'WARN', reasons: ['empty banner (honeypot giveaway: real services greet)'] };
  }
  const low = s.toLowerCase();
  if (low.includes('honey') || low.includes('ducgo') || low.includes('mirage') || low.includes('miragenet')) {
    reasons.push('contains honeypot keyword (honey/ducgo/mirage)');
  }
  if (s.includes('MirageNet/1.0') || s.includes('OpenSSH_9.2 MirageNet') || s.includes('Welcome to Telnet service. Login:')) {
    reasons.push('matches default ducgo banner text (giveaway)');
  }
  // Nmap-style realistic signatures (our stealth imitations):
  if (s.includes('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6')) {
    if (reasons.length === 0) return { verdict: 'PASS', reasons: ['matches stealth SSH imitation (Nmap-style OpenSSH signature)'] };
    reasons.push('ssh imitation present but mixed with giveaway text');
  }
  if (s.includes('220 FileZilla Server 1.7.0')) {
    if (reasons.length === 0) return { verdict: 'PASS', reasons: ['matches stealth FTP imitation (Nmap-style FileZilla signature)'] };
    reasons.push('ftp imitation present but mixed with giveaway text');
  }
  if (s.includes('Welcome to Microsoft Telnet Service')) {
    if (reasons.length === 0) return { verdict: 'PASS', reasons: ['matches stealth Telnet imitation (Nmap-style MS Telnet signature)'] };
    reasons.push('telnet imitation present but mixed with giveaway text');
  }
  // Generic realistic shapes (not giveaways) get a cautious PASS:
  if (reasons.length === 0) {
    if (/^SSH-2\.0-OpenSSH/i.test(s.trim())) return { verdict: 'PASS', reasons: ['SSH version string looks realistic (no giveaway keywords)'] };
    if (/^220\s+.+FTP/i.test(s.trim()) || /^220\s+FileZilla/i.test(s.trim())) return { verdict: 'PASS', reasons: ['FTP 220 greeting looks realistic (no giveaway keywords)'] };
    if (/telnet/i.test(s) && !/ducgo|mirage|honey/i.test(low)) return { verdict: 'PASS', reasons: ['Telnet greeting has no giveaway keywords'] };
    return { verdict: 'WARN', reasons: ['unknown banner shape (not a known stealth imitation, no Nmap-style match)'] };
  }
  return { verdict: 'WARN', reasons };
}

// ---------- ATIME WATCH (opt-in silent-read detection, complements fs.watch) ----------
// fs.watch reports modify/rename/delete only, NOT silent reads. atime-watch
// polls fs.statSync atimeMs vs a baseline (in-memory + persisted to
// <dataDir>/atime-baseline.json) and reports ACCESSED (atime newer,
// mtime/size unchanged) vs MODIFIED (mtime/size changed).
// Honest limits: noatime/relatime mounts and some filesystems (tmpfs,
// network FS) disable or coalesce atime. Check `mount | grep noatime` on
// Linux, `mount | grep noatime` / relatime on macOS. If atime never advances,
// this tool reports nothing (by design, not a bug).
export function atimeBaselinePath(dataDir) {
  return path.join(dataDir, 'atime-baseline.json');
}

export function snapshotAtimeDir(dir, recursive = true) {
  const out = {};
  const root = path.resolve(dir);
  const walk = (d) => {
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const fp = path.join(d, e.name);
      try {
        if (e.isDirectory()) { if (recursive) walk(fp); continue; }
        if (!e.isFile() && !e.isSymbolicLink()) continue;
        const st = fs.statSync(fp);
        if (!st.isFile()) continue;
        out[fp] = { atimeMs: st.atimeMs, mtimeMs: st.mtimeMs, size: st.size };
      } catch { /* ignore unreadable */ }
    }
  };
  walk(root);
  return out;
}

export function diffAtime(baseline, current) {
  const events = [];
  const base = baseline || {};
  const cur = current || {};
  for (const [fp, c] of Object.entries(cur)) {
    const b = base[fp];
    if (!b) { events.push({ path: fp, kind: 'CREATED', detail: `new file: ${fp}` }); continue; }
    const atimeNewer = Number(c.atimeMs) > Number(b.atimeMs) + 1;
    const mtimeSame = Number(c.mtimeMs) === Number(b.mtimeMs) && Number(c.size) === Number(b.size);
    const modified = Number(c.mtimeMs) !== Number(b.mtimeMs) || Number(c.size) !== Number(b.size);
    if (modified) {
      events.push({ path: fp, kind: 'MODIFIED', detail: `mtime/size changed: ${fp}` });
    } else if (atimeNewer && mtimeSame) {
      events.push({ path: fp, kind: 'ACCESSED', detail: `atime newer, content unchanged (silent read): ${fp}` });
    }
  }
  for (const fp of Object.keys(base)) {
    if (!(fp in cur)) events.push({ path: fp, kind: 'DELETED', detail: `deleted: ${fp}` });
  }
  return events;
}

export function loadAtimeBaseline(dataDir) {
  try {
    const j = JSON.parse(fs.readFileSync(atimeBaselinePath(dataDir), 'utf8'));
    if (j && typeof j === 'object') return j;
  } catch { /* none */ }
  return null;
}

export function saveAtimeBaseline(dataDir, snapshot) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(atimeBaselinePath(dataDir), JSON.stringify({ savedAt: new Date().toISOString(), files: snapshot }, null, 2), 'utf8');
}

function sanitizePreview(buf, max = MAX_BANNER_BYTES) {
  let s = buf.subarray(0, max).toString('utf8');
  s = s.replace(/[\u0000--]/g, '.');
  if (buf.length > max) s += ` ...(+${buf.length - max}B)`;
  return s;
}

function cleanIP(addr) {
  return String(addr ?? 'unknown').replace(/^::ffff:/, '');
}

// Honey TCP listener: sends a fake banner, logs the connection plus any
// banner-grab bytes (preview capped at 256B), then drops the socket after 5s.
// opts.bannerText overrides fakeBanner (stealth imitations); opts.stealth
// ('ssh'|'ftp'|'telnet') selects a stealth imitation.
export function startHoneyTcp(port, onEvent, opts = {}) {
  const host = opts.host ?? '0.0.0.0';
  const closeAfterMs = opts.closeAfterMs ?? CLOSE_AFTER_MS;
  const stealthKind = opts.stealth ? String(opts.stealth).toLowerCase() : null;
  const bannerOverride = opts.bannerText || (stealthKind ? stealthBannerFor(stealthKind) : null);
  let livePort = port;
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      const remoteIP = cleanIP(socket.remoteAddress);
      const remotePort = socket.remotePort ?? 0;
      const trap = `honey-tcp:${livePort}`;
      try {
        socket.write(bannerOverride || fakeBanner(livePort, stealthKind));
      } catch {
        /* ignore */
      }
      onEvent({
        ...makeEvent(
          'honey-tcp',
          trap,
          remoteIP,
          `Connection on fake port ${livePort} from ${remoteIP}:${remotePort}`,
          livePort === 2222 ? 'high' : 'medium',
          { port: livePort, remotePort }
        ),
        remoteIP,
        remotePort,
        bannerBytes: '',
      });
      socket.on('data', (d) => {
        const buf = Buffer.isBuffer(d) ? d : Buffer.from(d);
        const preview = sanitizePreview(buf);
        onEvent({
          ...makeEvent(
            'banner-grab',
            trap,
            remoteIP,
            `Banner grab on :${livePort} - ${buf.length}B: "${preview}"`,
            'high',
            { port: livePort, remotePort, bytes: buf.length, preview, bannerBytes: preview }
          ),
          remoteIP,
          remotePort,
          bannerBytes: preview,
        });
      });
      socket.on('error', () => {
        /* ignore resets */
      });
      const t = setTimeout(() => {
        try {
          socket.end();
        } catch {
          /* ignore */
        }
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
      }, closeAfterMs);
      socket.on('close', () => clearTimeout(t));
      try {
        socket.setTimeout(closeAfterMs + 1000);
      } catch {
        /* ignore */
      }
      socket.on('timeout', () => {
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
      });
    });
    server.on('error', reject);
    server.listen(port, host, () => {
      try {
        const a = server.address();
        if (a && typeof a === 'object' && a.port) livePort = a.port;
      } catch {
        /* keep requested port label */
      }
      resolve(server);
    });
  });
}

// Honey HTTP: fake "Admin Login" page on 127.0.0.1. Logs every request with
// {time, ip, method, path, userAgent, loginAttempted, username?}.
// Posted passwords are NEVER logged or stored - only a boolean flag.
export function startHoneyHttp(port, host, onEvent) {
  const bindHost = host ?? '127.0.0.1';
  let livePort = port;
  return new Promise((resolve, reject) => {
    const srv = http.createServer((req, res) => {
      const ip = cleanIP(req.socket.remoteAddress);
      const userAgent = String(req.headers['user-agent'] ?? '');
      const method = req.method ?? 'GET';
      const urlPath = (req.url ?? '/').split('?')[0];
      const trap = `honey-http:${livePort}`;

      if (method === 'POST' && (urlPath === '/login' || urlPath === '/')) {
        let body = '';
        req.on('data', (c) => {
          body += String(c);
          if (body.length > 8192) {
            try {
              req.destroy();
            } catch {
              /* ignore */
            }
          }
        });
        req.on('end', () => {
          const username = extractUsername(body, req.headers['content-type']);
          onEvent({
            ...makeEvent(
              'honey-http',
              trap,
              ip,
              `Fake-admin login attempt by "${username || 'unknown'}" - ${method} ${urlPath}`,
              'critical',
              {
                method,
                path: urlPath,
                userAgent: userAgent.slice(0, 300),
                username: (username || 'unknown').slice(0, 120),
                attempted: true,
              }
            ),
            method,
            path: urlPath,
            userAgent: userAgent.slice(0, 300),
            loginAttempted: true,
            username: (username || 'unknown').slice(0, 120),
          });
          res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(FAKE_LOGIN_PAGE.replace('Admin Login', 'Invalid credentials - try again'));
        });
        return;
      }

      onEvent({
        ...makeEvent(
          'honey-http',
          trap,
          ip,
          `${method} ${urlPath} on fake admin panel`,
          urlPath === '/' ? 'medium' : 'high',
          { method, path: urlPath, userAgent: userAgent.slice(0, 300) }
        ),
        method,
        path: urlPath,
        userAgent: userAgent.slice(0, 300),
        loginAttempted: false,
      });
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(FAKE_LOGIN_PAGE);
    });
    srv.on('error', reject);
    srv.listen(port, bindHost, () => {
      try {
        const a = srv.address();
        if (a && typeof a === 'object' && a.port) livePort = a.port;
      } catch {
        /* keep requested port label */
      }
      resolve(srv);
    });
  });
}

function extractUsername(body, ctype) {
  const ct = String(ctype ?? '');
  try {
    if (ct.includes('application/json')) {
      const j = JSON.parse(body);
      if (j && typeof j === 'object') {
        const u = j.username ?? j.user ?? j.email ?? j.login;
        return String(u ?? '').slice(0, 120);
      }
    }
  } catch {
    /* fall through to form parse */
  }
  const m = body.match(/(?:^|&)(?:username|user|email|login)=([^&]*)/i);
  if (m) {
    try {
      return decodeURIComponent(m[1].replace(/\+/g, ' ')).slice(0, 120);
    } catch {
      return m[1].slice(0, 120);
    }
  }
  return '';
}

export function getServerPort(srv) {
  try {
    const a = srv.address();
    return a && typeof a === 'object' ? a.port : 0;
  } catch {
    return 0;
  }
}

export function closeServer(srv) {
  return new Promise((resolve) => {
    if (!srv) return resolve();
    try {
      srv.close(() => resolve());
    } catch {
      resolve();
    }
    setTimeout(resolve, 800);
  });
}

// On Windows, watching a short (8.3) path like C:\Users\NAME~1\... with
// fs.watch crashes Node when an event fires (libuv fs-event.c prefix
// assertion: Windows reports the event with the long name). Always watch
// the long-path form. Pure stdlib: realpathSync.native + strip \\?\.
function toLongPath(p) {
  try {
    let r = fs.realpathSync.native(p);
    if (r.startsWith('\\\\?\\UNC\\')) r = '\\\\' + r.slice(8);
    else if (r.startsWith('\\\\?\\')) r = r.slice(4);
    return r;
  } catch {
    return p;
  }
}

// Watch deployed directories for modify/rename touches (fs.watch).
// NOTE: the OS only reports modify/rename/delete - silent reads trip nothing.
export function watchDirs(dirs, onEvent) {
  const watchers = [];
  for (const dir of dirs) {
    let target = dir;
    try {
      target = path.resolve(dir);
    } catch {
      continue;
    }
    try {
      if (!fs.statSync(target).isDirectory()) continue;
    } catch {
      continue;
    }
    try {
      const watchTarget = toLongPath(target);
      const w = fs.watch(watchTarget, (eventType, filename) => {
        const file = String(filename ?? 'unknown');
        const isCanary = /aws-keys|passwords|wallet-seed/i.test(file);
        const detail =
          eventType === 'rename'
            ? `Canary directory event (rename): ${file} in ${target} - file may have been deleted or renamed`
            : `Canary directory event (modify): ${file} in ${target} - file was modified`;
        onEvent(
          makeEvent('canary', `canary:${file}`, '127.0.0.1', detail, isCanary ? 'critical' : 'medium', {
            dir: target,
            file,
            event: String(eventType),
          })
        );
      });
      w.on('error', () => {
        /* watcher errors are non-fatal */
      });
      watchers.push(w);
    } catch {
      /* ignore unwatched */
    }
  }
  return watchers;
}

// Drop realistic decoy files with random CANARY tokens into dir.
export function deployCanaries(dir) {
  try {
    const target = path.resolve(dir);
    fs.mkdirSync(target, { recursive: true });
    const token = (p) => `MIRAGETOKEN-${crypto.randomBytes(6).toString('hex')}-${p}`;
    const files = [
      {
        name: 'aws-keys.txt',
        content: `# AWS credentials - ROTATED DECOY, NOT REAL\n# canary: ${token('aws')}\n[default]\naws_access_key_id = AKIAIOSFODNN7DECOY${crypto.randomBytes(3).toString('hex').toUpperCase()}\naws_secret_access_key = ${crypto.randomBytes(20).toString('base64')}\nregion = us-east-1\n# If you are reading this outside an authorized review, stop - this access is logged.\n`,
      },
      {
        name: 'passwords.csv',
        content: `site,username,password,canary\nvpn,admin,DECOY-NOT-REAL-${crypto.randomBytes(4).toString('hex')},${token('csv')}\nmail,backup,DECOY-NOT-REAL-${crypto.randomBytes(4).toString('hex')},${token('csv2')}\n# decoy file - any use of these credentials triggers an alert\n`,
      },
      {
        name: 'wallet-seed.txt',
        content: `BITCOIN WALLET SEED - DECOY, DO NOT USE, FUNDS DO NOT EXIST\ncanary: ${token('seed')}\n${Array.from({ length: 12 }, () => crypto.randomBytes(4).toString('hex')).join(' ')}\nContact security if you found this file unexpectedly.\n`,
      },
    ];
    const written = [];
    for (const f of files) {
      const fp = path.join(target, f.name);
      if (!fs.existsSync(fp)) fs.writeFileSync(fp, f.content, 'utf8');
      written.push(f.name);
    }
    return { ok: true, dir: target, files: written };
  } catch (err) {
    return { ok: false, dir, files: [], error: String((err && err.message) || err) };
  }
}
