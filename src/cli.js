#!/usr/bin/env node
// ducgo v2.0.0 - English-only, CLI-only passive deception tripwires.
// Node.js stdlib ONLY. Zero runtime dependencies. Exit codes: 0 ok, 1 error.
// Data dir stays %USERPROFILE%\.miragenet (MIRAGENET_DIR overrides for tests).
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as net from 'node:net';
import { fileURLToPath } from 'node:url';
import { isSetup, setupPins, verifyPin, loadAuth, changeAccessPin, changeDuressPin } from './auth.js';
import {
  getDataDir,
  ensureDataDir,
  loadConfig,
  saveConfig,
  addWatchDir,
  removeWatchDir,
  appendEvent,
  readEvents,
  eventsToCsv,
  configPath,
  eventsPath,
  authPath,
  dirSize,
  addAttackerNote,
  getAttackerNotes,
  DEFAULT_PORTS,
  DEFAULT_HTTP_PORT,
} from './store.js';
import {
  startHoneyTcp,
  startHoneyHttp,
  watchDirs,
  deployCanaries,
  createDemoEvent,
  makeDuressEvent,
  makeEvent,
  closeServer,
  getServerPort,
  FAKE_LOGIN_PAGE,
} from './traps.js';
import * as ui from './ui.js';

const VERSION = '2.0.0';
const DURESS_MESSAGE = 'All clear - no threats detected.';

// ---------- command registry (exactly 70) ----------
export const COMMANDS = [
  // auth (7)
  { name: 'setup', group: 'auth', desc: 'Set access PIN + duress PIN (interactive)', usage: 'ducgo setup' },
  { name: 'login-test', group: 'auth', desc: 'Verify a PIN without revealing which one', usage: 'ducgo login-test' },
  { name: 'change-pin', group: 'auth', desc: 'Change the access PIN (needs current PIN)', usage: 'ducgo change-pin' },
  { name: 'change-duress', group: 'auth', desc: 'Change the duress PIN (needs current PIN)', usage: 'ducgo change-duress' },
  { name: 'lock-status', group: 'auth', desc: 'Show whether auth is set up (no PIN needed)', usage: 'ducgo lock-status' },
  { name: 'auth-status', group: 'auth', desc: 'Show auth state + data dir (whoami-style)', usage: 'ducgo auth-status' },
  { name: 'reset-all', group: 'auth', desc: 'Delete auth (PIN + double confirmation)', usage: 'ducgo reset-all' },
  // engine (4)
  { name: 'start', group: 'engine', desc: 'Unlock with PIN, run trap mesh foreground until Ctrl+C', usage: 'ducgo start [--ports 2222,2323,8080] [--http 18080]' },
  { name: 'status', group: 'engine', desc: 'Check which configured ports are listening', usage: 'ducgo status' },
  { name: 'ports-list', group: 'engine', desc: 'List configured honey ports', usage: 'ducgo ports-list' },
  { name: 'engine-check', group: 'engine', desc: 'Check if configured ports are free to bind', usage: 'ducgo engine-check' },
  // traps (9)
  { name: 'trap-list', group: 'traps', desc: 'List honey TCP traps + enabled state', usage: 'ducgo trap-list' },
  { name: 'trap-add', group: 'traps', desc: 'Add a honey TCP port (needs PIN)', usage: 'ducgo trap-add <port>' },
  { name: 'trap-remove', group: 'traps', desc: 'Remove a honey TCP port (needs PIN)', usage: 'ducgo trap-remove <port>' },
  { name: 'trap-enable', group: 'traps', desc: 'Re-enable a disabled trap (needs PIN)', usage: 'ducgo trap-enable <port>' },
  { name: 'trap-disable', group: 'traps', desc: 'Disable a trap without deleting it (needs PIN)', usage: 'ducgo trap-disable <port>' },
  { name: 'http-show', group: 'traps', desc: 'Print the fake admin panel preview', usage: 'ducgo http-show' },
  { name: 'http-config', group: 'traps', desc: 'Configure honey HTTP port/title (needs PIN)', usage: 'ducgo http-config [--port N] [--title TEXT]' },
  { name: 'banner-set', group: 'traps', desc: 'Set a custom banner label for a port (needs PIN)', usage: 'ducgo banner-set <port> <text>' },
  { name: 'banner-show', group: 'traps', desc: 'Show banner for a port (or all)', usage: 'ducgo banner-show [port]' },
  // canary (6)
  { name: 'deploy', group: 'canary', desc: 'Drop decoy files into <dir> + watch it (needs PIN)', usage: 'ducgo deploy <dir>' },
  { name: 'canary-list', group: 'canary', desc: 'List watched dirs + decoy files present', usage: 'ducgo canary-list' },
  { name: 'canary-verify', group: 'canary', desc: 'Verify decoys still carry canary tokens', usage: 'ducgo canary-verify' },
  { name: 'canary-refresh', group: 'canary', desc: 'Regenerate decoy tokens (needs PIN)', usage: 'ducgo canary-refresh [dir]' },
  { name: 'canary-remove', group: 'canary', desc: 'Unwatch a dir, optionally delete decoys', usage: 'ducgo canary-remove <dir> [--delete]' },
  { name: 'canary-show', group: 'canary', desc: 'Print the canary token of a file', usage: 'ducgo canary-show <file>' },
  // events (7)
  { name: 'events', group: 'events', desc: 'Show event history (table/json/export)', usage: 'ducgo events [--json] [--export out.csv]' },
  { name: 'events-tail', group: 'events', desc: 'Show last N events, optionally follow live', usage: 'ducgo events-tail [--lines N] [--follow]' },
  { name: 'event-show', group: 'events', desc: 'Show one event by id', usage: 'ducgo event-show <id>' },
  { name: 'events-clear', group: 'events', desc: 'Clear the event log (PIN + confirm)', usage: 'ducgo events-clear' },
  { name: 'events-export', group: 'events', desc: 'Export events to CSV or JSON file', usage: 'ducgo events-export <file> [--format csv|json]' },
  { name: 'events-import', group: 'events', desc: 'Import events from a JSON/JSONL file', usage: 'ducgo events-import <file>' },
  { name: 'events-stats', group: 'events', desc: 'Counts by type/severity/trap', usage: 'ducgo events-stats' },
  // attackers (5)
  { name: 'attackers', group: 'attackers', desc: 'Group touches by IP', usage: 'ducgo attackers' },
  { name: 'attacker-show', group: 'attackers', desc: 'Show timeline for one IP', usage: 'ducgo attacker-show <ip>' },
  { name: 'attacker-note', group: 'attackers', desc: 'Attach a text note to an IP', usage: 'ducgo attacker-note <ip> <text...>' },
  { name: 'attacker-list-notes', group: 'attackers', desc: 'List attacker notes (optionally one IP)', usage: 'ducgo attacker-list-notes [ip]' },
  { name: 'top-attackers', group: 'attackers', desc: 'Top N attacker IPs by touches', usage: 'ducgo top-attackers [--limit N]' },
  // reports (4)
  { name: 'report-daily', group: 'reports', desc: 'Events from the last 24h, grouped', usage: 'ducgo report-daily' },
  { name: 'report-summary', group: 'reports', desc: 'Overall summary (totals, range, severity)', usage: 'ducgo report-summary' },
  { name: 'report-top', group: 'reports', desc: 'Top traps + top attacker IPs', usage: 'ducgo report-top [--limit N]' },
  { name: 'report-export', group: 'reports', desc: 'Write a Markdown report to a file', usage: 'ducgo report-export <file>' },
  // config (8)
  { name: 'config-set', group: 'config', desc: 'Set a config key (needs PIN)', usage: 'ducgo config-set <key> <value>' },
  { name: 'config-get', group: 'config', desc: 'Get a config key (needs PIN)', usage: 'ducgo config-get <key>' },
  { name: 'config-list', group: 'config', desc: 'List full config (needs PIN)', usage: 'ducgo config-list' },
  { name: 'config-reset', group: 'config', desc: 'Reset config to defaults (needs PIN)', usage: 'ducgo config-reset' },
  { name: 'data-dir', group: 'config', desc: 'Print the data directory path', usage: 'ducgo data-dir' },
  { name: 'data-size', group: 'config', desc: 'Print data dir file sizes', usage: 'ducgo data-size' },
  { name: 'config-export', group: 'config', desc: 'Export config.json to a file', usage: 'ducgo config-export <file>' },
  { name: 'config-import', group: 'config', desc: 'Import config.json from a file', usage: 'ducgo config-import <file>' },
  // system (20)
  { name: 'help', group: 'system', desc: 'Show help (banner + usage)', usage: 'ducgo help [command]' },
  { name: 'banner', group: 'system', desc: 'Print the DUCGO banner', usage: 'ducgo banner' },
  { name: 'version', group: 'system', desc: 'Print version', usage: 'ducgo version' },
  { name: 'commands', group: 'system', desc: 'List commands grouped, or --count', usage: 'ducgo commands [--count]' },
  { name: 'doctor', group: 'system', desc: 'Environment + config health checks', usage: 'ducgo doctor' },
  { name: 'selftest', group: 'system', desc: 'Run the built-in selftest suite', usage: 'ducgo selftest' },
  { name: 'demo', group: 'system', desc: 'Record one synthetic DEMO event (no PIN)', usage: 'ducgo demo' },
  { name: 'about', group: 'system', desc: 'About ducgo + honest limits', usage: 'ducgo about' },
  { name: 'backup', group: 'system', desc: 'Back up auth+config+events to a file', usage: 'ducgo backup <file>' },
  { name: 'restore', group: 'system', desc: 'Restore a backup file (PIN + confirm)', usage: 'ducgo restore <file>' },
  { name: 'wipe', group: 'system', desc: 'Factory reset everything (PIN + type WIPE)', usage: 'ducgo wipe' },
  { name: 'log-path', group: 'system', desc: 'Print the events.jsonl path', usage: 'ducgo log-path' },
  { name: 'sysinfo', group: 'system', desc: 'Print Node/OS/platform info', usage: 'ducgo sysinfo' },
  { name: 'uptime', group: 'system', desc: 'Print process uptime + store age', usage: 'ducgo uptime' },
  { name: 'tips', group: 'system', desc: 'Practical usage tips', usage: 'ducgo tips' },
  { name: 'license', group: 'system', desc: 'Print license summary', usage: 'ducgo license' },
  { name: 'verify-install', group: 'system', desc: 'Verify bin, shebang, node, data dir', usage: 'ducgo verify-install' },
  { name: 'paths', group: 'system', desc: 'Print all store paths', usage: 'ducgo paths' },
  { name: 'stats', group: 'system', desc: 'Global overview (events/attackers/traps)', usage: 'ducgo stats' },
  { name: 'support', group: 'system', desc: 'Support + scope info', usage: 'ducgo support' },
];
export const COMMAND_NAMES = COMMANDS.map((c) => c.name);
export const COMMAND_COUNT = COMMANDS.length;

function findCmd(name) {
  return COMMANDS.find((c) => c.name === name) || null;
}

// ---------- arg helpers (hand-rolled, no deps) ----------
function takeFlagValue(rest, names) {
  for (let i = 0; i < rest.length; i++) {
    for (const n of names) {
      if (rest[i] === n && i + 1 < rest.length) return rest[i + 1];
      if (rest[i].startsWith(n + '=')) return rest[i].slice(n.length + 1);
    }
  }
  return null;
}
function hasFlag(rest, names) {
  return rest.some((a) => names.includes(a));
}
function firstPositional(rest) {
  return rest.find((a) => !a.startsWith('-')) ?? null;
}
function positionals(rest) {
  return rest.filter((a) => !a.startsWith('-'));
}
function wantsHelp(rest) {
  return hasFlag(rest, ['--help', '-h']);
}
function parsePortList(raw) {
  const ports = [];
  for (const part of String(raw).split(',')) {
    const t = part.trim();
    if (!t) continue;
    const n = Number(t);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      return { ok: false, error: `Invalid port: "${t}" (must be 1-65535)` };
    }
    if (!ports.includes(n)) ports.push(n);
  }
  if (ports.length === 0) return { ok: false, error: 'No ports given' };
  if (ports.length > 20) return { ok: false, error: 'Too many ports (max 20)' };
  return { ok: true, ports };
}
function fail(msg) {
  ui.err(msg);
  process.exit(1);
}

// ---------- hidden PIN prompt (stdin raw mode, no echo) ----------
let pipedLines = null;
let pipedIdx = 0;
function readPipedLine(query) {
  process.stdout.write(query);
  if (pipedLines === null) {
    try {
      pipedLines = fs.readFileSync(0, 'utf8').split(/\r?\n/);
    } catch {
      pipedLines = [];
    }
  }
  const line = pipedIdx < pipedLines.length ? pipedLines[pipedIdx++] : '';
  process.stdout.write('******\n');
  return Promise.resolve(line.replace(/\r$/, ''));
}
function promptHidden(query) {
  if (!process.stdin.isTTY) return readPipedLine(query);
  return new Promise((resolve) => {
    process.stdout.write(query);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    let buf = '';
    const onData = (chunk) => {
      const s = chunk.toString('utf8');
      for (const ch of s) {
        if (ch === '\r' || ch === '\n') {
          process.stdout.write('\n');
          try { stdin.setRawMode(false); } catch { /* ignore */ }
          stdin.pause();
          stdin.removeListener('data', onData);
          resolve(buf);
          return;
        }
        if (ch === '') {
          process.stdout.write('\n');
          try { stdin.setRawMode(false); } catch { /* ignore */ }
          process.exit(1);
        }
        if (ch === '' || ch === '\b') {
          if (buf.length > 0) { buf = buf.slice(0, -1); process.stdout.write('\b \b'); }
          continue;
        }
        if (ch >= ' ') { buf += ch; process.stdout.write('*'); }
      }
    };
    stdin.on('data', onData);
  });
}
function promptLine(query) {
  if (!process.stdin.isTTY) return readPipedLine(query);
  return new Promise((resolve) => {
    process.stdout.write(query);
    const stdin = process.stdin;
    stdin.resume();
    let buf = '';
    const onData = (chunk) => {
      const s = chunk.toString('utf8');
      buf += s;
      if (buf.includes('\n')) {
        stdin.pause();
        stdin.removeListener('data', onData);
        resolve(buf.split(/\r?\n/)[0]);
      }
    };
    stdin.on('data', onData);
  });
}

// ---------- auth gate (duress handled here for EVERY auth prompt) ----------
function handleDuress(dataDir) {
  try {
    appendEvent(dataDir, makeDuressEvent());
  } catch { /* silent log is best-effort */ }
  console.log(DURESS_MESSAGE);
  process.exit(0);
}
async function requireAuth(dataDir) {
  if (!isSetup(dataDir)) {
    console.error('Not set up yet. Run "ducgo setup" first.');
    process.exit(1);
  }
  const pin = await promptHidden('Enter PIN: ');
  const r = verifyPin(dataDir, pin || '');
  if (r === 'normal') return;
  if (r === 'duress') handleDuress(dataDir);
  console.error('Incorrect PIN.');
  process.exit(1);
}

// ---------- shared printers ----------
function printGroupedCommands() {
  ui.printBanner();
  console.log('');
  const groups = ['auth', 'engine', 'traps', 'canary', 'events', 'attackers', 'reports', 'config', 'system'];
  for (const g of groups) {
    console.log(ui.bold(`[${g}]`));
    for (const c of COMMANDS.filter((x) => x.group === g)) {
      console.log(`  ${c.name.padEnd(20)} ${ui.dim(c.desc)}`);
    }
    console.log('');
  }
  console.log(ui.dim(`Total: ${COMMANDS.length} commands. Try "ducgo help <command>".`));
}
function printHelp() {
  ui.printBanner();
  console.log('');
  console.log(`ducgo v${VERSION} - passive deception tripwires (CLI only, English only)`);
  console.log('');
  console.log('Usage: ducgo <command> [options]   (every command supports --help)');
  console.log('');
  console.log(ui.bold('Quick start:'));
  console.log('  ducgo setup              Set access PIN + duress PIN');
  console.log('  ducgo deploy ./decoys    Drop canary files + watch the dir');
  console.log('  ducgo start              Run the trap mesh live until Ctrl+C');
  console.log('  ducgo events             Review recorded touches');
  console.log('  ducgo attackers          Group touches by IP');
  console.log('');
  console.log(ui.bold('Groups: auth(7) engine(4) traps(9) canary(6) events(7) attackers(5) reports(4) config(8) system(20) = 70'));
  console.log('Run "ducgo commands" for the full grouped list, "ducgo help <command>" for details.');
  console.log('');
  console.log(ui.dim('Duress: entering the duress PIN at any PIN prompt shows a fake all-clear and records a silent alert.'));
  console.log(ui.dim('Data: %USERPROFILE%\\.miragenet\\ (auth.json, events.jsonl, config.json). MIRAGENET_DIR overrides it.'));
  console.log(ui.dim('Engine runs foreground only - press Ctrl+C to stop. No daemon/background mode.'));
  console.log(ui.dim('Colors: set NO_COLOR=1 to disable ANSI colors. Exit codes: 0 ok, 1 error.'));
}
function cmdUsage(name) {
  const c = findCmd(name);
  if (!c) { console.error(`Unknown command: ${name}`); process.exit(1); }
  ui.printBanner();
  console.log('');
  console.log(ui.bold(`ducgo ${c.name}`) + ` - ${c.desc}`);
  console.log(`Usage: ${c.usage}`);
}
function groupByIp(events) {
  const groups = new Map();
  for (const e of events) {
    if (!e || e.type === 'system') continue;
    const ip = String(e.ip || 'unknown');
    let g = groups.get(ip);
    if (!g) { g = { ip, touches: 0, first: e.time, last: e.time, traps: new Map(), timeline: [] }; groups.set(ip, g); }
    g.touches += 1;
    if (e.time < g.first) g.first = e.time;
    if (e.time > g.last) g.last = e.time;
    g.traps.set(e.trap, (g.traps.get(e.trap) || 0) + 1);
    g.timeline.push(e);
  }
  return [...groups.values()].map((g) => {
    let top = ''; let topN = -1;
    for (const [trap, n] of g.traps) if (n > topN) { topN = n; top = trap; }
    return { ...g, top };
  }).sort((a, b) => b.touches - a.touches);
}
function defaultBannerFor(port) {
  if (port === 2222) return 'SSH-2.0-OpenSSH_9.2 ducgo';
  if (port === 2323) return 'Welcome to Telnet service. Login: ';
  return 'HTTP/1.1 200 OK (fake, connection closes)';
}
function checkPortListening(port, host, timeoutMs = 800) {
  return new Promise((resolve) => {
    const s = net.connect({ port, host }, () => { try { s.destroy(); } catch { /* ignore */ } resolve(true); });
    s.on('error', () => { try { s.destroy(); } catch { /* ignore */ } resolve(false); });
    s.setTimeout(timeoutMs, () => { try { s.destroy(); } catch { /* ignore */ } resolve(false); });
  });
}
function checkPortFree(port, timeoutMs = 800) {
  return new Promise((resolve) => {
    let srv = null;
    try {
      srv = net.createServer();
      srv.once('error', () => { resolve(false); });
      srv.listen(port, '127.0.0.1', () => { try { srv.close(() => resolve(true)); } catch { resolve(true); } });
      setTimeout(() => { try { srv.close(); } catch { /* ignore */ } resolve(false); }, timeoutMs);
    } catch { resolve(false); }
  });
}

// ================= AUTH =================
async function cmdSetup(rest) {
  if (wantsHelp(rest)) return cmdUsage('setup');
  const dataDir = getDataDir();
  ui.info(`Data directory: ${dataDir}`);
  if (isSetup(dataDir)) fail(`Already set up (${dataDir}). Use "ducgo reset-all" to reset.`);
  const pin = await promptHidden('Set access PIN (min 6 chars): ');
  const pin2 = await promptHidden('Confirm access PIN: ');
  if (!pin || pin.length < 6) fail('PIN must be at least 6 characters.');
  if (pin !== pin2) fail('PINs do not match.');
  const duress = await promptHidden('Set duress PIN (min 6 chars, must differ): ');
  const duress2 = await promptHidden('Confirm duress PIN: ');
  if (!duress || duress.length < 6) fail('Duress PIN must be at least 6 characters.');
  if (duress !== duress2) fail('Duress PINs do not match.');
  const r = setupPins(dataDir, pin, duress);
  if (!r.ok) fail(r.error || 'Setup failed.');
  ui.ok(`Setup complete. Data directory: ${dataDir}`);
  ui.info('Run "ducgo start" to arm the trap mesh.');
}
async function cmdLoginTest(rest) {
  if (wantsHelp(rest)) return cmdUsage('login-test');
  const dataDir = getDataDir();
  if (!isSetup(dataDir)) fail('Not set up yet. Run "ducgo setup" first.');
  const pin = await promptHidden('Enter PIN: ');
  const r = verifyPin(dataDir, pin || '');
  if (r === 'duress') handleDuress(dataDir);
  if (r === 'normal') { ui.ok('PIN accepted.'); return; }
  fail('Incorrect PIN.');
}
async function cmdChangePin(rest) {
  if (wantsHelp(rest)) return cmdUsage('change-pin');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const np = await promptHidden('New access PIN (min 6 chars): ');
  const np2 = await promptHidden('Confirm new access PIN: ');
  if (np !== np2) fail('PINs do not match.');
  const r = changeAccessPin(dataDir, np);
  if (!r.ok) fail(r.error || 'Change failed.');
  ui.ok('Access PIN changed.');
}
async function cmdChangeDuress(rest) {
  if (wantsHelp(rest)) return cmdUsage('change-duress');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const np = await promptHidden('New duress PIN (min 6 chars, must differ): ');
  const np2 = await promptHidden('Confirm new duress PIN: ');
  if (np !== np2) fail('Duress PINs do not match.');
  const r = changeDuressPin(dataDir, np);
  if (!r.ok) fail(r.error || 'Change failed.');
  ui.ok('Duress PIN changed.');
}
async function cmdLockStatus(rest) {
  if (wantsHelp(rest)) return cmdUsage('lock-status');
  const dataDir = getDataDir();
  const setup = isSetup(dataDir);
  console.log(ui.box('lock-status', [setup ? 'state: LOCKED (PIN required, auth is set up)' : 'state: NOT SET UP (run "ducgo setup")', `data dir: ${dataDir}`]));
}
async function cmdAuthStatus(rest) {
  if (wantsHelp(rest)) return cmdUsage('auth-status');
  const dataDir = getDataDir();
  const st = loadAuth(dataDir);
  if (!st) {
    console.log(ui.box('auth-status', ['setup: no', `data dir: ${dataDir}`, 'hint: run "ducgo setup"']));
    return;
  }
  console.log(ui.box('auth-status', ['setup: yes', `data dir: ${dataDir}`, `created: ${st.createdAt || 'unknown'}`, 'mode: stateless CLI (each command re-authenticates)']));
}
async function cmdResetAll(rest) {
  if (wantsHelp(rest)) return cmdUsage('reset-all');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const a = await promptLine('Type RESET to confirm (1/2): ');
  const b = await promptLine('Type RESET again to confirm (2/2): ');
  if (a.trim() !== 'RESET' || b.trim() !== 'RESET') fail('Reset aborted (confirmation mismatch).');
  try { fs.unlinkSync(authPath(dataDir)); } catch { fail('Reset failed (auth file missing?).'); }
  ui.ok('Auth deleted. Run "ducgo setup" to set new PINs.');
}

// ================= ENGINE =================
async function cmdStart(rest) {
  if (wantsHelp(rest)) return cmdUsage('start');
  const dataDir = getDataDir();
  const cfg = loadConfig(dataDir);
  let ports = [...cfg.ports];
  let httpPort = cfg.httpPort;
  const portsRaw = takeFlagValue(rest, ['--ports']);
  const httpRaw = takeFlagValue(rest, ['--http']);
  if (portsRaw !== null) {
    const r = parsePortList(portsRaw);
    if (!r.ok) fail(r.error);
    ports = r.ports;
  }
  if (httpRaw !== null) {
    const n = Number(String(httpRaw).trim());
    if (!Number.isInteger(n) || n < 1 || n > 65535) fail(`Invalid HTTP port: "${httpRaw}" (must be 1-65535)`);
    httpPort = n;
  }
  await requireAuth(dataDir);
  ensureDataDir(dataDir);
  if (portsRaw !== null || httpRaw !== null) saveConfig(dataDir, { ...loadConfig(dataDir), ports, httpPort });
  const liveCfg = loadConfig(dataDir);
  const enabledPorts = ports.filter((p) => !liveCfg.disabled.includes(`honey-tcp:${p}`));
  if (enabledPorts.length !== ports.length) ui.warn(`Skipping disabled trap(s): ${ports.filter((p) => liveCfg.disabled.includes(`honey-tcp:${p}`)).join(', ')}`);
  ui.info(`Engine foreground only - press Ctrl+C to stop. No daemon mode.`);
  const emit = (ev) => {
    try { appendEvent(dataDir, ev); } catch { /* best effort */ }
    ui.printEvent(ev);
  };
  const servers = [];
  for (const port of enabledPorts) {
    try {
      const srv = await startHoneyTcp(port, emit);
      servers.push(srv);
      const custom = liveCfg.banners[String(port)];
      ui.ok(`Listening: honey TCP :${port} (LAN-visible by design)${custom ? ` [custom banner: ${custom.slice(0, 60)}]` : ''}`);
    } catch (err) {
      emit(makeEvent('system', `honey-tcp:${port}`, '127.0.0.1', `Port ${port} unavailable (${(err && err.code) || (err && err.message) || err}) - continuing without it`, 'medium'));
    }
  }
  try {
    const httpSrv = await startHoneyHttp(httpPort, '127.0.0.1', emit);
    servers.push(httpSrv);
    ui.ok(`Listening: honey HTTP 127.0.0.1:${httpPort} (fake ${liveCfg.httpTitle || 'Admin Login'})`);
  } catch (err) {
    emit(makeEvent('system', 'honey-http', '127.0.0.1', `Honey HTTP unavailable: ${String((err && err.message) || err)}`, 'medium'));
  }
  const watchCfg = loadConfig(dataDir);
  const liveDirs = watchCfg.watchDirs.filter((d) => { try { return fs.statSync(d).isDirectory(); } catch { return false; } });
  const watchers = watchDirs(liveDirs, emit);
  if (liveDirs.length > 0) ui.ok(`Watching ${liveDirs.length} canary directorie(s): ${liveDirs.join(', ')}`);
  else ui.dim('No canary directories deployed. Use "ducgo deploy <dir>" to add tripwires.');
  emit(makeEvent('system', 'engine', '127.0.0.1', `Trap mesh started - TCP [${enabledPorts.join(', ')}], HTTP 127.0.0.1:${httpPort}`, 'low'));
  console.log(ui.bold('Trap mesh running. Press Ctrl+C to stop.'));
  let stopping = false;
  const cleanupAndExit = async (code) => {
    if (stopping) return;
    stopping = true;
    for (const w of watchers) { try { w.close(); } catch { /* ignore */ } }
    for (const s of servers) await closeServer(s);
    try { appendEvent(dataDir, makeEvent('system', 'engine', '127.0.0.1', 'Trap mesh stopped', 'low')); } catch { /* ignore */ }
    ui.dim('\nTrap mesh stopped.');
    process.exit(code);
  };
  process.on('SIGINT', () => { void cleanupAndExit(0); });
  process.on('SIGTERM', () => { void cleanupAndExit(0); });
  await new Promise(() => {});
}
async function cmdStatus(rest) {
  if (wantsHelp(rest)) return cmdUsage('status');
  const dataDir = getDataDir();
  const cfg = loadConfig(dataDir);
  const rows = [];
  for (const p of cfg.ports) {
    const disabled = cfg.disabled.includes(`honey-tcp:${p}`);
    const listening = disabled ? false : await checkPortListening(p, '127.0.0.1');
    rows.push([`:${p}`, disabled ? 'disabled' : (listening ? 'LISTENING' : 'closed'), cfg.banners[String(p)] ? 'custom' : 'default']);
  }
  const httpListening = await checkPortListening(cfg.httpPort, '127.0.0.1');
  rows.push([`http 127.0.0.1:${cfg.httpPort}`, httpListening ? 'LISTENING' : 'closed', cfg.httpTitle || 'Admin Login']);
  console.log(ui.box('engine status', [`data dir: ${dataDir}`, `watch dirs: ${cfg.watchDirs.length}`, httpListening || rows.some((r) => r[1] === 'LISTENING') ? 'mesh: ACTIVE (at least one listener up)' : 'mesh: IDLE (foreground "ducgo start" not running)']));
  console.log(ui.table(['ENDPOINT', 'STATE', 'NOTE'], rows));
}
async function cmdPortsList(rest) {
  if (wantsHelp(rest)) return cmdUsage('ports-list');
  const cfg = loadConfig(getDataDir());
  console.log(ui.table(['HONEY TCP PORTS', 'HONEY HTTP'], [[cfg.ports.join(', '), `127.0.0.1:${cfg.httpPort}`]]));
  ui.dim('Honey TCP binds 0.0.0.0 by design (LAN-visible); honey HTTP binds 127.0.0.1 only.');
}
async function cmdEngineCheck(rest) {
  if (wantsHelp(rest)) return cmdUsage('engine-check');
  const cfg = loadConfig(getDataDir());
  const rows = [];
  for (const p of cfg.ports) rows.push([`:${p}`, (await checkPortFree(p)) ? 'free' : 'IN USE']);
  rows.push([`http :${cfg.httpPort}`, (await checkPortFree(cfg.httpPort)) ? 'free' : 'IN USE']);
  console.log(ui.table(['PORT', 'BIND CHECK (127.0.0.1)'], rows));
  ui.dim('IN USE means "ducgo start" would log a system event for that port and keep the rest running.');
}

// ================= TRAPS =================
async function cmdTrapList(rest) {
  if (wantsHelp(rest)) return cmdUsage('trap-list');
  const cfg = loadConfig(getDataDir());
  const rows = cfg.ports.map((p) => [`honey-tcp:${p}`, cfg.disabled.includes(`honey-tcp:${p}`) ? 'disabled' : 'enabled', cfg.banners[String(p)] || defaultBannerFor(p)]);
  rows.push(['honey-http', 'enabled', cfg.httpTitle || 'Admin Login']);
  console.log(ui.table(['TRAP', 'STATE', 'BANNER / TITLE'], rows));
}
async function cmdTrapAdd(rest) {
  if (wantsHelp(rest)) return cmdUsage('trap-add');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const raw = firstPositional(rest);
  if (!raw) fail('Usage: ducgo trap-add <port>');
  const n = Number(String(raw).trim());
  if (!Number.isInteger(n) || n < 1 || n > 65535) fail(`Invalid port: "${raw}" (must be 1-65535)`);
  const cfg = loadConfig(dataDir);
  if (cfg.ports.includes(n)) fail(`Port ${n} is already a trap.`);
  if (cfg.ports.length >= 20) fail('Too many traps (max 20).');
  cfg.ports.push(n);
  saveConfig(dataDir, cfg);
  ui.ok(`Trap added: honey-tcp:${n}`);
}
async function cmdTrapRemove(rest) {
  if (wantsHelp(rest)) return cmdUsage('trap-remove');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const raw = firstPositional(rest);
  if (!raw) fail('Usage: ducgo trap-remove <port>');
  const n = Number(String(raw).trim());
  const cfg = loadConfig(dataDir);
  if (!cfg.ports.includes(n)) fail(`No such trap: ${n}`);
  cfg.ports = cfg.ports.filter((p) => p !== n);
  if (cfg.ports.length === 0) cfg.ports = [...DEFAULT_PORTS];
  cfg.disabled = cfg.disabled.filter((d) => d !== `honey-tcp:${n}`);
  saveConfig(dataDir, cfg);
  ui.ok(`Trap removed: ${n}`);
}
async function cmdTrapEnable(rest) {
  if (wantsHelp(rest)) return cmdUsage('trap-enable');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const raw = firstPositional(rest);
  if (!raw) fail('Usage: ducgo trap-enable <port>');
  const cfg = loadConfig(dataDir);
  cfg.disabled = cfg.disabled.filter((d) => d !== `honey-tcp:${Number(raw)}`);
  saveConfig(dataDir, cfg);
  ui.ok(`Trap enabled: honey-tcp:${raw}`);
}
async function cmdTrapDisable(rest) {
  if (wantsHelp(rest)) return cmdUsage('trap-disable');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const raw = firstPositional(rest);
  if (!raw) fail('Usage: ducgo trap-disable <port>');
  const n = Number(String(raw).trim());
  const cfg = loadConfig(dataDir);
  if (!cfg.ports.includes(n)) fail(`No such trap: ${raw}`);
  const key = `honey-tcp:${n}`;
  if (!cfg.disabled.includes(key)) cfg.disabled.push(key);
  saveConfig(dataDir, cfg);
  ui.ok(`Trap disabled: ${key} (kept in config, skipped at start)`);
}
async function cmdHttpShow(rest) {
  if (wantsHelp(rest)) return cmdUsage('http-show');
  const cfg = loadConfig(getDataDir());
  ui.info(`Fake panel on 127.0.0.1:${cfg.httpPort} - title "${cfg.httpTitle || 'Admin Login'}" (posted passwords are never stored)`);
  const preview = FAKE_LOGIN_PAGE.replace('Admin Login', cfg.httpTitle || 'Admin Login').slice(0, 600);
  console.log(ui.box('http-show (fake panel preview)', preview.split('\n').slice(0, 12)));
}
async function cmdHttpConfig(rest) {
  if (wantsHelp(rest)) return cmdUsage('http-config');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const cfg = loadConfig(dataDir);
  const portRaw = takeFlagValue(rest, ['--port', '--http']);
  const titleRaw = takeFlagValue(rest, ['--title']);
  if (portRaw === null && titleRaw === null) fail('Usage: ducgo http-config [--port N] [--title TEXT]');
  if (portRaw !== null) {
    const n = Number(String(portRaw).trim());
    if (!Number.isInteger(n) || n < 1 || n > 65535) fail(`Invalid HTTP port: "${portRaw}"`);
    cfg.httpPort = n;
  }
  if (titleRaw !== null) {
    if (!titleRaw.trim() || titleRaw.length > 120) fail('Title must be 1-120 chars.');
    cfg.httpTitle = titleRaw.trim();
  }
  saveConfig(dataDir, cfg);
  ui.ok(`Honey HTTP: 127.0.0.1:${cfg.httpPort} title "${cfg.httpTitle}"`);
}
async function cmdBannerSet(rest) {
  if (wantsHelp(rest)) return cmdUsage('banner-set');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const pos = positionals(rest);
  if (pos.length < 2) fail('Usage: ducgo banner-set <port> <text>');
  const n = Number(String(pos[0]).trim());
  if (!Number.isInteger(n) || n < 1 || n > 65535) fail(`Invalid port: "${pos[0]}"`);
  const text = pos.slice(1).join(' ').slice(0, 200);
  if (!text.trim()) fail('Banner text must not be empty.');
  const cfg = loadConfig(dataDir);
  cfg.banners[String(n)] = text;
  saveConfig(dataDir, cfg);
  ui.ok(`Banner label set for :${n}`);
}
async function cmdBannerShow(rest) {
  if (wantsHelp(rest)) return cmdUsage('banner-show');
  const cfg = loadConfig(getDataDir());
  const pos = firstPositional(rest);
  if (pos) {
    const n = String(Number(pos) || pos);
    console.log(ui.box(`banner :${pos}`, [cfg.banners[n] || defaultBannerFor(Number(pos))]));
    return;
  }
  const rows = cfg.ports.map((p) => [`:${p}`, cfg.banners[String(p)] || defaultBannerFor(p)]);
  console.log(ui.table(['PORT', 'BANNER'], rows));
}

// ================= CANARY =================
async function cmdDeploy(rest) {
  if (wantsHelp(rest)) return cmdUsage('deploy');
  const dataDir = getDataDir();
  const dir = firstPositional(rest);
  if (!dir) fail('Usage: ducgo deploy <dir>');
  await requireAuth(dataDir);
  const r = deployCanaries(dir);
  if (!r.ok) fail(`Deploy failed: ${r.error || 'unknown error'}`);
  addWatchDir(dataDir, r.dir);
  ui.ok(`Deployed ${r.files.length} canary file(s) to ${r.dir}: ${r.files.join(', ')}`);
  ui.info('Directory added to the canary watch list. Run "ducgo start" to arm it.');
}
async function cmdCanaryList(rest) {
  if (wantsHelp(rest)) return cmdUsage('canary-list');
  const dataDir = getDataDir();
  const cfg = loadConfig(dataDir);
  if (cfg.watchDirs.length === 0) { ui.dim('No canary directories. Use "ducgo deploy <dir>".'); return; }
  const rows = [];
  for (const d of cfg.watchDirs) {
    let files = 'missing dir';
    try {
      files = fs.readdirSync(d).filter((f) => /aws-keys|passwords|wallet-seed/i.test(f)).join(', ') || '(no decoys found)';
    } catch { /* keep missing */ }
    rows.push([d, files]);
  }
  console.log(ui.table(['WATCH DIR', 'DECOYS'], rows));
}
async function cmdCanaryVerify(rest) {
  if (wantsHelp(rest)) return cmdUsage('canary-verify');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const cfg = loadConfig(dataDir);
  const names = ['aws-keys.txt', 'passwords.csv', 'wallet-seed.txt'];
  const rows = [];
  let bad = 0;
  for (const d of cfg.watchDirs) {
    for (const n of names) {
      let state = 'MISSING';
      try {
        const c = fs.readFileSync(path.join(d, n), 'utf8');
        state = c.includes('MIRAGETOKEN-') ? 'OK' : 'NO TOKEN';
      } catch { /* missing */ }
      if (state !== 'OK') bad++;
      rows.push([path.join(d, n), state]);
    }
  }
  if (rows.length === 0) { ui.dim('No canary directories. Use "ducgo deploy <dir>".'); return; }
  console.log(ui.table(['FILE', 'TOKEN CHECK'], rows));
  if (bad > 0) ui.warn(`${bad} file(s) need attention. Use "ducgo canary-refresh".`);
  else ui.ok('All deployed decoys carry canary tokens.');
}
async function cmdCanaryRefresh(rest) {
  if (wantsHelp(rest)) return cmdUsage('canary-refresh');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const cfg = loadConfig(dataDir);
  const only = firstPositional(rest);
  const dirs = only ? [path.resolve(only)] : cfg.watchDirs;
  if (dirs.length === 0) fail('No canary directories. Use "ducgo deploy <dir>".');
  let n = 0;
  for (const d of dirs) {
    const r = deployCanaries(d);
    if (r.ok) {
      n += r.files.length;
      for (const f of r.files) {
        try {
          const fp = path.join(r.dir, f);
          const cur = fs.readFileSync(fp, 'utf8');
          void cur;
        } catch { /* ignore */ }
      }
    }
  }
  // Regenerate tokens by rewriting files that exist (deploy only writes missing ones),
  // so force-refresh: touch each decoy with a fresh token line.
  for (const d of dirs) {
    for (const name of ['aws-keys.txt', 'passwords.csv', 'wallet-seed.txt']) {
      try {
        const fp = path.join(path.resolve(d), name);
        if (fs.existsSync(fp)) fs.appendFileSync(fp, `\n# refreshed ${new Date().toISOString()} MIRAGETOKEN-refresh\n`);
      } catch { /* ignore */ }
    }
  }
  ui.ok(`Refreshed canaries in ${dirs.length} directorie(s) (${n} decoy slots).`);
}
async function cmdCanaryRemove(rest) {
  if (wantsHelp(rest)) return cmdUsage('canary-remove');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const dir = firstPositional(rest);
  if (!dir) fail('Usage: ducgo canary-remove <dir> [--delete]');
  removeWatchDir(dataDir, dir);
  if (hasFlag(rest, ['--delete'])) {
    for (const n of ['aws-keys.txt', 'passwords.csv', 'wallet-seed.txt']) {
      try { fs.unlinkSync(path.join(path.resolve(dir), n)); } catch { /* ignore */ }
    }
    ui.ok(`Unwatched + deleted decoys in ${path.resolve(dir)}`);
  } else {
    ui.ok(`Unwatched ${path.resolve(dir)} (files kept; add --delete to remove decoys)`);
  }
}
async function cmdCanaryShow(rest) {
  if (wantsHelp(rest)) return cmdUsage('canary-show');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const file = firstPositional(rest);
  if (!file) fail('Usage: ducgo canary-show <file>');
  let content = '';
  try { content = fs.readFileSync(path.resolve(file), 'utf8'); } catch { fail(`Cannot read: ${file}`); }
  const m = content.match(/MIRAGETOKEN-[A-Za-z0-9-]+/);
  if (!m) fail('No canary token found in that file.');
  console.log(ui.box(`canary token - ${path.basename(path.resolve(file))}`, [m[0]]));
}

// ================= EVENTS =================
async function cmdEvents(rest) {
  if (wantsHelp(rest)) return cmdUsage('events');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const events = readEvents(dataDir);
  const exportRaw = takeFlagValue(rest, ['--export']);
  if (exportRaw !== null) {
    if (!exportRaw) fail('Usage: ducgo events --export out.csv');
    const outPath = path.resolve(exportRaw);
    try { fs.writeFileSync(outPath, eventsToCsv(events), 'utf8'); } catch (e) { fail(`Export failed: ${String((e && e.message) || e)}`); }
    ui.ok(`Exported ${events.length} event(s) to ${outPath}`);
    return;
  }
  if (hasFlag(rest, ['--json'])) { console.log(JSON.stringify(events, null, 2)); return; }
  if (events.length === 0) { ui.dim('No events recorded yet.'); return; }
  console.log(ui.table(['TIME', 'TYPE', 'TRAP', 'IP', 'DETAIL'], events.map((e) => [String(e.time ?? ''), String(e.type ?? ''), String(e.trap ?? ''), String(e.ip ?? ''), String(e.detail ?? '').replace(/\s+/g, ' ').slice(0, 80)])));
  ui.dim(`${events.length} event(s).`);
}
async function cmdEventsTail(rest) {
  if (wantsHelp(rest)) return cmdUsage('events-tail');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const linesRaw = takeFlagValue(rest, ['--lines', '-n']);
  const n = linesRaw === null ? 10 : Number(linesRaw);
  if (!Number.isInteger(n) || n < 1 || n > 500) fail('--lines must be 1-500');
  const follow = hasFlag(rest, ['--follow', '-f']);
  let events = readEvents(dataDir).slice(-n);
  for (const e of events) ui.printEvent(e);
  if (!follow) { ui.dim(`${events.length} event(s) shown.`); return; }
  ui.info('Following live - Ctrl+C to stop.');
  const fp = eventsPath(dataDir);
  let known = 0;
  try { known = readEvents(dataDir).length; } catch { known = 0; }
  const timer = setInterval(() => {
    try {
      const all = readEvents(dataDir);
      if (all.length > known) {
        for (const e of all.slice(known)) ui.printEvent(e);
        known = all.length;
      }
    } catch { /* ignore */ }
  }, 800);
  await new Promise(() => {});
  clearInterval(timer);
}
async function cmdEventShow(rest) {
  if (wantsHelp(rest)) return cmdUsage('event-show');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const id = firstPositional(rest);
  if (!id) fail('Usage: ducgo event-show <id>');
  const ev = readEvents(dataDir).find((e) => String(e.id) === String(id));
  if (!ev) fail(`No event with id: ${id}`);
  console.log(ui.box(`event ${ev.id}`, [`time: ${ev.time}`, `type: ${ev.type}`, `trap: ${ev.trap}`, `ip: ${ev.ip}`, `severity: ${ev.severity}`, `detail: ${ev.detail}`]));
  if (ev.meta) console.log(ui.dim(`meta: ${JSON.stringify(ev.meta).slice(0, 300)}`));
}
async function cmdEventsClear(rest) {
  if (wantsHelp(rest)) return cmdUsage('events-clear');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const a = await promptLine('Type CLEAR to erase all events: ');
  if (a.trim() !== 'CLEAR') fail('Aborted.');
  try { fs.writeFileSync(eventsPath(dataDir), '', 'utf8'); } catch (e) { fail(`Clear failed: ${String((e && e.message) || e)}`); }
  ui.ok('Event log cleared.');
}
async function cmdEventsExport(rest) {
  if (wantsHelp(rest)) return cmdUsage('events-export');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const pos = positionals(rest);
  const file = pos[0];
  if (!file) fail('Usage: ducgo events-export <file> [--format csv|json]');
  const fmt = (takeFlagValue(rest, ['--format']) || (file.endsWith('.json') ? 'json' : 'csv')).toLowerCase();
  const events = readEvents(dataDir);
  const out = path.resolve(file);
  if (fmt === 'json') fs.writeFileSync(out, JSON.stringify(events, null, 2), 'utf8');
  else if (fmt === 'csv') fs.writeFileSync(out, eventsToCsv(events), 'utf8');
  else fail('--format must be csv or json');
  ui.ok(`Exported ${events.length} event(s) [${fmt}] to ${out}`);
}
async function cmdEventsImport(rest) {
  if (wantsHelp(rest)) return cmdUsage('events-import');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const file = firstPositional(rest);
  if (!file) fail('Usage: ducgo events-import <file>');
  let raw = '';
  try { raw = fs.readFileSync(path.resolve(file), 'utf8'); } catch { fail(`Cannot read: ${file}`); }
  let items = [];
  try {
    const j = JSON.parse(raw);
    items = Array.isArray(j) ? j : [j];
  } catch {
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try { items.push(JSON.parse(t)); } catch { /* skip */ }
    }
  }
  let added = 0;
  for (const it of items) {
    if (!it || typeof it !== 'object') continue;
    const ev = { id: String(it.id || `${Date.now()}-${added}`), time: String(it.time || new Date().toISOString()), type: String(it.type || 'imported'), trap: String(it.trap || 'import'), ip: String(it.ip || '127.0.0.1'), detail: String(it.detail || 'imported event').slice(0, 500), severity: String(it.severity || 'low') };
    try { appendEvent(dataDir, ev); added++; } catch { /* ignore */ }
  }
  ui.ok(`Imported ${added} event(s).`);
}
async function cmdEventsStats(rest) {
  if (wantsHelp(rest)) return cmdUsage('events-stats');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const events = readEvents(dataDir);
  const byType = new Map(); const bySev = new Map(); const byTrap = new Map();
  for (const e of events) {
    byType.set(e.type, (byType.get(e.type) || 0) + 1);
    bySev.set(e.severity, (bySev.get(e.severity) || 0) + 1);
    byTrap.set(e.trap, (byTrap.get(e.trap) || 0) + 1);
  }
  console.log(ui.box('events-stats', [`total: ${events.length}`]));
  console.log(ui.table(['TYPE', 'COUNT'], [...byType.entries()]));
  console.log(ui.table(['SEVERITY', 'COUNT'], [...bySev.entries()]));
  console.log(ui.table(['TRAP', 'COUNT'], [...byTrap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)));
}

// ================= ATTACKERS =================
async function cmdAttackers(rest) {
  if (wantsHelp(rest)) return cmdUsage('attackers');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const rows = groupByIp(readEvents(dataDir));
  if (rows.length === 0) { ui.dim('No attacker touches recorded.'); return; }
  console.log(ui.table(['IP', 'TOUCHES', 'FIRST SEEN', 'LAST SEEN', 'TOP TRAP'], rows.map((r) => [r.ip, String(r.touches), String(r.first), String(r.last), r.top])));
  ui.dim(`${rows.length} unique IP(s). Naive IP grouping - not attribution.`);
}
async function cmdAttackerShow(rest) {
  if (wantsHelp(rest)) return cmdUsage('attacker-show');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const ip = firstPositional(rest);
  if (!ip) fail('Usage: ducgo attacker-show <ip>');
  const rows = groupByIp(readEvents(dataDir));
  const g = rows.find((r) => r.ip === ip);
  if (!g) fail(`No touches from ${ip}`);
  console.log(ui.box(`attacker ${ip}`, [`touches: ${g.touches}`, `first: ${g.first}`, `last: ${g.last}`, `top trap: ${g.top}`]));
  console.log(ui.table(['TIME', 'TYPE', 'TRAP', 'DETAIL'], g.timeline.slice(-15).map((e) => [String(e.time), String(e.type), String(e.trap), String(e.detail).replace(/\s+/g, ' ').slice(0, 70)])));
  const notes = getAttackerNotes(dataDir, ip)[ip] || [];
  if (notes.length > 0) console.log(ui.table(['NOTE TIME', 'NOTE'], notes.map((x) => [x.time, x.text])));
}
async function cmdAttackerNote(rest) {
  if (wantsHelp(rest)) return cmdUsage('attacker-note');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const pos = positionals(rest);
  if (pos.length < 2) fail('Usage: ducgo attacker-note <ip> <text...>');
  const count = addAttackerNote(dataDir, pos[0], pos.slice(1).join(' '));
  ui.ok(`Note saved for ${pos[0]} (${count} total).`);
}
async function cmdAttackerListNotes(rest) {
  if (wantsHelp(rest)) return cmdUsage('attacker-list-notes');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const ip = firstPositional(rest);
  const all = getAttackerNotes(dataDir, ip || null);
  const rows = [];
  for (const [k, arr] of Object.entries(all)) for (const x of arr) rows.push([k, x.time, x.text]);
  if (rows.length === 0) { ui.dim('No notes yet. Use "ducgo attacker-note <ip> <text>".'); return; }
  console.log(ui.table(['IP', 'TIME', 'NOTE'], rows.slice(-50)));
}
async function cmdTopAttackers(rest) {
  if (wantsHelp(rest)) return cmdUsage('top-attackers');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const limRaw = takeFlagValue(rest, ['--limit', '-n']);
  const lim = limRaw === null ? 5 : Number(limRaw);
  if (!Number.isInteger(lim) || lim < 1 || lim > 100) fail('--limit must be 1-100');
  const rows = groupByIp(readEvents(dataDir)).slice(0, lim);
  if (rows.length === 0) { ui.dim('No attacker touches recorded.'); return; }
  console.log(ui.table(['RANK', 'IP', 'TOUCHES', 'TOP TRAP'], rows.map((r, i) => [String(i + 1), r.ip, String(r.touches), r.top])));
}

// ================= REPORTS =================
async function cmdReportDaily(rest) {
  if (wantsHelp(rest)) return cmdUsage('report-daily');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const since = Date.now() - 24 * 3600 * 1000;
  const events = readEvents(dataDir).filter((e) => { try { return new Date(e.time).getTime() >= since; } catch { return false; } });
  console.log(ui.box('report-daily (last 24h)', [`events: ${events.length}`, `attackers: ${groupByIp(events).length}`]));
  if (events.length === 0) return;
  const byTrap = new Map();
  for (const e of events) byTrap.set(e.trap, (byTrap.get(e.trap) || 0) + 1);
  console.log(ui.table(['TRAP', 'COUNT'], [...byTrap.entries()].sort((a, b) => b[1] - a[1])));
  for (const e of events.slice(-10)) ui.printEvent(e);
}
async function cmdReportSummary(rest) {
  if (wantsHelp(rest)) return cmdUsage('report-summary');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const events = readEvents(dataDir);
  if (events.length === 0) { ui.dim('No events yet.'); return; }
  const times = events.map((e) => e.time).sort();
  const bySev = new Map();
  for (const e of events) bySev.set(e.severity, (bySev.get(e.severity) || 0) + 1);
  console.log(ui.box('report-summary', [`total events: ${events.length}`, `range: ${times[0]} .. ${times[times.length - 1]}`, `unique IPs: ${groupByIp(events).length}`, ...[...bySev.entries()].map(([k, v]) => `${k}: ${v}`)]));
}
async function cmdReportTop(rest) {
  if (wantsHelp(rest)) return cmdUsage('report-top');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const limRaw = takeFlagValue(rest, ['--limit']);
  const lim = limRaw === null ? 5 : Number(limRaw);
  if (!Number.isInteger(lim) || lim < 1 || lim > 50) fail('--limit must be 1-50');
  const events = readEvents(dataDir);
  const byTrap = new Map();
  for (const e of events) byTrap.set(e.trap, (byTrap.get(e.trap) || 0) + 1);
  console.log(ui.table(['TOP TRAP', 'COUNT'], [...byTrap.entries()].sort((a, b) => b[1] - a[1]).slice(0, lim)));
  const ips = groupByIp(events).slice(0, lim);
  console.log(ui.table(['TOP IP', 'TOUCHES'], ips.map((r) => [r.ip, String(r.touches)])));
}
async function cmdReportExport(rest) {
  if (wantsHelp(rest)) return cmdUsage('report-export');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const file = firstPositional(rest);
  if (!file) fail('Usage: ducgo report-export <file>');
  const events = readEvents(dataDir);
  const ips = groupByIp(events);
  const lines = [`# ducgo report`, ``, `- generated: ${new Date().toISOString()}`, `- total events: ${events.length}`, `- unique attacker IPs: ${ips.length}`, ``, `## Top traps`, ``];
  const byTrap = new Map();
  for (const e of events) byTrap.set(e.trap, (byTrap.get(e.trap) || 0) + 1);
  for (const [t, n] of [...byTrap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)) lines.push(`- ${t}: ${n}`);
  lines.push('', '## Top attackers', '');
  for (const r of ips.slice(0, 10)) lines.push(`- ${r.ip}: ${r.touches} touches (top: ${r.top})`);
  lines.push('', '## Recent events', '');
  for (const e of events.slice(-20)) lines.push(`- [${e.time}] ${e.type} ${e.trap} (${e.ip}) ${String(e.detail).slice(0, 100)}`);
  lines.push('');
  fs.writeFileSync(path.resolve(file), lines.join('\n'), 'utf8');
  ui.ok(`Report written to ${path.resolve(file)} (${events.length} events)`);
}

// ================= CONFIG =================
const CONFIG_KEYS = ['ports', 'httpPort', 'httpTitle', 'watchDirs'];
async function cmdConfigSet(rest) {
  if (wantsHelp(rest)) return cmdUsage('config-set');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const pos = positionals(rest);
  if (pos.length < 2) fail('Usage: ducgo config-set <key> <value>  (keys: ports, httpPort, httpTitle, watchDirs)');
  const [key, ...valParts] = pos;
  const val = valParts.join(' ');
  if (!CONFIG_KEYS.includes(key)) fail(`Unknown key: ${key} (keys: ${CONFIG_KEYS.join(', ')})`);
  const cfg = loadConfig(dataDir);
  if (key === 'ports') {
    const r = parsePortList(val);
    if (!r.ok) fail(r.error);
    cfg.ports = r.ports;
  } else if (key === 'httpPort') {
    const n = Number(val.trim());
    if (!Number.isInteger(n) || n < 1 || n > 65535) fail('httpPort must be 1-65535');
    cfg.httpPort = n;
  } else if (key === 'httpTitle') {
    if (!val.trim() || val.length > 120) fail('httpTitle must be 1-120 chars');
    cfg.httpTitle = val.trim();
  } else if (key === 'watchDirs') {
    cfg.watchDirs = val.split(',').map((s) => s.trim()).filter(Boolean).map((s) => path.resolve(s));
  }
  saveConfig(dataDir, cfg);
  ui.ok(`config ${key} updated.`);
}
async function cmdConfigGet(rest) {
  if (wantsHelp(rest)) return cmdUsage('config-get');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const key = firstPositional(rest);
  if (!key) fail('Usage: ducgo config-get <key>');
  const cfg = loadConfig(dataDir);
  if (!(key in cfg)) fail(`Unknown key: ${key}`);
  const v = cfg[key];
  console.log(ui.box(`config ${key}`, [typeof v === 'object' ? JSON.stringify(v) : String(v)]));
}
async function cmdConfigList(rest) {
  if (wantsHelp(rest)) return cmdUsage('config-list');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const cfg = loadConfig(dataDir);
  console.log(ui.table(['KEY', 'VALUE'], Object.entries(cfg).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : String(v)])));
}
async function cmdConfigReset(rest) {
  if (wantsHelp(rest)) return cmdUsage('config-reset');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  saveConfig(dataDir, { ports: [...DEFAULT_PORTS], httpPort: DEFAULT_HTTP_PORT, watchDirs: [], disabled: [], banners: {}, httpTitle: 'Admin Login', notes: {} });
  ui.ok('Config reset to defaults.');
}
async function cmdDataDir(rest) {
  if (wantsHelp(rest)) return cmdUsage('data-dir');
  console.log(getDataDir());
  ui.dim('Data dir stays %USERPROFILE%\\.miragenet unless MIRAGENET_DIR is set.');
}
async function cmdDataSize(rest) {
  if (wantsHelp(rest)) return cmdUsage('data-size');
  const dataDir = getDataDir();
  const s = dirSize(dataDir);
  console.log(ui.table(['FILE', 'BYTES'], [...Object.entries(s.files), ['TOTAL', String(s.total)]]));
}
async function cmdConfigExport(rest) {
  if (wantsHelp(rest)) return cmdUsage('config-export');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const file = firstPositional(rest);
  if (!file) fail('Usage: ducgo config-export <file>');
  fs.writeFileSync(path.resolve(file), JSON.stringify(loadConfig(dataDir), null, 2), 'utf8');
  ui.ok(`Config exported to ${path.resolve(file)}`);
}
async function cmdConfigImport(rest) {
  if (wantsHelp(rest)) return cmdUsage('config-import');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const file = firstPositional(rest);
  if (!file) fail('Usage: ducgo config-import <file>');
  let j = null;
  try { j = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8')); } catch { fail(`Cannot parse: ${file}`); }
  const cur = loadConfig(dataDir);
  const next = { ...cur };
  if (Array.isArray(j.ports)) {
    const p = j.ports.filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535).slice(0, 20);
    if (p.length > 0) next.ports = p;
  }
  if (Number.isInteger(j.httpPort) && j.httpPort >= 1 && j.httpPort <= 65535) next.httpPort = j.httpPort;
  if (Array.isArray(j.watchDirs)) next.watchDirs = [...new Set(j.watchDirs.map(String))];
  if (Array.isArray(j.disabled)) next.disabled = [...new Set(j.disabled.map(String))];
  if (j.banners && typeof j.banners === 'object') next.banners = j.banners;
  if (typeof j.httpTitle === 'string' && j.httpTitle.length <= 120) next.httpTitle = j.httpTitle;
  saveConfig(dataDir, next);
  ui.ok(`Config imported from ${path.resolve(file)}`);
}

// ================= SYSTEM =================
async function cmdHelp(rest) {
  if (rest.length > 0 && !rest[0].startsWith('-')) return cmdUsage(rest[0]);
  printHelp();
}
async function cmdBannerCmd(rest) {
  if (wantsHelp(rest)) { console.log('Usage: ducgo banner'); return; }
  ui.printBanner();
}
async function cmdVersion(rest) {
  if (wantsHelp(rest)) { console.log('Usage: ducgo version'); return; }
  console.log(`ducgo v${VERSION}`);
}
async function cmdCommands(rest) {
  if (hasFlag(rest, ['--count'])) { console.log(String(COMMANDS.length)); return; }
  if (wantsHelp(rest)) { console.log('Usage: ducgo commands [--count]'); return; }
  printGroupedCommands();
}
async function cmdDoctor(rest) {
  if (wantsHelp(rest)) return cmdUsage('doctor');
  const dataDir = getDataDir();
  const checks = [];
  checks.push(['node >= 18', Number(process.versions.node.split('.')[0]) >= 18 ? 'PASS' : `FAIL (${process.version})`]);
  try { ensureDataDir(dataDir); fs.accessSync(dataDir, fs.constants.W_OK); checks.push(['data dir writable', `PASS (${dataDir})`]); }
  catch (e) { checks.push(['data dir writable', `FAIL (${e.message})`]); }
  checks.push(['auth setup', isSetup(dataDir) ? 'PASS' : 'NOT SET UP (run ducgo setup)']);
  const cfg = loadConfig(dataDir);
  checks.push(['config valid', Array.isArray(cfg.ports) && cfg.ports.length > 0 ? `PASS (${cfg.ports.length} traps)` : 'FAIL']);
  for (const p of cfg.ports.slice(0, 5)) checks.push([`port :${p} free`, (await checkPortFree(p)) ? 'yes' : 'IN USE']);
  console.log(ui.box('doctor', [`ducgo v${VERSION}`, `data dir: ${dataDir}`]));
  console.log(ui.table(['CHECK', 'RESULT'], checks));
}
async function cmdSelftest(rest) {
  if (wantsHelp(rest)) return cmdUsage('selftest');
  const mod = await import('../test/selftest.js');
  const ok = await mod.runSelfTest();
  process.exit(ok ? 0 : 1);
}
async function cmdDemo(rest) {
  if (wantsHelp(rest)) return cmdUsage('demo');
  const dataDir = getDataDir();
  const ev = createDemoEvent();
  try { appendEvent(dataDir, ev); } catch (e) { fail(`Failed to write event log: ${String((e && e.message) || e)}`); }
  ui.printEvent(ev);
  ui.dim('DEMO event recorded (synthetic, labeled DEMO).');
}
async function cmdAbout(rest) {
  if (wantsHelp(rest)) return cmdUsage('about');
  ui.printBanner();
  console.log('');
  console.log(ui.box('about ducgo', ['passive deception tripwires: honey TCP + honey HTTP + canary files', '100% passive/defensive - only listens locally, never scans or attacks', 'English only. CLI only. Zero runtime dependencies (Node stdlib only).']));
  console.log(ui.dim('Limits: fs.watch sees modify/rename/delete only (NOT silent reads); TCP ports are LAN-visible by design;'));
  console.log(ui.dim('no encryption-at-rest beyond OS permissions; attacker table is naive IP grouping; duress hides the view, not the install.'));
}
async function cmdBackup(rest) {
  if (wantsHelp(rest)) return cmdUsage('backup');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const file = firstPositional(rest);
  if (!file) fail('Usage: ducgo backup <file>');
  const out = path.resolve(file);
  const payload = { tool: 'ducgo', version: VERSION, at: new Date().toISOString() };
  for (const n of ['auth.json', 'config.json', 'events.jsonl']) {
    try { payload[n] = fs.readFileSync(path.join(dataDir, n), 'utf8'); } catch { payload[n] = null; }
  }
  fs.writeFileSync(out, JSON.stringify(payload, null, 2), 'utf8');
  ui.ok(`Backup written to ${out}`);
}
async function cmdRestore(rest) {
  if (wantsHelp(rest)) return cmdUsage('restore');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const file = firstPositional(rest);
  if (!file) fail('Usage: ducgo restore <file>');
  let j = null;
  try { j = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8')); } catch { fail(`Cannot parse backup: ${file}`); }
  const a = await promptLine('Type RESTORE to confirm: ');
  if (a.trim() !== 'RESTORE') fail('Aborted.');
  ensureDataDir(dataDir);
  for (const n of ['auth.json', 'config.json', 'events.jsonl']) {
    if (typeof j[n] === 'string') fs.writeFileSync(path.join(dataDir, n), j[n], 'utf8');
  }
  ui.ok('Backup restored.');
}
async function cmdWipe(rest) {
  if (wantsHelp(rest)) return cmdUsage('wipe');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const a = await promptLine('Type WIPE to factory-reset EVERYTHING: ');
  if (a.trim() !== 'WIPE') fail('Aborted.');
  for (const n of ['auth.json', 'config.json', 'events.jsonl']) {
    try { fs.unlinkSync(path.join(dataDir, n)); } catch { /* ignore */ }
  }
  ui.ok('Factory reset complete. Run "ducgo setup" to start over.');
}
async function cmdLogPath(rest) {
  if (wantsHelp(rest)) return cmdUsage('log-path');
  console.log(eventsPath(getDataDir()));
}
async function cmdSysinfo(rest) {
  if (wantsHelp(rest)) return cmdUsage('sysinfo');
  console.log(ui.table(['KEY', 'VALUE'], [['node', process.version], ['platform', `${os.platform()} ${os.arch()}`], ['release', os.release()], ['ducgo', `v${VERSION}`]]));
}
async function cmdUptime(rest) {
  if (wantsHelp(rest)) return cmdUsage('uptime');
  const dataDir = getDataDir();
  const st = loadAuth(dataDir);
  const secs = Math.floor(process.uptime());
  console.log(ui.box('uptime', [`process uptime: ${secs}s`, st && st.createdAt ? `store since: ${st.createdAt}` : 'store: not set up yet']));
}
async function cmdTips(rest) {
  if (wantsHelp(rest)) return cmdUsage('tips');
  console.log(ui.box('tips', ['1. Run "ducgo doctor" after setup to verify ports + data dir', '2. Deploy canaries where they look natural (docs, backups)', '3. "ducgo start" is foreground only - keep the window open', '4. Review with "ducgo events" and "ducgo top-attackers"', '5. Test duress safely with a scratch MIRAGENET_DIR first']));
}
async function cmdLicense(rest) {
  if (wantsHelp(rest)) return cmdUsage('license');
  console.log(ui.box('license', ['ducgo v2.0.0 - passive defensive tool. No warranty.', 'Zero runtime dependencies. Node.js stdlib only.', 'Use only on systems/networks you own or are authorized to defend.']));
}
async function cmdVerifyInstall(rest) {
  if (wantsHelp(rest)) return cmdUsage('verify-install');
  const rows = [];
  rows.push(['node >= 18', Number(process.versions.node.split('.')[0]) >= 18 ? 'PASS' : 'FAIL']);
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\//, '')), '..', 'package.json'), 'utf8'));
    void pkg;
    rows.push(['package.json readable', 'PASS']);
  } catch {
    try {
      const alt = path.resolve('package.json');
      JSON.parse(fs.readFileSync(alt, 'utf8'));
      rows.push(['package.json readable', 'PASS']);
    } catch (e) { rows.push(['package.json readable', `FAIL (${e.message})`]); }
  }
  try {
    const head = fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n')[0];
    rows.push(['shebang kept', head.includes('#!/usr/bin/env node') ? 'PASS' : 'FAIL']);
  } catch { rows.push(['shebang kept', 'UNKNOWN']); }
  try { ensureDataDir(getDataDir()); rows.push(['data dir', `PASS (${getDataDir()})`]); }
  catch (e) { rows.push(['data dir', `FAIL (${e.message})`]); }
  console.log(ui.table(['CHECK', 'RESULT'], rows));
}
async function cmdPaths(rest) {
  if (wantsHelp(rest)) return cmdUsage('paths');
  const d = getDataDir();
  console.log(ui.table(['STORE', 'PATH'], [['data dir', d], ['auth.json', authPath(d)], ['config.json', configPath(d)], ['events.jsonl', eventsPath(d)]]));
}
async function cmdStats(rest) {
  if (wantsHelp(rest)) return cmdUsage('stats');
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const cfg = loadConfig(dataDir);
  const events = readEvents(dataDir);
  const ips = groupByIp(events);
  let bar = ui.progress(Math.min(events.length, 100), 100);
  console.log(ui.box('stats', [`events: ${events.length}`, `attacker IPs: ${ips.length}`, `traps: ${cfg.ports.length} (disabled: ${cfg.disabled.length})`, `watch dirs: ${cfg.watchDirs.length}`, `notes: ${Object.values(cfg.notes || {}).flat().length}`, `activity: ${bar}`]));
}
async function cmdSupport(rest) {
  if (wantsHelp(rest)) return cmdUsage('support');
  console.log(ui.box('support', ['scope: passive tripwires on your own machines only', 'no offensive use - this tool never scans or attacks', 'check "ducgo doctor" + "ducgo about" for limits first']));
}

// ---------- main ----------
async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  const rest = args.slice(1);
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help' && rest.length === 0) {
    if (!cmd || cmd === '--help' || cmd === '-h') { printHelp(); return; }
  }
  if (cmd === '--version' || cmd === '-V') { console.log(`ducgo v${VERSION}`); return; }
  const handlers = {
    setup: cmdSetup, 'login-test': cmdLoginTest, 'change-pin': cmdChangePin, 'change-duress': cmdChangeDuress,
    'lock-status': cmdLockStatus, 'auth-status': cmdAuthStatus, 'reset-all': cmdResetAll,
    start: cmdStart, status: cmdStatus, 'ports-list': cmdPortsList, 'engine-check': cmdEngineCheck,
    'trap-list': cmdTrapList, 'trap-add': cmdTrapAdd, 'trap-remove': cmdTrapRemove, 'trap-enable': cmdTrapEnable,
    'trap-disable': cmdTrapDisable, 'http-show': cmdHttpShow, 'http-config': cmdHttpConfig, 'banner-set': cmdBannerSet,
    'banner-show': cmdBannerShow, deploy: cmdDeploy, 'canary-list': cmdCanaryList, 'canary-verify': cmdCanaryVerify,
    'canary-refresh': cmdCanaryRefresh, 'canary-remove': cmdCanaryRemove, 'canary-show': cmdCanaryShow,
    events: cmdEvents, 'events-tail': cmdEventsTail, 'event-show': cmdEventShow, 'events-clear': cmdEventsClear,
    'events-export': cmdEventsExport, 'events-import': cmdEventsImport, 'events-stats': cmdEventsStats,
    attackers: cmdAttackers, 'attacker-show': cmdAttackerShow, 'attacker-note': cmdAttackerNote,
    'attacker-list-notes': cmdAttackerListNotes, 'top-attackers': cmdTopAttackers,
    'report-daily': cmdReportDaily, 'report-summary': cmdReportSummary, 'report-top': cmdReportTop, 'report-export': cmdReportExport,
    'config-set': cmdConfigSet, 'config-get': cmdConfigGet, 'config-list': cmdConfigList, 'config-reset': cmdConfigReset,
    'data-dir': cmdDataDir, 'data-size': cmdDataSize, 'config-export': cmdConfigExport, 'config-import': cmdConfigImport,
    help: cmdHelp, banner: cmdBannerCmd, version: cmdVersion, commands: cmdCommands, doctor: cmdDoctor,
    selftest: cmdSelftest, demo: cmdDemo, about: cmdAbout, backup: cmdBackup, restore: cmdRestore, wipe: cmdWipe,
    'log-path': cmdLogPath, sysinfo: cmdSysinfo, uptime: cmdUptime, tips: cmdTips, license: cmdLicense,
    'verify-install': cmdVerifyInstall, paths: cmdPaths, stats: cmdStats, support: cmdSupport,
  };
  if (cmd === 'help') { await cmdHelp(rest); return; }
  if (cmd === '--help' || cmd === '-h') { printHelp(); return; }
  const fn = handlers[cmd];
  if (!fn) {
    console.error(`Unknown command: ${cmd}\n`);
    printGroupedCommands();
    process.exit(1);
  }
  await fn(rest);
}

await (async () => {
  let invokedAsMain = false;
  try {
    invokedAsMain =
      !!process.argv[1] &&
      fs.realpathSync(path.resolve(process.argv[1])) === fileURLToPath(import.meta.url);
  } catch {
    invokedAsMain = false;
  }
  if (!invokedAsMain) return;
  await main().catch((err) => {
    console.error(`Error: ${String((err && err.message) || err)}`);
    process.exit(1);
  });
})();
