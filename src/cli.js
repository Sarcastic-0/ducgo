#!/usr/bin/env node
// MirageNet v2 — English-only, CLI-only passive deception tripwires.
// Node.js stdlib only. Zero runtime dependencies. Exit codes: 0 ok, 1 error.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { isSetup, setupPins, verifyPin } from './auth.js';
import {
  getDataDir,
  ensureDataDir,
  loadConfig,
  saveConfig,
  addWatchDir,
  appendEvent,
  readEvents,
  eventsToCsv,
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
} from './traps.js';

const VERSION = '2.0.0';
const DURESS_MESSAGE = 'All clear — no threats detected.';

// ---------- minimal colors (NO_COLOR disables all styling) ----------
const USE_COLOR = !('NO_COLOR' in process.env);
const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  magenta: '\x1b[35m',
};
function paint(name, s) {
  return USE_COLOR ? ANSI[name] + s + ANSI.reset : s;
}
function severityColor(sev) {
  switch (sev) {
    case 'critical':
      return 'red';
    case 'high':
      return 'yellow';
    case 'medium':
      return 'cyan';
    case 'low':
      return 'gray';
    default:
      return 'gray';
  }
}

// ---------- help ----------
function printHelp() {
  console.log(`MirageNet v${VERSION} — passive deception tripwires (CLI only, English only)

Usage: mirage <command> [options]

Commands:
  setup                 Set access PIN + duress PIN (interactive, min 6 chars)
  start [--ports P,...] [--http PORT]
                        Unlock with PIN, then run the trap mesh live until Ctrl+C.
                        Honey TCP ports (default 2222,2323,8080) + honey HTTP
                        on 127.0.0.1 (default 18080) + canary watch on
                        deployed directories.
  deploy <dir>          Unlock with PIN, drop decoy canary files into <dir>
                        and add it to the watch list.
  events [--json] [--export out.csv]
                        Unlock with PIN, show recorded event history
                        (table by default, raw JSON with --json, CSV file
                        with --export).
  attackers             Unlock with PIN, show touches grouped by IP
                        (touches, first/last seen, top trap).
  demo                  No PIN needed. Record one synthetic DEMO event so you
                        can review the output format.
  selftest              Run the built-in selftest suite (same as "npm test").

Duress: entering the duress PIN at any PIN prompt shows a fake all-clear
message and records a silent alert. It exits 0 and never reveals itself.

Examples:
  mirage setup
  mirage start
  mirage start --ports 2222,2323 --http 18080
  mirage deploy ./decoys
  mirage events
  mirage events --json
  mirage events --export report.csv
  mirage attackers
  mirage demo
  mirage selftest

Data: %USERPROFILE%\\.miragenet\\ (auth.json, events.jsonl, config.json).
Set MIRAGENET_DIR to override the data directory (used for testing).
Colors: set NO_COLOR=1 to disable ANSI colors. Exit codes: 0 ok, 1 error.`);
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

// ---------- hidden PIN prompt (stdin raw mode, no echo) ----------
// When stdin is piped (scripting/tests), lines are consumed sequentially
// instead, so `printf "pin\\n..." | mirage setup` works.
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
          try {
            stdin.setRawMode(false);
          } catch {
            /* ignore */
          }
          stdin.pause();
          stdin.removeListener('data', onData);
          resolve(buf);
          return;
        }
        if (ch === '') {
          process.stdout.write('\n');
          try {
            stdin.setRawMode(false);
          } catch {
            /* ignore */
          }
          process.exit(1);
        }
        if (ch === '' || ch === '\b') {
          if (buf.length > 0) {
            buf = buf.slice(0, -1);
            process.stdout.write('\b \b');
          }
          continue;
        }
        if (ch >= ' ') {
          buf += ch;
          process.stdout.write('*');
        }
      }
    };
    stdin.on('data', onData);
  });
}

// ---------- auth gate (duress handled here for EVERY auth prompt) ----------
function handleDuress(dataDir) {
  try {
    appendEvent(dataDir, makeDuressEvent());
  } catch {
    /* silent log is best-effort */
  }
  console.log(DURESS_MESSAGE);
  process.exit(0);
}

async function requireAuth(dataDir) {
  if (!isSetup(dataDir)) {
    console.error('Not set up yet. Run "mirage setup" first.');
    process.exit(1);
  }
  const pin = await promptHidden('Enter PIN: ');
  const r = verifyPin(dataDir, pin || '');
  if (r === 'normal') return;
  if (r === 'duress') handleDuress(dataDir);
  console.error('Incorrect PIN.');
  process.exit(1);
}

// ---------- event printing ----------
function printEvent(ev) {
  const line = `[${ev.time}] ${String(ev.severity || 'info').toUpperCase().padEnd(8)} ${ev.type} ${ev.trap} — ${ev.detail} (${ev.ip})`;
  console.log(paint(severityColor(ev.severity), line));
}

function printEventsTable(events) {
  if (events.length === 0) {
    console.log('No events recorded yet.');
    return;
  }
  console.log(paint('bold', `${'TIME'.padEnd(24)} ${'TYPE'.padEnd(11)} ${'TRAP'.padEnd(20)} ${'IP'.padEnd(15)} DETAIL`));
  for (const e of events) {
    const detail = String(e.detail ?? '').replace(/\s+/g, ' ').slice(0, 90);
    console.log(
      `${String(e.time ?? '').padEnd(24)} ${String(e.type ?? '').padEnd(11)} ${String(e.trap ?? '').padEnd(20)} ${String(e.ip ?? '').padEnd(15)} ${paint(severityColor(e.severity), detail)}`
    );
  }
  console.log(paint('gray', `\n${events.length} event(s).`));
}

// ---------- commands ----------
async function cmdSetup() {
  const dataDir = getDataDir();
  if (isSetup(dataDir)) {
    console.error(`Already set up (${dataDir}). Delete auth.json there to reset.`);
    process.exit(1);
  }
  const pin = await promptHidden('Set access PIN (min 6 chars): ');
  const pin2 = await promptHidden('Confirm access PIN: ');
  if (!pin || pin.length < 6) {
    console.error('PIN must be at least 6 characters.');
    process.exit(1);
  }
  if (pin !== pin2) {
    console.error('PINs do not match.');
    process.exit(1);
  }
  const duress = await promptHidden('Set duress PIN (min 6 chars, must differ): ');
  const duress2 = await promptHidden('Confirm duress PIN: ');
  if (!duress || duress.length < 6) {
    console.error('Duress PIN must be at least 6 characters.');
    process.exit(1);
  }
  if (duress !== duress2) {
    console.error('Duress PINs do not match.');
    process.exit(1);
  }
  const r = setupPins(dataDir, pin, duress);
  if (!r.ok) {
    console.error(r.error || 'Setup failed.');
    process.exit(1);
  }
  console.log(paint('green', `Setup complete. Data directory: ${dataDir}`));
  console.log('Run "mirage start" to arm the trap mesh.');
}

async function cmdStart(rest) {
  const dataDir = getDataDir();
  const cfg = loadConfig(dataDir);

  let ports = [...cfg.ports];
  let httpPort = cfg.httpPort;
  const portsRaw = takeFlagValue(rest, ['--ports']);
  const httpRaw = takeFlagValue(rest, ['--http']);
  if (portsRaw !== null) {
    const r = parsePortList(portsRaw);
    if (!r.ok) {
      console.error(r.error);
      process.exit(1);
    }
    ports = r.ports;
  }
  if (httpRaw !== null) {
    const n = Number(String(httpRaw).trim());
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      console.error(`Invalid HTTP port: "${httpRaw}" (must be 1-65535)`);
      process.exit(1);
    }
    httpPort = n;
  }

  await requireAuth(dataDir);
  ensureDataDir(dataDir);
  if (portsRaw !== null || httpRaw !== null) {
    saveConfig(dataDir, { ...loadConfig(dataDir), ports, httpPort });
  }

  const emit = (ev) => {
    try {
      appendEvent(dataDir, ev);
    } catch {
      /* best effort */
    }
    printEvent(ev);
  };

  const servers = [];
  for (const port of ports) {
    try {
      const srv = await startHoneyTcp(port, emit);
      servers.push(srv);
      console.log(paint('green', `Listening: honey TCP :${port} (LAN-visible by design)`));
    } catch (err) {
      emit(
        makeEvent(
          'system',
          `honey-tcp:${port}`,
          '127.0.0.1',
          `Port ${port} unavailable (${(err && err.code) || (err && err.message) || err}) — continuing without it`,
          'medium'
        )
      );
    }
  }
  try {
    const httpSrv = await startHoneyHttp(httpPort, '127.0.0.1', emit);
    servers.push(httpSrv);
    console.log(paint('green', `Listening: honey HTTP 127.0.0.1:${httpPort} (fake Admin Login)`));
  } catch (err) {
    emit(
      makeEvent(
        'system',
        'honey-http',
        '127.0.0.1',
        `Honey HTTP unavailable: ${String((err && err.message) || err)}`,
        'medium'
      )
    );
  }

  const watchCfg = loadConfig(dataDir);
  const liveDirs = watchCfg.watchDirs.filter((d) => {
    try {
      return fs.statSync(d).isDirectory();
    } catch {
      return false;
    }
  });
  const watchers = watchDirs(liveDirs, emit);
  if (liveDirs.length > 0) {
    console.log(paint('green', `Watching ${liveDirs.length} canary directorie(s): ${liveDirs.join(', ')}`));
  } else {
    console.log(paint('gray', 'No canary directories deployed. Use "mirage deploy <dir>" to add tripwires.'));
  }

  emit(makeEvent('system', 'engine', '127.0.0.1', `Trap mesh started — TCP [${ports.join(', ')}], HTTP 127.0.0.1:${httpPort}`, 'low'));
  console.log(paint('bold', 'Trap mesh running. Press Ctrl+C to stop.'));

  let stopping = false;
  const cleanupAndExit = async (code) => {
    if (stopping) return;
    stopping = true;
    for (const w of watchers) {
      try {
        w.close();
      } catch {
        /* ignore */
      }
    }
    for (const s of servers) {
      await closeServer(s);
    }
    try {
      appendEvent(dataDir, makeEvent('system', 'engine', '127.0.0.1', 'Trap mesh stopped', 'low'));
    } catch {
      /* ignore */
    }
    console.log(paint('gray', '\nTrap mesh stopped.'));
    process.exit(code);
  };
  process.on('SIGINT', () => {
    void cleanupAndExit(0);
  });
  process.on('SIGTERM', () => {
    void cleanupAndExit(0);
  });
  await new Promise(() => {}); // run until Ctrl+C
}

async function cmdDeploy(rest) {
  const dataDir = getDataDir();
  const dir = firstPositional(rest);
  if (!dir) {
    console.error('Usage: mirage deploy <dir>');
    process.exit(1);
  }
  await requireAuth(dataDir);
  const r = deployCanaries(dir);
  if (!r.ok) {
    console.error(`Deploy failed: ${r.error || 'unknown error'}`);
    process.exit(1);
  }
  addWatchDir(dataDir, r.dir);
  console.log(paint('green', `Deployed ${r.files.length} canary file(s) to ${r.dir}: ${r.files.join(', ')}`));
  console.log('Directory added to the canary watch list. Run "mirage start" to arm it.');
}

async function cmdEvents(rest) {
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const events = readEvents(dataDir);
  const exportRaw = takeFlagValue(rest, ['--export']);
  if (exportRaw !== null) {
    if (!exportRaw) {
      console.error('Usage: mirage events --export out.csv');
      process.exit(1);
    }
    const outPath = path.resolve(exportRaw);
    try {
      fs.writeFileSync(outPath, eventsToCsv(events), 'utf8');
    } catch (err) {
      console.error(`Export failed: ${String((err && err.message) || err)}`);
      process.exit(1);
    }
    console.log(paint('green', `Exported ${events.length} event(s) to ${outPath}`));
    return;
  }
  if (hasFlag(rest, ['--json'])) {
    console.log(JSON.stringify(events, null, 2));
    return;
  }
  printEventsTable(events);
}

async function cmdAttackers() {
  const dataDir = getDataDir();
  await requireAuth(dataDir);
  const events = readEvents(dataDir).filter((e) => e && e.type !== 'system');
  if (events.length === 0) {
    console.log('No attacker touches recorded.');
    return;
  }
  const groups = new Map();
  for (const e of events) {
    const ip = String(e.ip || 'unknown');
    let g = groups.get(ip);
    if (!g) {
      g = { ip, touches: 0, first: e.time, last: e.time, traps: new Map() };
      groups.set(ip, g);
    }
    g.touches += 1;
    if (e.time < g.first) g.first = e.time;
    if (e.time > g.last) g.last = e.time;
    g.traps.set(e.trap, (g.traps.get(e.trap) || 0) + 1);
  }
  const rows = [...groups.values()]
    .map((g) => {
      let top = '';
      let topN = -1;
      for (const [trap, n] of g.traps) {
        if (n > topN) {
          topN = n;
          top = trap;
        }
      }
      return { ip: g.ip, touches: g.touches, first: g.first, last: g.last, top };
    })
    .sort((a, b) => b.touches - a.touches);
  console.log(paint('bold', `${'IP'.padEnd(18)} ${'TOUCHES'.padEnd(8)} ${'FIRST SEEN'.padEnd(24)} ${'LAST SEEN'.padEnd(24)} TOP TRAP`));
  for (const r of rows) {
    console.log(`${r.ip.padEnd(18)} ${String(r.touches).padEnd(8)} ${String(r.first).padEnd(24)} ${String(r.last).padEnd(24)} ${r.top}`);
  }
  console.log(paint('gray', `\n${rows.length} unique IP(s). Naive IP grouping — not attribution.`));
}

async function cmdDemo() {
  const dataDir = getDataDir();
  const ev = createDemoEvent();
  try {
    appendEvent(dataDir, ev);
  } catch (err) {
    console.error(`Failed to write event log: ${String((err && err.message) || err)}`);
    process.exit(1);
  }
  printEvent(ev);
  console.log(paint('gray', 'DEMO event recorded (synthetic, labeled DEMO).'));
}

async function cmdSelftest() {
  const mod = await import('../test/selftest.js');
  const ok = await mod.runSelfTest();
  process.exit(ok ? 0 : 1);
}

// ---------- main ----------
async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') {
    printHelp();
    return;
  }
  if (cmd === '--version' || cmd === '-V' || cmd === 'version') {
    console.log(`mirage ${VERSION}`);
    return;
  }
  switch (cmd) {
    case 'setup':
      await cmdSetup();
      break;
    case 'start':
      await cmdStart(args.slice(1));
      break;
    case 'deploy':
      await cmdDeploy(args.slice(1));
      break;
    case 'events':
      await cmdEvents(args.slice(1));
      break;
    case 'attackers':
      await cmdAttackers();
      break;
    case 'demo':
      await cmdDemo();
      break;
    case 'selftest':
      await cmdSelftest();
      break;
    default:
      console.error(`Unknown command: ${cmd}\n`);
      printHelp();
      process.exit(1);
  }
}

await main().catch((err) => {
  console.error(`Error: ${String((err && err.message) || err)}`);
  process.exit(1);
});
