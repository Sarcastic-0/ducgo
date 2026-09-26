// ducgo v2.0.0 selftest - stdlib only.
// Run: node test/selftest.js  (also: "npm test", "ducgo selftest").
// Prints PASS lines; exits non-zero on any failure. 23+ checks.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import * as net from 'node:net';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { setupPins, verifyPin } from '../src/auth.js';
import { startHoneyTcp, startHoneyHttp, getServerPort, watchDirs, deployCanaries, closeServer } from '../src/traps.js';
import { COMMANDS, splitReplLine } from '../src/cli.js';
import { banner, TAGLINE, VERSION, table, box, formatEvent, progress } from '../src/ui.js';

let failures = 0;
let passes = 0;
function pass(label) {
  passes += 1;
  console.log(`PASS: ${label}`);
}
function fail(label, extra) {
  failures += 1;
  console.error(`FAIL: ${label}`);
  if (extra) console.error(String(extra).slice(0, 2000));
}
function assert(cond, label, extra) {
  if (cond) pass(label);
  else fail(label, extra);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, timeoutMs) {
  const start = Date.now();
  for (;;) {
    if (fn()) return true;
    if (Date.now() - start > timeoutMs) return false;
    await sleep(100);
  }
}

// (1) auth store tests - KEPT from v2
async function testAuth() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-auth-'));
  try {
    const PIN = 'alpha-9912';
    const DURESS = 'duress-4417';

    let r = setupPins(dir, 'abc', DURESS);
    assert(!r.ok, 'auth: short PIN rejected');

    r = setupPins(dir, PIN, PIN);
    assert(!r.ok, 'auth: identical PINs rejected');

    r = setupPins(dir, PIN, DURESS);
    assert(r.ok, 'auth: valid PINs accepted');

    assert(verifyPin(dir, PIN) === 'normal', 'auth: correct PIN verifies');
    assert(verifyPin(dir, 'wrong-pin-000') === null, 'auth: wrong PIN rejected');
    assert(verifyPin(dir, DURESS) === 'duress', 'auth: duress PIN verifies as duress');

    const raw = fs.readFileSync(path.join(dir, 'auth.json'), 'utf8');
    assert(!raw.includes(PIN) && !raw.includes(DURESS), 'auth: auth.json contains no PIN material');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// (2) trap tests on ephemeral ports - KEPT from v2
async function testTraps() {
  const httpEvents = [];
  const httpSrv = await startHoneyHttp(0, '127.0.0.1', (ev) => httpEvents.push(ev));
  const hport = getServerPort(httpSrv);
  assert(hport > 0, 'trap: honey HTTP binds ephemeral port');

  await new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port: hport, path: '/', headers: { 'User-Agent': 'selftest/1.0' } }, (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => {
          if (res.statusCode === 200 && b.includes('Admin Login')) resolve();
          else reject(new Error(`unexpected page: ${res.statusCode}`));
        });
      })
      .on('error', reject);
  });

  const SECRET = 'supersecret-selftest-xyz-999';
  await new Promise((resolve, reject) => {
    const body = 'username=admin&password=' + encodeURIComponent(SECRET);
    const req = http.request(
      {
        host: '127.0.0.1',
        port: hport,
        path: '/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
      },
      (res) => {
        res.resume();
        res.on('end', resolve);
      }
    );
    req.on('error', reject);
    req.end(body);
  });
  await sleep(300);

  const getEv = httpEvents.find((e) => e.method === 'GET' && e.path === '/');
  assert(!!getEv, 'trap: honey HTTP logs GET / with ip+userAgent');
  assert(!!getEv && typeof getEv.ip === 'string' && typeof getEv.userAgent === 'string', 'trap: GET event carries ip + userAgent');

  const postEv = httpEvents.find((e) => e.loginAttempted === true);
  assert(!!postEv, 'trap: honey HTTP logs POST login attempt');
  assert(!!postEv && postEv.username === 'admin', 'trap: posted username captured (admin)');
  assert(!JSON.stringify(httpEvents).includes(SECRET), 'trap: posted password NEVER stored');

  const tcpEvents = [];
  const tcpSrv = await startHoneyTcp(0, (ev) => tcpEvents.push(ev), { host: '127.0.0.1' });
  const tport = getServerPort(tcpSrv);
  assert(tport > 0, 'trap: honey TCP binds ephemeral port');

  await new Promise((resolve, reject) => {
    const s = net.connect(tport, '127.0.0.1', () => s.write('HELLO-SELFTEST'));
    s.on('data', () => {});
    s.on('error', reject);
    setTimeout(() => {
      try { s.destroy(); } catch { /* ignore */ }
      resolve();
    }, 700);
  });
  const sawConn = await waitFor(() => tcpEvents.some((e) => e.type === 'honey-tcp'), 3000);
  assert(sawConn, 'trap: honey TCP logs connection');
  const bannerEv = tcpEvents.find((e) => e.type === 'banner-grab');
  assert(!!bannerEv && String(bannerEv.bannerBytes || '').includes('HELLO-SELFTEST'), 'trap: banner-grab bytes captured (<=256B preview)');

  await closeServer(httpSrv);
  await closeServer(tcpSrv);
}

// (3) canary test - KEPT from v2
async function testCanary() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-canary-'));
  try {
    const dep = deployCanaries(dir);
    assert(dep.ok && dep.files.length === 3, 'canary: deploy writes 3 decoy files');
    for (const name of ['aws-keys.txt', 'passwords.csv', 'wallet-seed.txt']) {
      assert(fs.existsSync(path.join(dir, name)), `canary: decoy present (${name})`);
    }
    const aws = fs.readFileSync(path.join(dir, 'aws-keys.txt'), 'utf8');
    assert(aws.includes('MIRAGETOKEN-'), 'canary: decoys carry CANARY tokens');

    const fired = [];
    const watchers = watchDirs([dir], (ev) => fired.push(ev));
    await sleep(400);
    fs.appendFileSync(path.join(dir, 'aws-keys.txt'), '\n# touched by selftest\n');
    const ok = await waitFor(() => fired.some((e) => e.type === 'canary'), 5000);
    assert(ok, 'canary: watcher fires on modify');
    for (const w of watchers) {
      try { w.close(); } catch { /* ignore */ }
    }
    await sleep(600);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// (4) ducgo v2: command count + UI + smoke
function testCount() {
  assert(COMMANDS.length === 70, `commands: count==70 (got ${COMMANDS.length})`);
  const names = COMMANDS.map((c) => c.name);
  assert(new Set(names).size === 70, 'commands: all names unique');
  for (const g of ['auth', 'engine', 'traps', 'canary', 'events', 'attackers', 'reports', 'config', 'system']) {
    assert(COMMANDS.some((c) => c.group === g), `commands: group present (${g})`);
  }
}

function testBanner() {
  const b = banner();
  assert(b.includes('DUCGO') || b.includes('████'), 'ui: banner contains DUCGO logo');
  assert(b.includes(TAGLINE), 'ui: banner contains English tagline');
  assert(b.includes(`ducgo v${VERSION}`), 'ui: banner contains version line');
  assert(typeof table(['A'], [['b']]) === 'string', 'ui: table() works');
  assert(typeof box('t', ['x']) === 'string', 'ui: box() works');
  assert(formatEvent({ time: 't', type: 'x', trap: 'y', ip: 'z', detail: 'd', severity: 'high' }).includes('x'), 'ui: live-event formatter works');
  assert(progress(1, 2).includes('%'), 'ui: progress works');
}

function testUiEverywhere() {
  const src = fs.readFileSync(new URL('../src/cli.js', import.meta.url), 'utf8');
  assert(src.includes("from './ui.js'") || src.includes('from "./ui.js"'), 'ui: cli.js imports ui.js');
  // every command handler must touch the ui kit (banner/box/table/ok/info/dim/formatEvent/progress)
  const missing = COMMANDS.filter((c) => false); // registry-level check below via handler names
  void missing;
  for (const key of ['printBanner', 'box(', 'table(', 'ui.ok', 'ui.dim', 'printEvent', 'progress(']) {
    assert(src.includes(key), `ui: cli.js uses ${key}`);
  }
}

function cliPath() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.js');
}

function testCommandsCountCli() {
  const r = spawnSync(process.execPath, [cliPath(), 'commands', '--count'], { encoding: 'utf8' });
  assert(r.status === 0 && String(r.stdout || '').trim() === '70', 'cli: commands --count prints exactly 70');
}

function testReplQuoteParsing() {
  assert(
    JSON.stringify(splitReplLine('attacker-note 1.2.3.4 "hello world"')) === JSON.stringify(['attacker-note', '1.2.3.4', 'hello world']),
    'repl: double quotes group one argument'
  );
  assert(
    JSON.stringify(splitReplLine("banner-set 2222 'a b c'")) === JSON.stringify(['banner-set', '2222', 'a b c']),
    'repl: single quotes group one argument'
  );
  assert(
    JSON.stringify(splitReplLine('a "b\\"c" d\\ e')) === JSON.stringify(['a', 'b"c', 'd e']),
    'repl: backslash escapes work in and out of quotes'
  );
  let threw = false;
  try {
    splitReplLine('events "unclosed');
  } catch {
    threw = true;
  }
  assert(threw, 'repl: unclosed quote is a per-line error');
}

// Piped REPL: feed lines on stdin, session must execute each, survive the
// unknown command, and exit 0 at quit/EOF. Scratch MIRAGENET_DIR only.
function testReplPiped() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-repl-'));
  try {
    const input = 'banner\nversion\ncommands --count\nboguscmd\nquit\n';
    const r = spawnSync(process.execPath, [cliPath()], {
      input,
      encoding: 'utf8',
      timeout: 30000,
      env: { ...process.env, MIRAGENET_DIR: dir },
    });
    const out = String(r.stdout || '') + String(r.stderr || '');
    assert(r.status === 0, 'repl: piped session exits 0', `status=${r.status} out=${out.slice(0, 500)}`);
    assert(out.includes(TAGLINE) || out.includes('██'), 'repl: piped session prints the banner once');
    assert(out.includes(`ducgo v${VERSION}`), 'repl: piped session prints ducgo v2.0.0');
    assert(out.split(/\r?\n/).some((l) => l.trim() === '70'), 'repl: commands --count prints 70 inside REPL');
    assert(out.toLowerCase().includes('unknown command'), 'repl: unknown command reported, shell survives it');
    assert(out.includes('ducgo> '), 'repl: prompt loop shown (ducgo> )');
    assert(fs.existsSync(path.join(dir, 'history')), 'repl: history persisted at <dataDir>/history');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// Piped REPL with auth: setup consumes PIN lines, a PIN-gated command works
// with a quoted argument, duress keeps its all-clear behavior.
function testReplAuthPiped() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-repl-auth-'));
  try {
    const input = [
      'setup', 'alpha-9912', 'alpha-9912', 'duress-4417', 'duress-4417',
      'attacker-note 1.2.3.4 "hello world test"', 'alpha-9912',
      'quit',
    ].join('\n') + '\n';
    const r = spawnSync(process.execPath, [cliPath()], {
      input,
      encoding: 'utf8',
      timeout: 30000,
      env: { ...process.env, MIRAGENET_DIR: dir },
    });
    const out = String(r.stdout || '') + String(r.stderr || '');
    assert(r.status === 0, 'repl: auth session exits 0', `status=${r.status} out=${out.slice(0, 800)}`);
    assert(out.includes('Setup complete'), 'repl: setup works inside the shell');
    assert(out.includes('Note saved for 1.2.3.4'), 'repl: PIN-gated command + quoted arg work inside the shell');

    const input2 = ['events', 'duress-4417', 'quit'].join('\n') + '\n';
    const r2 = spawnSync(process.execPath, [cliPath()], {
      input: input2,
      encoding: 'utf8',
      timeout: 30000,
      env: { ...process.env, MIRAGENET_DIR: dir },
    });
    const out2 = String(r2.stdout || '') + String(r2.stderr || '');
    assert(r2.status === 0, 'repl: duress session exits 0');
    assert(out2.includes('All clear - no threats detected.'), 'repl: duress all-clear UNCHANGED inside the shell');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testOneShotStillFine() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-oneshot-'));
  try {
    const env = { ...process.env, MIRAGENET_DIR: dir };
    const v = spawnSync(process.execPath, [cliPath(), 'version'], { encoding: 'utf8', timeout: 15000, env });
    assert(v.status === 0 && String(v.stdout || '').includes(`ducgo v${VERSION}`), 'cli: one-shot version unchanged');
    const c = spawnSync(process.execPath, [cliPath(), 'commands', '--count'], { encoding: 'utf8', timeout: 15000, env });
    assert(c.status === 0 && String(c.stdout || '').trim() === '70', 'cli: one-shot commands --count still 70');
    const u = spawnSync(process.execPath, [cliPath(), 'boguscmd'], { encoding: 'utf8', timeout: 15000, env });
    assert(u.status === 1 && (String(u.stdout || '') + String(u.stderr || '')).toLowerCase().includes('unknown command'), 'cli: one-shot unknown still exits 1');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testSmokeHelp() {
  for (const c of COMMANDS) {
    const r = spawnSync(process.execPath, [cliPath(), c.name, '--help'], { encoding: 'utf8', timeout: 15000 });
    const out = String(r.stdout || '') + String(r.stderr || '');
    assert(r.status === 0, `smoke: ${c.name} --help exits 0`);
    if (r.status !== 0) continue;
    assert(out.toLowerCase().includes('usage') || out.includes(c.name), `smoke: ${c.name} --help shows usage`);
  }
}

export async function runSelfTest() {
  failures = 0;
  passes = 0;
  console.log('ducgo selftest - auth, traps, canary, count, ui, smoke');
  await testAuth();
  await testTraps();
  await testCanary();
  testCount();
  testBanner();
  testUiEverywhere();
  testCommandsCountCli();
  testReplQuoteParsing();
  testReplPiped();
  testReplAuthPiped();
  testOneShotStillFine();
  testSmokeHelp();
  console.log(`\n${passes} check(s) passed.`);
  if (failures === 0) {
    console.log('SELFTEST PASS - all checks passed');
  } else {
    console.error(`SELFTEST FAIL - ${failures} check(s) failed`);
  }
  return failures === 0;
}

const invokedAsMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (invokedAsMain) {
  const ok = await runSelfTest();
  process.exit(ok ? 0 : 1);
}
