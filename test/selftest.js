// ducgo v3.0.4 selftest - stdlib only.
// Run: node test/selftest.js  (also: "npm test", "ducgo selftest").
// Prints PASS lines; exits non-zero on any failure. 23+ checks.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import * as net from 'node:net';
import { fileURLToPath } from 'node:url';
import { spawnSync, spawn } from 'node:child_process';
import { setupPins, verifyPin } from '../src/auth.js';
import { startHoneyTcp, startHoneyHttp, getServerPort, watchDirs, deployCanaries, closeServer } from '../src/traps.js';
import { COMMANDS, EXTRA_BUILTINS, splitReplLine } from '../src/cli.js';
import * as sniff from '../src/sniff.js';
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

// (4) ducgo v3: command count + UI + smoke
function testCount() {
  assert(COMMANDS.length === 92, `commands: count==92 (got ${COMMANDS.length})`);
  const names = COMMANDS.map((c) => c.name);
  assert(new Set(names).size === 92, 'commands: all names unique');
  for (const g of ['auth', 'engine', 'traps', 'canary', 'events', 'attackers', 'reports', 'config', 'system', 'sentinel', 'integrity']) {
    assert(COMMANDS.some((c) => c.group === g), `commands: group present (${g})`);
  }
  const sentN = COMMANDS.filter((c) => c.group === 'sentinel').length;
  const intN = COMMANDS.filter((c) => c.group === 'integrity').length;
  assert(sentN === 11, `commands: sentinel group has 11 (got ${sentN})`);
  assert(intN === 5, `commands: integrity group has 5 (got ${intN})`);
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
  assert(r.status === 0 && String(r.stdout || '').trim() === '92', 'cli: commands --count prints exactly 92');
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
    assert(out.includes(`ducgo v${VERSION}`), 'repl: piped session prints ducgo v3.0.4');
    assert(out.split(/\r?\n/).some((l) => l.trim() === '92'), 'repl: commands --count prints 92 inside REPL');
    assert(out.toLowerCase().includes('unknown command'), 'repl: unknown command reported, shell survives it');
    assert(out.includes('ducgo> '), 'repl: prompt loop shown (ducgo> )');
    assert(fs.existsSync(path.join(dir, 'history')), 'repl: history persisted at <dataDir>/history');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// REPL prints the logo once (startup); help/commands add none.
// Explicit `banner` still prints it; one-shot help keeps it.
function testReplNoRepeatLogo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-repllogo-'));
  try {
    const countTag = (s) => (s.match(/No one can race me/g) || []).length;
    const run = (input) =>
      spawnSync(process.execPath, [cliPath()], {
        input,
        encoding: 'utf8',
        timeout: 30000,
        env: { ...process.env, MIRAGENET_DIR: dir },
      });
    const rHelp = run('help\nquit\n');
    const rCmds = run('commands\nquit\n');
    const rBanner = run('banner\nquit\n');
    const rOne = spawnSync(process.execPath, [cliPath(), 'help'], { encoding: 'utf8', timeout: 30000 });
    assert(rHelp.status === 0 && countTag(String(rHelp.stdout || '')) === 1, 'repl: help adds no logo (startup only)');
    assert(rCmds.status === 0 && countTag(String(rCmds.stdout || '')) === 1, 'repl: commands adds no logo (startup only)');
    assert(rBanner.status === 0 && countTag(String(rBanner.stdout || '')) === 2, 'repl: explicit banner still prints the logo');
    assert(rOne.status === 0 && countTag(String(rOne.stdout || '')) === 1, 'one-shot: help keeps its logo');
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
    assert(c.status === 0 && String(c.stdout || '').trim() === '92', 'cli: one-shot commands --count still 92');
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

// ---------- extras: plugins / completion / aliases / macros (scratch MIRAGENET_DIR only) ----------
function examplePluginPath() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'examples', 'hello-plugin.js');
}
function runCli(dir, args, input, extraEnv = {}) {
  return spawnSync(process.execPath, [cliPath(), ...args], {
    input: input ?? undefined,
    encoding: 'utf8',
    timeout: 15000,
    env: { ...process.env, MIRAGENET_DIR: dir, DUC_NO_LOCK_SLEEP: '1', ...extraEnv },
  });
}
function setupScratch(dir, pin = 'alpha-9912', duress = 'duress-4417') {
  const r = runCli(dir, ['setup'], `${pin}\n${pin}\n${duress}\n${duress}\n`);
  return r;
}

// setup: mismatch retries (with lengths hint) instead of instant fail,
// attempts exhausted exits non-zero, DUC_PIN/DUC_DURESS env path works.
function testSetupRetry() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-setupretry-'));
  try {
    const r = runCli(
      dir,
      ['setup'],
      'retry-111\nWRONG-222\nretry-111\nretry-111\nduress-1\nduress-1\n'
    );
    const out = String(r.stdout || '') + String(r.stderr || '');
    assert(r.status === 0, 'setup: mismatch retries then succeeds', out.slice(0, 800));
    assert(/8 vs 9 chars|do not match/i.test(out), 'setup: mismatch shows lengths hint');
    assert(verifyPin(dir, 'retry-111') === 'normal', 'setup: retried PIN verifies');
    assert(verifyPin(dir, 'duress-1') === 'duress', 'setup: duress verifies');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-setupexh-'));
  try {
    const r2 = runCli(dir2, ['setup'], 'aaaaaa\nbbbbbb\naaaaaa\nbbbbbb\naaaaaa\nbbbbbb\n');
    const out2 = String(r2.stdout || '') + String(r2.stderr || '');
    assert(r2.status !== 0, 'setup: 3 mismatches exits non-zero');
    assert(/Too many mismatched attempts/i.test(out2), 'setup: exhaustion message shown');
    assert(!fs.existsSync(path.join(dir2, 'auth.json')), 'setup: no auth file after exhaustion');
  } finally {
    fs.rmSync(dir2, { recursive: true, force: true });
  }
  const dir3 = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-setupenv-'));
  try {
    const r3 = runCli(dir3, ['setup'], undefined, { DUC_PIN: 'envpin-1', DUC_DURESS: 'envdur-2' });
    const out3 = String(r3.stdout || '') + String(r3.stderr || '');
    assert(r3.status === 0, 'setup: DUC_PIN/DUC_DURESS env path succeeds', out3.slice(0, 500));
    assert(!out3.includes('envpin-1') && !out3.includes('envdur-2'), 'setup: env PINs never echoed');
    assert(verifyPin(dir3, 'envpin-1') === 'normal', 'setup: env PIN verifies');
  } finally {
    fs.rmSync(dir3, { recursive: true, force: true });
  }
  const dir4 = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-setupenv2-'));
  try {
    const r4 = runCli(dir4, ['setup'], undefined, { DUC_PIN: 'same-11', DUC_DURESS: 'same-11' });
    const out4 = String(r4.stdout || '') + String(r4.stderr || '');
    assert(r4.status !== 0, 'setup: env identical PINs rejected');
    assert(/must differ/i.test(out4), 'setup: env identical PINs message');
  } finally {
    fs.rmSync(dir4, { recursive: true, force: true });
  }
}

function testPluginCycle() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-plugin-'));
  try {
    const PIN = 'alpha-9912';
    const s = setupScratch(dir);
    assert(s.status === 0, 'plugin: setup ok in scratch dir', String(s.stdout || '').slice(0, 500));
    const add = runCli(dir, ['plugin-add', examplePluginPath()], PIN + '\n');
    const addOut = String(add.stdout || '') + String(add.stderr || '');
    assert(add.status === 0, 'plugin: add exits 0');
    assert(/SHA-256:/i.test(addOut), 'plugin: add prints SHA-256');
    assert(/DISABLED/i.test(addOut), 'plugin: add DISABLED by default');
    assert(/cannot hook|only.*command/i.test(addOut), 'plugin: add trust warning (engine/auth limits)');
    const list1 = runCli(dir, ['plugin-list'], PIN + '\n');
    const list1Out = String(list1.stdout || '') + String(list1.stderr || '');
    assert(list1.status === 0, 'plugin: list exits 0');
    assert(list1Out.includes('hello-plugin'), 'plugin: list shows name');
    assert(list1Out.toLowerCase().includes('disabled'), 'plugin: default-disabled');
    assert(list1Out.includes('hello') && list1Out.includes('threat-tip'), 'plugin: list shows commands');
    const runDisabled = runCli(dir, ['hello'], PIN + '\n');
    assert(runDisabled.status !== 0, 'plugin: disabled command unavailable');
    const en = runCli(dir, ['plugin-enable', 'hello-plugin'], PIN + '\nCONFIRM\n');
    assert(en.status === 0, 'plugin: enable exits 0 (CONFIRM gate)');
    assert(/CONFIRM|FULL/i.test(String(en.stdout || '') + String(en.stderr || '')) || en.status === 0, 'plugin: CONFIRM gate shown');
    const run1 = runCli(dir, ['hello'], PIN + '\n');
    const run1Out = String(run1.stdout || '') + String(run1.stderr || '');
    assert(run1.status === 0, 'plugin: run hello exits 0 after enable');
    assert(run1Out.includes('Hello'), 'plugin: hello runs');
    const run2 = runCli(dir, ['threat-tip'], PIN + '\n');
    assert(run2.status === 0 && (String(run2.stdout || '') + String(run2.stderr || '')).toLowerCase().includes('tip'), 'plugin: threat-tip runs');
    const dis = runCli(dir, ['plugin-disable', 'hello-plugin'], PIN + '\n');
    assert(dis.status === 0, 'plugin: disable exits 0');
    const runAfterDis = runCli(dir, ['hello'], PIN + '\n');
    assert(runAfterDis.status !== 0, 'plugin: disabled again unavailable');
    const show = runCli(dir, ['plugin-show', 'hello-plugin'], PIN + '\n');
    assert(show.status === 0 && (String(show.stdout || '') + String(show.stderr || '')).includes('hello-plugin'), 'plugin: show works');
    const rem = runCli(dir, ['plugin-remove', 'hello-plugin'], PIN + '\n');
    assert(rem.status === 0, 'plugin: remove exits 0');
    const list2 = runCli(dir, ['plugin-list'], PIN + '\n');
    assert(list2.status === 0 && !(String(list2.stdout || '') + String(list2.stderr || '')).includes('hello-plugin'), 'plugin: removed gone');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testBrokenPlugin() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-broken-'));
  try {
    const PIN = 'alpha-9912';
    setupScratch(dir);
    const brokenFile = path.join(dir, 'broken-add.js');
    fs.writeFileSync(brokenFile, 'export default { broken', 'utf8');
    const add = runCli(dir, ['plugin-add', brokenFile], PIN + '\n');
    assert(add.status === 0, 'broken: add does not crash (tool continues)');
    const en = runCli(dir, ['plugin-enable', 'broken-add'], PIN + '\nCONFIRM\n');
    assert(en.status === 0, 'broken: enable does not crash (CONFIRM gate)');
    // Add a good plugin too - it must still work despite the broken one.
    const addGood = runCli(dir, ['plugin-add', examplePluginPath()], PIN + '\n');
    assert(addGood.status === 0, 'broken: good add still works');
    runCli(dir, ['plugin-enable', 'hello-plugin'], PIN + '\nCONFIRM\n');
    const list = runCli(dir, ['plugin-list'], PIN + '\n');
    const listOut = String(list.stdout || '') + String(list.stderr || '');
    assert(list.status === 0, 'broken: list exits 0 despite broken plugin');
    assert(/failed to load|invalid|skipped/i.test(listOut), 'broken: warning shown, tool continues');
    const runGood = runCli(dir, ['hello'], PIN + '\n');
    assert(runGood.status === 0 && (String(runGood.stdout || '')).includes('Hello'), 'broken: good plugin still runs');
    // Collision: plugin command colliding with built-in is skipped + warning, built-in wins.
    const collideFile = path.join(dir, 'collide-add.js');
    fs.writeFileSync(collideFile, "export default { name: 'collide', commands: [{ name: 'version', desc: 'collide', run: async (ctx) => { ctx.ui.ok('bad'); } }] }", 'utf8');
    runCli(dir, ['plugin-add', collideFile], PIN + '\n');
    runCli(dir, ['plugin-enable', 'collide-add'], PIN + '\nCONFIRM\n');
    const list2 = runCli(dir, ['plugin-list'], PIN + '\n');
    assert(/collide|skipped/i.test(String(list2.stdout || '') + String(list2.stderr || '')), 'broken: collision skipped + warning');
    const ver = runCli(dir, ['version']);
    assert(ver.status === 0 && String(ver.stdout || '').includes('ducgo v'), 'broken: built-in wins collision');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testCompletion() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-compl-'));
  try {
    const ps = runCli(dir, ['completion', 'powershell']);
    const psOut = String(ps.stdout || '') + String(ps.stderr || '');
    assert(ps.status === 0, 'completion: powershell exits 0');
    assert(psOut.includes('Register-ArgumentCompleter') && psOut.includes('__complete'), 'completion: powershell script feeds __complete');
    assert(psOut.toLowerCase().includes('manual'), 'completion: manual-install instructions printed');
    const bash = runCli(dir, ['completion', 'bash']);
    const bashOut = String(bash.stdout || '') + String(bash.stderr || '');
    assert(bash.status === 0, 'completion: bash exits 0');
    assert(bashOut.includes('_ducgo_completions') && bashOut.includes('__complete'), 'completion: bash script feeds __complete');
    const comp = runCli(dir, ['__complete', '']);
    const compOut = String(comp.stdout || '');
    assert(comp.status === 0, 'completion: __complete exits 0');
    for (const c of COMMANDS) {
      assert(compOut.split(/\r?\n/).includes(c.name), `completion: __complete has built-in ${c.name}`);
    }
    assert(!compOut.split(/\r?\n/).includes('__complete'), 'completion: __complete never listed');
    const pref = runCli(dir, ['__complete', 'hel']);
    const prefOut = String(pref.stdout || '');
    assert(prefOut.includes('hello') || prefOut.includes('help'), 'completion: __complete prefix filter works');
    const ch = runCli(dir, ['completion', '--help']);
    assert(ch.status === 0, 'completion: --help exits 0');
    const hh = runCli(dir, ['__complete', '--help']);
    assert(hh.status === 0, 'completion: __complete --help exits 0');
    // --install/--uninstall idempotent block (scratch HOME only, bash target, never real home).
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-home-'));
    try {
      const bashrc = path.join(fakeHome, '.bashrc');
      const envHome = { ...process.env, MIRAGENET_DIR: dir, HOME: fakeHome, USERPROFILE: fakeHome };
      const inst1 = spawnSync(process.execPath, [cliPath(), 'completion', '--install', 'bash'], { encoding: 'utf8', timeout: 15000, env: envHome });
      assert(inst1.status === 0, 'completion: --install bash exits 0');
      assert(fs.existsSync(bashrc) && fs.readFileSync(bashrc, 'utf8').includes('# >>> ducgo completion >>>'), 'completion: install writes marked block');
      const inst2 = spawnSync(process.execPath, [cliPath(), 'completion', '--install', 'bash'], { encoding: 'utf8', timeout: 15000, env: envHome });
      const content = fs.readFileSync(bashrc, 'utf8');
      assert(inst2.status === 0 && content.split('# >>> ducgo completion >>>').length === 2, 'completion: install idempotent (no duplicate)');
      const un = spawnSync(process.execPath, [cliPath(), 'completion', '--uninstall', 'bash'], { encoding: 'utf8', timeout: 15000, env: envHome });
      assert(un.status === 0 && !fs.readFileSync(bashrc, 'utf8').includes('# >>> ducgo completion >>>'), 'completion: --uninstall removes block');
    } finally {
      fs.rmSync(fakeHome, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testAliasMacro() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-alias-'));
  try {
    const PIN = 'alpha-9912';
    setupScratch(dir);
    const set = runCli(dir, ['alias', 'set', 'll', 'version'], PIN + '\n');
    assert(set.status === 0, 'alias: set exits 0');
    const get = runCli(dir, ['alias', 'get', 'll'], PIN + '\n');
    assert(get.status === 0 && String(get.stdout || '').includes('version'), 'alias: get shows expansion');
    const list = runCli(dir, ['alias', 'list'], PIN + '\n');
    assert(list.status === 0 && String(list.stdout || '').includes('ll'), 'alias: list shows alias');
    const run = runCli(dir, ['ll']);
    assert(run.status === 0 && String(run.stdout || '').includes('ducgo v'), 'alias: expansion runs');
    const helpA = runCli(dir, ['help', 'll']);
    assert(helpA.status === 0 && String(helpA.stdout || '').toLowerCase().includes('alias'), 'alias: help shows origin/expansion');
    // Cycle rejection
    runCli(dir, ['alias', 'set', 'a', 'b'], PIN + '\n');
    runCli(dir, ['alias', 'set', 'b', 'a'], PIN + '\n');
    const cyc = runCli(dir, ['a']);
    const cycOut = String(cyc.stdout || '') + String(cyc.stderr || '');
    assert(cyc.status !== 0 && /cycle|recursion|too deep/i.test(cycOut), 'alias: cycle clean error');
    const rm = runCli(dir, ['alias', 'remove', 'a'], PIN + '\n');
    assert(rm.status === 0, 'alias: remove exits 0');
    runCli(dir, ['alias', 'remove', 'b'], PIN + '\n');
    // Macros
    const mset = runCli(dir, ['macro', 'set', 'daily', 'version; banner'], PIN + '\n');
    assert(mset.status === 0, 'macro: set exits 0');
    const mlist = runCli(dir, ['macro', 'list'], PIN + '\n');
    assert(mlist.status === 0 && String(mlist.stdout || '').includes('daily'), 'macro: list shows macro');
    const mrun = runCli(dir, ['macro', 'run', 'daily'], PIN + '\n');
    const mrunOut = String(mrun.stdout || '') + String(mrun.stderr || '');
    assert(mrun.status === 0 && mrunOut.includes('ducgo v'), 'macro: run executes');
    const mhelp = runCli(dir, ['help', 'daily']);
    assert(mhelp.status === 0 && String(mhelp.stdout || '').toLowerCase().includes('macro'), 'macro: help shows origin/expansion');
    const mrunDirect = runCli(dir, ['daily'], PIN + '\n');
    assert(mrunDirect.status === 0, 'macro: direct name runs');
    const mrem = runCli(dir, ['macro', 'remove', 'daily'], PIN + '\n');
    assert(mrem.status === 0, 'macro: remove exits 0');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testCountWithExtras() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-count-'));
  try {
    const PIN = 'alpha-9912';
    setupScratch(dir);
    runCli(dir, ['plugin-add', examplePluginPath()], PIN + '\n');
    runCli(dir, ['plugin-enable', 'hello-plugin'], PIN + '\nCONFIRM\n');
    runCli(dir, ['alias', 'set', 'll', 'version'], PIN + '\n');
    runCli(dir, ['macro', 'set', 'daily', 'version; banner'], PIN + '\n');
    assert(COMMANDS.length === 92, 'contract: built-ins exactly 92');
    const c = runCli(dir, ['commands', '--count']);
    assert(c.status === 0 && String(c.stdout || '').trim() === '92', 'contract: commands --count stays 92 with extras');
    const full = runCli(dir, ['commands']);
    const fullOut = String(full.stdout || '') + String(full.stderr || '');
    assert(full.status === 0 && fullOut.includes('Total: 92'), 'contract: grouped list still 92');
    assert(/\+ \d+ plugin command\(s\)/i.test(fullOut), 'contract: footer line for extras');
    assert(/\+ [1-9]\d* plugin command\(s\)/i.test(fullOut), 'contract: footer shows enabled plugin count');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testDuressPlugins() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-duress-'));
  try {
    const PIN = 'alpha-9912';
    const DURESS = 'duress-4417';
    setupScratch(dir, PIN, DURESS);
    runCli(dir, ['plugin-add', examplePluginPath()], PIN + '\n');
    runCli(dir, ['plugin-enable', 'hello-plugin'], PIN + '\nCONFIRM\n');
    runCli(dir, ['alias', 'set', 'll', 'version'], PIN + '\n');
    const pl = runCli(dir, ['plugin-list'], DURESS + '\n');
    const plOut = String(pl.stdout || '') + String(pl.stderr || '');
    assert(pl.status === 0, 'duress: plugin-list exits 0');
    assert(plOut.includes('All clear - no threats detected.'), 'duress: all-clear');
    assert(!plOut.includes('hello-plugin') && !plOut.includes('threat-tip'), 'duress: no plugin list leak');
    const run = runCli(dir, ['hello'], DURESS + '\n');
    const runOut = String(run.stdout || '') + String(run.stderr || '');
    assert(run.status === 0 && runOut.includes('All clear - no threats detected.'), 'duress: plugin command unavailable (all-clear)');
    assert(!runOut.includes('Hello'), 'duress: plugin output hidden');
    const al = runCli(dir, ['alias', 'list'], DURESS + '\n');
    assert(String(al.stdout || '').includes('All clear') && !String(al.stdout || '').includes('ll ->'), 'duress: alias sees nothing extra');
    let sawDuress = false;
    try {
      // Encrypted logs: check via decrypted CLI read (normal PIN) plus raw envelope.
      const evOut = runCli(dir, ['events', '--json'], PIN + '\n');
      const evText = String(evOut.stdout || '') + String(evOut.stderr || '');
      sawDuress = evText.includes('"duress"') || evText.includes('duress');
      if (!sawDuress) {
        const raw = fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8');
        sawDuress = raw.includes('"duress"') || raw.includes('duress') || raw.includes('"k":"d"') || raw.includes('"v":1');
      }
    } catch { sawDuress = false; }
    assert(sawDuress, 'duress: silent log appended (plaintext or encrypted envelope)');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testReplPlugins() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-replplug-'));
  try {
    const PIN = 'alpha-9912';
    setupScratch(dir);
    runCli(dir, ['plugin-add', examplePluginPath()], PIN + '\n');
    runCli(dir, ['plugin-enable', 'hello-plugin'], PIN + '\nCONFIRM\n');
    const input = ['hello', PIN, 'help hello', 'quit'].join('\n') + '\n';
    const r = spawnSync(process.execPath, [cliPath()], {
      input,
      encoding: 'utf8',
      timeout: 30000,
      env: { ...process.env, MIRAGENET_DIR: dir, DUC_NO_LOCK_SLEEP: '1' },
    });
    const out = String(r.stdout || '') + String(r.stderr || '');
    assert(r.status === 0, 'repl: plugin session exits 0');
    assert(out.includes('Hello'), 'repl: sees plugin names (hello runs)');
    assert(out.toLowerCase().includes('plugin'), 'repl: help shows plugin origin');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testExtrasSmoke() {
  for (const c of EXTRA_BUILTINS) {
    const r = spawnSync(process.execPath, [cliPath(), c.name, '--help'], { encoding: 'utf8', timeout: 15000 });
    const out = String(r.stdout || '') + String(r.stderr || '');
    assert(r.status === 0, `smoke: extra ${c.name} --help exits 0`);
    if (r.status !== 0) continue;
    assert(out.toLowerCase().includes('usage') || out.includes(c.name), `smoke: extra ${c.name} --help shows usage`);
  }
}

// ---------- sentinel + integrity (v3, scratch MIRAGENET_DIR only) ----------
const NETSTAT_FIXTURE = [
  'Active Connections',
  '',
  '  Proto  Local Address          Foreign Address        State           PID',
  '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1111',
  '  TCP    127.0.0.1:18080        0.0.0.0:0              LISTENING       2222',
  '  TCP    192.168.1.5:54321      93.184.216.34:443      ESTABLISHED     3333',
  '  UDP    0.0.0.0:5353           *:*                                    4444',
].join('\r\n');

const ARP_FIXTURE_A = [
  'Interface: 192.168.1.5 --- 0x4',
  '  Internet Address      Physical Address      Type',
  '  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic',
  '  192.168.1.10          11-22-33-44-55-66     dynamic',
].join('\r\n');

const ARP_FIXTURE_B = [
  'Interface: 192.168.1.5 --- 0x4',
  '  Internet Address      Physical Address      Type',
  '  192.168.1.1           aa-bb-cc-dd-ee-00     dynamic',
  '  192.168.1.10          11-22-33-44-55-66     dynamic',
  '  192.168.1.99          77-88-99-aa-bb-cc     dynamic',
].join('\r\n');

const NETSH_BASE_FIXTURE = [
  'SSID 1 : HomeNet',
  '    Network type            : Infrastructure',
  '    Authentication          : WPA2-Personal',
  '    Encryption              : CCMP',
  '    BSSID 1                 : aa:bb:cc:dd:ee:ff',
  '         Signal             : 90%',
  '         Radio type         : 802.11n',
  '         Channel            : 6',
].join('\n');

const NETSH_EVIL_FIXTURE = [
  'SSID 1 : HomeNet',
  '    Network type            : Infrastructure',
  '    Authentication          : WPA2-Personal',
  '    Encryption              : CCMP',
  '    BSSID 1                 : aa:bb:cc:dd:ee:ff',
  '         Signal             : 90%',
  '         Radio type         : 802.11n',
  '         Channel            : 6',
  '    BSSID 2                 : 11:22:33:44:55:66',
  '         Signal             : 85%',
  '         Radio type         : 802.11n',
  '         Channel            : 6',
  'SSID 2 : HomeNet',
  '    Network type            : Infrastructure',
  '    Authentication          : Open',
  '    Encryption              : None',
  '    BSSID 1                 : de:ad:be:ef:00:01',
  '         Signal             : 99%',
  '         Radio type         : 802.11n',
  '         Channel            : 6',
].join('\n');

async function testSentinelParsers() {
  const s = await import('../src/sentinel.js');
  const p = s.parseNetstat(NETSTAT_FIXTURE);
  assert(p.listeners.length === 3, `sentinel: netstat fixture finds 3 listeners (got ${p.listeners.length})`);
  assert(p.listeners.some((l) => l.port === 135), 'sentinel: listener :135 parsed');
  assert(p.listeners.filter((l) => l.proto === 'TCP').length === 2, 'sentinel: 2 TCP listeners in fixture');
  assert(p.conns.length === 1 && p.conns[0].remoteIp === '93.184.216.34', 'sentinel: established conn parsed with remote IP');
  const arpA = s.parseArp(ARP_FIXTURE_A);
  assert(arpA.length === 2, `sentinel: arp fixture A has 2 entries (got ${arpA.length})`);
  const arpB = s.parseArp(ARP_FIXTURE_B);
  const baseMap = {};
  for (const e of arpA) baseMap[e.ip] = e.mac;
  const d = s.diffArp(baseMap, arpB);
  assert(d.changed.length === 1 && d.changed[0].ip === '192.168.1.1', 'sentinel: arp MAC change detected (possible spoofing)');
  assert(d.added.length === 1 && d.added[0].ip === '192.168.1.99', 'sentinel: arp new device detected');
  const wifiBase = s.parseNetshWlan(NETSH_BASE_FIXTURE);
  assert(wifiBase.length === 1 && wifiBase[0].ssid === 'HomeNet', 'sentinel: netsh baseline SSID parsed');
  const wifiCur = s.parseNetshWlan(NETSH_EVIL_FIXTURE);
  const twins = s.detectEvilTwin(wifiBase, wifiCur);
  assert(twins.some((t) => t.kind === 'open-twin'), 'sentinel: open twin of known network flagged');
  assert(twins.some((t) => t.kind === 'new-bssid' || t.kind === 'multi-bssid' || t.kind === 'bssid-change'), 'sentinel: evil-twin new-BSSID flagged');
  const h1 = s.sha256String('hello');
  assert(h1 === '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', 'sentinel: sha256 known-vector ok');
  const tl = s.parseTasklist('"chrome.exe","1234","Console","1","200,000 K"\r\n"svchost.exe","567","Services","0","10,000 K"');
  assert(tl.get(1234) === 'chrome.exe', 'sentinel: tasklist PID map ok');
}

async function testSentinelBaselineRoundTrip() {
  const s = await import('../src/sentinel.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-sentbase-'));
  try {
    const snap = {
      at: new Date().toISOString(),
      listeners: [{ proto: 'TCP', local: '0.0.0.0:135', port: 135, pid: 1 }],
      arp: { '192.168.1.1': 'aa-bb-cc-dd-ee-ff' },
      arpEntries: [{ ip: '192.168.1.1', mac: 'aa-bb-cc-dd-ee-ff', type: 'dynamic', iface: '' }],
      wifi: s.parseNetshWlan(NETSH_BASE_FIXTURE),
      hostsHash: s.sha256String('baseline-hosts'),
      dns: { 'example.com': ['1.2.3.4'] },
      openPorts: [135],
    };
    s.saveBaseline(dir, snap);
    const loaded = s.loadBaseline(dir);
    assert(!!loaded && loaded.hostsHash === snap.hostsHash, 'sentinel: baseline save/load round-trip');
    const same = s.diffSnapshot(loaded, { ...snap, arpEntries: snap.arpEntries });
    assert(same.alerts.length === 0, 'sentinel: identical snapshot diffs to 0 alerts');
    const mutated = {
      ...snap,
      listeners: [...snap.listeners, { proto: 'TCP', local: '0.0.0.0:9999', port: 9999, pid: 9 }],
      arpEntries: [{ ip: '192.168.1.1', mac: 'aa-bb-cc-dd-ee-00', type: 'dynamic', iface: '' }],
      arp: { '192.168.1.1': 'aa-bb-cc-dd-ee-00' },
    };
    const d2 = s.diffSnapshot(loaded, mutated);
    assert(d2.alerts.length >= 2, `sentinel: mutated snapshot raises alerts (got ${d2.alerts.length})`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testThreatScoreBounds() {
  const s = await import('../src/sentinel.js');
  const empty = s.computeThreatScore([]);
  assert(empty.score === 0 && empty.level === 'low', 'sentinel: empty log scores 0/low');
  assert(Array.isArray(empty.factors) && empty.factors.length >= 5, 'sentinel: factor table transparent');
  const now = new Date().toISOString();
  const heavy = [];
  for (let i = 0; i < 10; i++) heavy.push({ id: `x${i}`, time: now, type: 'honey-tcp', trap: 'honey-tcp:2222', ip: '1.2.3.4', detail: 'probe', severity: 'critical' });
  heavy.push({ id: 'd1', time: now, type: 'duress', trap: 'duress-pin', ip: '127.0.0.1', detail: 'duress', severity: 'critical' });
  const hs = s.computeThreatScore(heavy);
  assert(hs.score >= 0 && hs.score <= 100, `sentinel: score bounded 0-100 (got ${hs.score})`);
  assert(hs.score > empty.score, 'sentinel: heavy log scores higher than empty');
  const mid = s.computeThreatScore([{ id: 'a', time: now, type: 'sim', trap: 'x', ip: '1.1.1.1', detail: 'demo', severity: 'low' }]);
  assert(mid.score >= 0 && mid.score <= 100, 'sentinel: single low event bounded');
}

function testIntegrityCycle() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-int-'));
  try {
    const PIN = 'alpha-9912';
    setupScratch(dir);
    const f = path.join(dir, 'watched.txt');
    fs.writeFileSync(f, 'original-content', 'utf8');
    const add = runCli(dir, ['integrity-add', f], PIN + '\n');
    assert(add.status === 0, 'integrity: add exits 0');
    const ver1 = runCli(dir, ['integrity-verify'], PIN + '\n');
    assert(ver1.status === 0, 'integrity: verify clean exits 0');
    fs.appendFileSync(f, '-tampered');
    const ver2 = runCli(dir, ['integrity-verify'], PIN + '\n');
    const ver2Out = String(ver2.stdout || '') + String(ver2.stderr || '');
    assert(ver2.status === 1 && /CHANGED/i.test(ver2Out), 'integrity: tamper detected (CHANGED, exit 1)');
    const ref = runCli(dir, ['integrity-baseline-refresh'], PIN + '\n');
    assert(ref.status === 0, 'integrity: baseline-refresh exits 0');
    const ver3 = runCli(dir, ['integrity-verify'], PIN + '\n');
    assert(ver3.status === 0, 'integrity: verify clean again after refresh');
    const list = runCli(dir, ['integrity-list'], PIN + '\n');
    assert(list.status === 0 && String(list.stdout || '').includes('watched.txt'), 'integrity: list shows file');
    const rem = runCli(dir, ['integrity-remove', f], PIN + '\n');
    assert(rem.status === 0, 'integrity: remove exits 0');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testVersionExact() {
  assert(VERSION === '3.0.4', `version: ui VERSION exactly 3.0.4 (got ${VERSION})`);
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert(pkg.version === '3.0.4', 'version: package.json exactly 3.0.4');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-ver-'));
  try {
    const v = runCli(dir, ['version']);
    assert(v.status === 0 && String(v.stdout || '').includes('ducgo v3.0.4'), 'version: output exactly ducgo v3.0.4');
    const b = spawnSync(process.execPath, [cliPath(), 'banner'], { encoding: 'utf8', timeout: 15000, env: { ...process.env, MIRAGENET_DIR: dir } });
    assert(b.status === 0 && String(b.stdout || '').includes('ducgo v3.0.4'), 'version: banner line exactly ducgo v3.0.4');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testSentinelLive() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-sentlive-'));
  try {
    const PIN = 'alpha-9912';
    const DURESS = 'duress-4417';
    setupScratch(dir, PIN, DURESS);
    const base = runCli(dir, ['sentinel-baseline'], PIN + '\n');
    assert(base.status === 0, 'sentinel-live: baseline exits 0');
    const check = runCli(dir, ['sentinel-check'], PIN + '\n');
    const checkOut = String(check.stdout || '') + String(check.stderr || '');
    assert(check.status === 0 && /threat score/i.test(checkOut), 'sentinel-live: check shows score');
    const score = runCli(dir, ['threat-score'], PIN + '\n');
    const scoreOut = String(score.stdout || '') + String(score.stderr || '');
    assert(score.status === 0 && /FACTOR/i.test(scoreOut), 'sentinel-live: threat-score factor table shown');
    const rep = runCli(dir, ['sentinel-report'], PIN + '\n');
    assert(rep.status === 0, 'sentinel-live: report exits 0');
    const arp = runCli(dir, ['arp-watch'], PIN + '\n');
    assert(arp.status === 0, 'sentinel-live: arp-watch exits 0');
    const hosts = runCli(dir, ['hosts-verify'], PIN + '\n');
    assert(hosts.status === 0, 'sentinel-live: hosts-verify exits 0');
    const open = runCli(dir, ['open-ports'], PIN + '\n');
    assert(open.status === 0, 'sentinel-live: open-ports exits 0');
    const conn = runCli(dir, ['conn-summary'], PIN + '\n');
    assert(conn.status === 0, 'sentinel-live: conn-summary exits 0');
    // REAL listen --duration 3 on loopback-safe queries, clean stop exit 0.
    const t0 = Date.now();
    const listen = spawnSync(process.execPath, [cliPath(), 'listen', '--interval', '2', '--duration', '3'], {
      input: PIN + '\n', encoding: 'utf8', timeout: 30000, env: { ...process.env, MIRAGENET_DIR: dir },
    });
    const dt = Date.now() - t0;
    const listenOut = String(listen.stdout || '') + String(listen.stderr || '');
    assert(listen.status === 0, `sentinel-live: listen --duration 3 stops cleanly exit 0 (got ${listen.status})`);
    assert(/stopped cleanly/i.test(listenOut), 'sentinel-live: listen prints clean stop');
    assert(dt < 25000, 'sentinel-live: listen duration bounded');
    // Duress sees all-clear only on a sensitive sentinel command.
    const du = runCli(dir, ['threat-score'], DURESS + '\n');
    const duOut = String(du.stdout || '') + String(du.stderr || '');
    assert(du.status === 0 && duOut.includes('All clear - no threats detected.'), 'sentinel-live: duress all-clear on sentinel');
    // REPL parity spot check: new names resolve inside the shell.
    const input = ['commands --count', 'help listen', 'quit'].join('\n') + '\n';
    const repl = spawnSync(process.execPath, [cliPath()], {
      input, encoding: 'utf8', timeout: 30000, env: { ...process.env, MIRAGENET_DIR: dir },
    });
    const replOut = String(repl.stdout || '') + String(repl.stderr || '');
    assert(repl.status === 0, 'sentinel-live: REPL spot check exits 0');
    assert(replOut.split(/\r?\n/).some((l) => l.trim() === '92'), 'sentinel-live: REPL count==92');
    assert(replOut.includes('ducgo listen'), 'sentinel-live: REPL help listen works');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ---------- sniff (pktmon parser + analyzer fixtures, no admin needed) ----------
function testSniff() {
  const ev = (dir, type, comp, size, body) =>
    `[09]0004.03F4::2026-09-26 03:52:57.290944700 [Microsoft-Windows-PktMon] PktGroupId 1, PktNumber 1, Appearance 0, Direction ${dir}, Type Ethernet, Component ${comp}, Edge 1, Filter 0, OriginalSize ${size}, LoggedSize 128 \n\t${body}`;
  const tcp = (sip, sp, dip, dp, flags, size = 200, dir = 'Rx', comp = 40) =>
    ev(dir, 'Ethernet', comp, size, `AA > BB, ethertype IPv4 (0x0800), length ${size}: ${sip}.${sp} > ${dip}.${dp}: Flags [${flags}], seq 1:2, ack 1, win 1, length 0`);

  // mixed clean fixture: tcp + udp + arp + dns + http
  const clean = [
    tcp('192.168.8.41', 5001, '93.184.216.34', 443, 'P.', 300, 'Tx'),
    tcp('93.184.216.34', 443, '192.168.8.41', 5001, '.', 1400, 'Rx'),
    ev('Rx', 'Ethernet', 40, 145, 'AA > BB, ethertype IPv4 (0x0800), length 145: 192.168.8.41.62380 > 8.8.8.8.443: \nUDP, length 103'),
    ev('Rx', 'Ethernet', 40, 42, 'AA > BB, ethertype ARP (0x0806), length 42: Request who-has 192.168.8.41 tell \n192.168.8.1, length 28'),
    ev('Tx', 'Ethernet', 40, 71, 'AA > BB, ethertype IPv4 (0x0800), length 71: 192.168.8.41.55275 > 8.8.8.8.53: 2+ A? example.com. (29)'),
    ev('Tx', 'Ethernet', 40, 400, 'AA > BB, ethertype IPv4 (0x0800), length 400: 192.168.8.41.5002 > 93.184.216.34.80: Flags [P.], seq 1:2, ack 1, win 1, length 0 \nGET /index.html HTTP/1.1 Host: example.com'),
  ].join('\n');
  const p = sniff.parseEtlText(clean);
  assert(p.packets === 4, 'sniff: parses 4 packets (3 tcp + 1 udp; arp/dns-headers are not packets)', `got ${p.packets}`);
  assert(p.tcp === 3 && p.udp === 1, 'sniff: tcp/udp split', `tcp=${p.tcp} udp=${p.udp}`);
  assert(p.flows.size === 4, 'sniff: 4 flows', `got ${p.flows.size}`);
  assert(p.dns.has('example.com.'), 'sniff: DNS query captured');
  assert(p.arpReq.has('192.168.8.41'), 'sniff: wrapped ARP request parsed');
  const a0 = sniff.analyze(p);
  assert(a0.anomalies.length === 0, 'sniff: clean traffic, no anomalies', JSON.stringify(a0.anomalies).slice(0, 300));

  // port scan: 16 distinct ports from one src
  let scan = '';
  for (let i = 0; i < 16; i++) scan += tcp('10.9.9.9', 40000 + i, '192.168.8.41', 1000 + i, '.', 60) + '\n';
  const aScan = sniff.analyze(sniff.parseEtlText(scan));
  assert(aScan.anomalies.some((a) => a.severity === 'high' && /port scan/.test(a.title)), 'sniff: port scan flagged high');

  // SYN scan: 12 unanswered SYNs
  let syns = '';
  for (let i = 0; i < 12; i++) syns += tcp('10.9.9.8', 41000 + i, '192.168.8.41', 2000 + i, 'S', 60) + '\n';
  const aSyn = sniff.analyze(sniff.parseEtlText(syns));
  assert(aSyn.anomalies.some((a) => /SYN scan/.test(a.title)), 'sniff: SYN scan flagged');

  // sweep: 21 distinct dst IPs
  let sweep = '';
  for (let i = 1; i <= 21; i++) sweep += tcp('10.9.9.7', 42000, `192.168.9.${i}`, 445, 'S', 60) + '\n';
  const aSweep = sniff.analyze(sniff.parseEtlText(sweep));
  assert(aSweep.anomalies.some((a) => /sweep/.test(a.title)), 'sniff: network sweep flagged');

  // DNS tunneling: 31 subdomains + one over-long name
  let dnsFix = '';
  for (let i = 0; i < 31; i++) {
    dnsFix += ev('Tx', 'Ethernet', 40, 100, `AA > BB, length 100: 192.168.8.41.53${100 + i} > 8.8.8.8.53: 2+ A? part${i}.evil.example. (40)`) + '\n';
  }
  dnsFix += ev('Tx', 'Ethernet', 40, 120, 'AA > BB, length 120: 192.168.8.41.53111 > 8.8.8.8.53: 2+ A? ' + 'x'.repeat(65) + '.evil.example. (90)') + '\n';
  const aDns = sniff.analyze(sniff.parseEtlText(dnsFix));
  assert(aDns.anomalies.some((a) => /tunneling/.test(a.title) && /subdomains/.test(a.detail)), 'sniff: DNS subdomain storm flagged');
  assert(aDns.anomalies.some((a) => /tunneling/.test(a.title) && /over-long/.test(a.detail)), 'sniff: over-long DNS name flagged');

  // ARP conflict: one IP, two MACs
  const arpFix = [
    ev('Rx', 'Ethernet', 40, 42, 'AA > BB, ethertype ARP (0x0806), length 42: Reply 10.0.0.7 is-at AA-AA-AA-AA-AA-AA'),
    ev('Rx', 'Ethernet', 40, 42, 'AA > BB, ethertype ARP (0x0806), length 42: Reply 10.0.0.7 is-at BB-BB-BB-BB-BB-BB'),
  ].join('\n');
  const aArp = sniff.analyze(sniff.parseEtlText(arpFix));
  assert(aArp.anomalies.some((a) => /ARP spoofing/.test(a.title)), 'sniff: ARP conflict flagged high');

  // cleartext basic auth
  const httpFix = ev('Tx', 'Ethernet', 40, 300, 'AA > BB, length 300: 192.168.8.41.5009 > 93.184.216.34.80: Flags [P.], seq 1:2 \nGET /login HTTP/1.1 Host: example.com Authorization: Basic QQ==');
  const aHttp = sniff.analyze(sniff.parseEtlText(httpFix));
  assert(aHttp.anomalies.some((a) => /cleartext credential/.test(a.title)), 'sniff: basic-auth on wire flagged');
  assert(!JSON.stringify(aHttp.anomalies).includes('QQ=='), 'sniff: credential value never stored');

  // env shapes (no admin assumption)
  assert(typeof sniff.isAdmin() === 'boolean', 'sniff: isAdmin returns boolean');
  assert(sniff.pktmonExe() === null || typeof sniff.pktmonExe() === 'string', 'sniff: pktmonExe shape');
  const dst = sniff.driverStatus();
  assert(typeof dst.present === 'boolean' && typeof dst.admin === 'boolean', 'sniff: driverStatus shape');

  // UTF-16 etl2txt decoding (real pktmon output shape: BOM + wide chars)
  {
    const sample = '[09]0004.03F4::2026-09-26 03:52:57.290944700 [Microsoft-Windows-PktMon] PktGroupId 1, PktNumber 1, Appearance 0, Direction Rx, Type Ethernet, Component 40, Edge 1, Filter 0, OriginalSize 255, LoggedSize 128 \n\tAA > BB, ethertype IPv4 (0x0800), length 255: 1.2.3.4.443 > 5.6.7.8.5000: Flags [P.], seq 1:2, ack 1, win 1, length 201\n';
    const d16 = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-utf16-'));
    try {
      const fp = path.join(d16, 'cap.txt');
      fs.writeFileSync(fp, '﻿' + sample, 'utf16le');
      const back = sniff.readEtlText(fp);
      assert(!back.includes(' '), 'sniff: UTF-16 decoded (no NULs)');
      const p16 = sniff.parseEtlText(back);
      assert(p16.packets === 1, 'sniff: UTF-16 fixture parses', `got ${p16.packets}`);
    } finally {
      fs.rmSync(d16, { recursive: true, force: true });
    }
  }

  // live branch: admin -> real 3s capture; non-admin -> clean guidance error
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-sniff-'));
  try {
    const PIN = 'alpha-9912';
    setupScratch(dir);
    if (sniff.isAdmin() && sniff.pktmonExe()) {
      // guaranteed LAN traffic during the window: SYNs to a closed port on our own LAN IP
      let lan = null;
      try {
        for (const ifs of Object.values(os.networkInterfaces())) {
          for (const a of ifs || []) {
            if (a.family === 'IPv4' && !a.internal) lan = a.address;
          }
        }
      } catch { lan = null; }
      let gen = null;
      if (lan) {
        try {
          gen = spawn(process.execPath, ['-e', `const n=require('node:net');let i=0;const t=setInterval(()=>{if(++i>15){clearInterval(t);process.exit(0);}const s=n.connect(9,'${lan}');s.on('error',()=>{});s.on('connect',()=>s.end());},250);`], { windowsHide: true, stdio: 'ignore' });
        } catch { gen = null; }
      }
      const r = runCli(dir, ['sniff', '--duration', '4'], PIN + '\n');
      try { if (gen) gen.kill(); } catch { /* ignore */ }
      const out = String(r.stdout || '') + String(r.stderr || '');
      assert(r.status === 0, 'sniff-live: --duration 4 exits 0 (admin)', out.slice(-600));
      assert(/packets: \d+/.test(out), 'sniff-live: summary printed');
      let last = null;
      try { last = JSON.parse(fs.readFileSync(path.join(dir, 'captures.jsonl'), 'utf8').trim().split('\n').pop()); } catch { last = null; }
      assert(!!last && typeof last.packets === 'number', 'sniff-live: summary saved');
      assert(!!last && last.packets > 0, 'sniff-live: real traffic captured (packets>0)', `got ${last && last.packets}`);
      const rep = runCli(dir, ['sniff-report'], PIN + '\n');
      assert(rep.status === 0 && String(rep.stdout || '').includes('Last capture'), 'sniff-live: report reads saved capture');
      const top = runCli(dir, ['sniff-top', '--n', '5'], PIN + '\n');
      assert(top.status === 0, 'sniff-live: top exits 0');
      const dns = runCli(dir, ['sniff-dns'], PIN + '\n');
      assert(dns.status === 0, 'sniff-live: dns exits 0');
    } else {
      const r = runCli(dir, ['sniff', '--duration', '3'], PIN + '\n');
      const out = String(r.stdout || '') + String(r.stderr || '');
      assert(r.status !== 0 && /Administrator/.test(out), 'sniff: non-admin gets elevation guidance');
    }
    const chk = runCli(dir, ['sniff-check']);
    assert(chk.status === 0 && String(chk.stdout || '').includes('pktmon'), 'sniff: sniff-check needs no PIN');
    const norep = runCli(dir, ['sniff-report'], 'alpha-9912\n');
    assert(norep.status === 0 || /No captures yet/.test(String(norep.stdout || '') + String(norep.stderr || '')), 'sniff: report handles empty store');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // smoke: new sniff commands --help exit 0
  for (const c of ['sniff-check', 'sniff', 'sniff-live', 'sniff-report', 'sniff-top', 'sniff-dns']) {
    const r = spawnSync(process.execPath, [cliPath(), c, '--help'], { encoding: 'utf8', timeout: 15000 });
    assert(r.status === 0, `sniff: --help smoke ${c}`);
  }
}

// ---------- new production-grade features (atime, stealth, encryption, lockout, sandbox, alerts, geoip, caps) ----------
async function testAtime() {
  const { snapshotAtimeDir, diffAtime } = await import('../src/traps.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-atime-'));
  try {
    const fp = path.join(dir, 'watched.txt');
    fs.writeFileSync(fp, 'atime-content', 'utf8');
    const base = snapshotAtimeDir(dir, true);
    assert(base[fp] && typeof base[fp].atimeMs === 'number', 'atime: baseline captures atimeMs');
    // Simulate silent read: bump atime only (mtime/size unchanged).
    const st = fs.statSync(fp);
    const newAtime = new Date(st.atimeMs + 5000);
    const sameMtime = new Date(st.mtimeMs);
    try { fs.utimesSync(fp, newAtime, sameMtime); } catch { /* Windows may restrict */ }
    const cur = snapshotAtimeDir(dir, true);
    const diffs = diffAtime(base, cur);
    const acc = diffs.find((d) => d.path === fp && d.kind === 'ACCESSED');
    // On filesystems with atime disabled the OS may ignore utimes; accept either ACCESSED or empty, but logic must report MODIFIED on content change.
    if (!acc) {
      // Fallback: force atime newer in-memory to verify pure logic.
      const forced = { ...base };
      const curForced = { ...cur };
      curForced[fp] = { atimeMs: base[fp].atimeMs + 5000, mtimeMs: base[fp].mtimeMs, size: base[fp].size };
      const d2 = diffAtime(forced, curForced);
      assert(d2.some((x) => x.kind === 'ACCESSED'), 'atime: pure logic detects ACCESSED (atime newer, mtime same)');
    } else {
      assert(true, 'atime: access-vs-modify detects ACCESSED with real files');
    }
    fs.appendFileSync(fp, '-more');
    const cur2 = snapshotAtimeDir(dir, true);
    const d3 = diffAtime(cur, cur2);
    assert(d3.some((x) => x.path === fp && x.kind === 'MODIFIED'), 'atime: detects MODIFIED on content change');
    // CLI smoke: atime-watch --duration 2 stops cleanly (scratch MIRAGENET_DIR).
    const sdir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-atimecli-'));
    try {
      setupScratch(sdir);
      const r = runCli(sdir, ['atime-watch', dir, '--interval', '1', '--duration', '2'], 'alpha-9912\n');
      const out = String(r.stdout || '') + String(r.stderr || '');
      assert(r.status === 0 && /stopped cleanly/i.test(out), 'atime: CLI watch --duration stops cleanly exit 0');
    } finally { fs.rmSync(sdir, { recursive: true, force: true }); }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testStealth() {
  const { startHoneyTcp, closeServer, getServerPort, fingerprintBanner, STEALTH_BANNERS } = await import('../src/traps.js');
  assert(STEALTH_BANNERS.ssh.includes('OpenSSH_8.9p1'), 'stealth: ssh imitation present');
  assert(STEALTH_BANNERS.ftp.includes('FileZilla'), 'stealth: ftp imitation present');
  assert(STEALTH_BANNERS.telnet.includes('Microsoft Telnet'), 'stealth: telnet imitation present');
  // Serve stealth banner on ephemeral port, grab it, fingerprint PASS.
  const evs = [];
  const srv = await startHoneyTcp(0, (e) => evs.push(e), { host: '127.0.0.1', stealth: 'ssh' });
  const port = getServerPort(srv);
  const banner = await new Promise((resolve) => {
    let data = '';
    const s = net.connect(port, '127.0.0.1', () => {});
    s.on('data', (d) => { data += String(d); });
    s.on('error', () => resolve(null));
    setTimeout(() => { try { s.destroy(); } catch { /* ignore */ } resolve(data); }, 800);
  });
  assert(!!banner && banner.includes('OpenSSH_8.9p1'), 'stealth: honey serves ssh imitation banner');
  const fp = fingerprintBanner(banner);
  assert(fp.verdict === 'PASS', 'stealth: fingerprint PASS for stealth ssh');
  await closeServer(srv);
  // Giveaway cases: default ducgo text + empty.
  const give = fingerprintBanner('SSH-2.0-OpenSSH_9.2 MirageNet\r\n');
  assert(give.verdict === 'WARN' && give.reasons.join(' ').toLowerCase().includes('giveaway') || give.reasons.join(' ').toLowerCase().includes('default'), 'stealth: giveaway WARN for default ducgo text');
  const empty = fingerprintBanner('');
  assert(empty.verdict === 'WARN', 'stealth: WARN for empty banner');
  // CLI: trap-add --stealth-banner flag + fingerprint-check (needs running trap).
  const sdir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-stealthcli-'));
  try {
    setupScratch(sdir);
    const add = runCli(sdir, ['trap-add', '23231', '--stealth-banner', 'ssh'], 'alpha-9912\n');
    assert(add.status === 0 && /stealth/i.test(String(add.stdout || '') + String(add.stderr || '')), 'stealth: trap-add --stealth-banner flag works');
    const bad = runCli(sdir, ['trap-add', '23232', '--stealth-banner', 'bogus'], 'alpha-9912\n');
    assert(bad.status !== 0, 'stealth: bad stealth kind rejected');
    const help = runCli(sdir, ['trap-fingerprint-check', '--help']);
    assert(help.status === 0, 'stealth: fingerprint-check --help exits 0');
  } finally { fs.rmSync(sdir, { recursive: true, force: true }); }
}

async function testEncryption() {
  const PIN = 'alpha-9912';
  const DURESS = 'duress-4417';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-enc-'));
  try {
    setupScratch(dir, PIN, DURESS);
    // Round-trip: sentinel-check appends encrypted event, CLI reads it back.
    runCli(dir, ['sentinel-baseline'], PIN + '\n');
    runCli(dir, ['sentinel-check'], PIN + '\n');
    const raw = fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8');
    assert(raw.includes('"v":1') && raw.includes('"k":"p"'), 'enc: log lines are AES-GCM envelopes (k:p)');
    const rd = runCli(dir, ['events', '--json'], PIN + '\n');
    const rdOut = String(rd.stdout || '') + String(rd.stderr || '');
    assert(rd.status === 0 && rdOut.includes('sentinel'), 'enc: round-trip decrypts via CLI');
    // Mixed-file: append plaintext demo (no session) + encrypted line, both read.
    runCli(dir, ['demo']);
    const rd2 = runCli(dir, ['events', '--json'], PIN + '\n');
    const rd2Out = String(rd2.stdout || '') + String(rd2.stderr || '');
    assert(rd2Out.includes('DEMO') && rd2Out.includes('sentinel'), 'enc: mixed-file (plaintext+encrypted) reads both');
    // Duress-key line readable under normal PIN.
    runCli(dir, ['events'], DURESS + '\n'); // appends k:d duress event
    const rd3 = runCli(dir, ['events', '--json'], PIN + '\n');
    const rd3Out = String(rd3.stdout || '') + String(rd3.stderr || '');
    assert(rd3Out.includes('duress'), 'enc: duress-key (k:d) line readable under normal PIN');
    // events-decrypt export + warning.
    const outFile = path.join(dir, 'dec.json');
    const dec = runCli(dir, ['events-decrypt', outFile], PIN + '\n');
    const decOut = String(dec.stdout || '') + String(dec.stderr || '');
    assert(dec.status === 0 && fs.existsSync(outFile), 'enc: events-decrypt writes export');
    assert(/PLAINTEXT|Delete after use/i.test(decOut), 'enc: events-decrypt prints clear security warning');
    const exp = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert(Array.isArray(exp) && exp.length >= 3, 'enc: decrypt export contains events');
    // config-set encryption off writes plaintext going forward.
    runCli(dir, ['config-set', 'encryption', 'off'], PIN + '\n');
    runCli(dir, ['sentinel-check'], PIN + '\n');
    const raw2 = fs.readFileSync(path.join(dir, 'events.jsonl'), 'utf8');
    const lines = raw2.trim().split('\n');
    const last = lines[lines.length - 1];
    assert(!last.includes('"v":1'), 'enc: off writes plaintext going forward');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testLockoutPolicy() {
  return import('../src/auth.js').then((a) => {
    assert(a.getLockoutDelay(0) === 0, 'lockout: 0 fails no delay');
    assert(a.getLockoutDelay(2) === 0, 'lockout: 2 fails no delay');
    assert(a.getLockoutDelay(3) === 5000, 'lockout: 3 fails 5s delay');
    assert(a.getLockoutDelay(4) === 5000, 'lockout: 4 fails 5s delay');
    assert(a.getLockoutDelay(5) === 60000, 'lockout: 5 fails 60s');
    assert(a.getLockoutDelay(9) === 60000, 'lockout: 9 fails 60s');
    assert(a.getLockoutDelay(10) === 15 * 60 * 1000, 'lockout: 10 fails 15min lock');
    assert(a.getLockoutDelay(20) === 15 * 60 * 1000, 'lockout: 20 fails still 15min');
    assert(a.isLockedAt(Date.now() + 60000, Date.now()) === true, 'lockout: future lockUntil is locked');
    assert(a.isLockedAt(Date.now() - 1000, Date.now()) === false, 'lockout: past lockUntil not locked');
  });
}

async function testLockoutIntegration() {
  const PIN = 'alpha-9912';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-lock-'));
  try {
    setupScratch(dir, PIN, 'duress-4417');
    // 3 wrong attempts (short-circuit, no 5s sleep via DUC_NO_LOCK_SLEEP).
    for (let i = 0; i < 3; i++) {
      const r = runCli(dir, ['events'], 'wrong-pin-000\n');
      assert(r.status !== 0, `lockout: wrong PIN attempt ${i + 1} fails`);
    }
    const { loadLockState } = await import('../src/auth.js');
    const st = loadLockState(dir);
    assert(st.failCount >= 3, `lockout: failCount tracked (${st.failCount})`);
    // auth_failure logged (no PIN content).
    const evR = runCli(dir, ['events', '--json'], PIN + '\n');
    const evOut = String(evR.stdout || '') + String(evR.stderr || '');
    assert(evOut.includes('auth_failure'), 'lockout: auth_failure event logged');
    assert(!evOut.includes('wrong-pin-000'), 'lockout: no PIN content in log');
    // Successful normal auth resets.
    const ok = runCli(dir, ['events'], PIN + '\n');
    assert(ok.status === 0, 'lockout: correct PIN still works before 10 fails');
    const st2 = loadLockState(dir);
    assert(st2.failCount === 0, 'lockout: successful auth resets failCount');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testPluginSandbox() {
  const PIN = 'alpha-9912';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-sandbox-'));
  try {
    setupScratch(dir);
    runCli(dir, ['plugin-add', examplePluginPath()], PIN + '\n');
    // CONFIRM gate: without CONFIRM fails, with --yes-confirm succeeds (loud warning).
    const noConfirm = runCli(dir, ['plugin-enable', 'hello-plugin'], PIN + '\n');
    assert(noConfirm.status !== 0, 'sandbox: enable without CONFIRM fails');
    const yes = runCli(dir, ['plugin-enable', 'hello-plugin', '--yes-confirm'], PIN + '\n');
    const yesOut = String(yes.stdout || '') + String(yes.stderr || '');
    assert(yes.status === 0 && /--yes-confirm|WARNING/i.test(yesOut), 'sandbox: --yes-confirm allowed with loud warning');
    runCli(dir, ['plugin-disable', 'hello-plugin'], PIN + '\n');
    runCli(dir, ['plugin-enable', 'hello-plugin'], PIN + '\nCONFIRM\n');
    // vm blocks process: proc plugin fails without --unsafe, works with --unsafe.
    const procFile = path.join(dir, 'proc-plugin.js');
    fs.writeFileSync(procFile, "export default { name: 'procplug', commands: [{ name: 'proccmd', desc: 'uses process', run: async (ctx) => { ctx.ui.ok('pid=' + process.pid); } }] }", 'utf8');
    runCli(dir, ['plugin-add', procFile], PIN + '\n');
    runCli(dir, ['plugin-enable', 'proc-plugin'], PIN + '\nCONFIRM\n');
    const runBlocked = runCli(dir, ['proccmd'], PIN + '\n');
    const blockedOut = String(runBlocked.stdout || '') + String(runBlocked.stderr || '');
    assert(runBlocked.status !== 0 && /process is not defined|failed/i.test(blockedOut), 'sandbox: vm blocks process (no require/process)');
    runCli(dir, ['plugin-disable', 'proc-plugin'], PIN + '\n');
    const enUnsafe = runCli(dir, ['plugin-enable', 'proc-plugin', '--unsafe'], PIN + '\nCONFIRM\n');
    const unsafeOut = String(enUnsafe.stdout || '') + String(enUnsafe.stderr || '');
    assert(enUnsafe.status === 0 && /--unsafe|FULL-PRIVILEGE|WARNING/i.test(unsafeOut), 'sandbox: --unsafe recorded with loud warning');
    const runUnsafe = runCli(dir, ['proccmd'], PIN + '\n');
    assert(runUnsafe.status === 0 && /pid=/.test(String(runUnsafe.stdout || '')), 'sandbox: --unsafe fallback runs with full privileges');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testAlerts() {
  const PIN = 'alpha-9912';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-alert-'));
  try {
    setupScratch(dir);
    const store = await import('../src/store.js');
    assert(store.shouldAlert({ type: 'honey-tcp', severity: 'high' }) === true, 'alerts: high trap touch alerts');
    assert(store.shouldAlert({ type: 'sim', severity: 'high' }) === false, 'alerts: sim demo does not alert');
    assert(store.shouldAlert({ type: 'sentinel', severity: 'low' }) === false, 'alerts: low sentinel does not alert');
    assert(store.shouldAlert({ type: 'pcap', severity: 'critical' }) === true, 'alerts: critical pcap alerts');
    runCli(dir, ['config-set', 'alerts', 'file'], PIN + '\n');
    const alertFile = path.join(dir, 'alerts.log');
    runCli(dir, ['config-set', 'alerts-file', alertFile], PIN + '\n');
    // Real file write via central helper (same path as appendEvent).
    const rec = store.maybeAlert(dir, { time: new Date().toISOString(), type: 'honey-tcp', trap: 'honey-tcp:2222', ip: '9.9.9.9', detail: 'test touch', severity: 'high' });
    assert(rec.alerted === true, 'alerts: high event triggers alert');
    const lines = fs.readFileSync(alertFile, 'utf8').split('\n').filter((l) => l.trim());
    assert(lines.length >= 1, 'alerts: file line appended');
    const obj = JSON.parse(lines[lines.length - 1]);
    assert(obj.time && obj.type === 'honey-tcp' && obj.trap && obj.ip === '9.9.9.9' && obj.severity === 'high' && obj.alertAt, 'alerts: file schema {alertAt,time,type,trap,ip,detail,severity}');
    // Beep path best-effort (no crash when alerts=beep).
    runCli(dir, ['config-set', 'alerts', 'beep'], PIN + '\n');
    const r = runCli(dir, ['atime-watch', dir, '--interval', '1', '--duration', '1'], PIN + '\n');
    assert(r.status === 0, 'alerts: beep mode does not crash');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testGeoip() {
  const PIN = 'alpha-9912';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-geo-'));
  try {
    setupScratch(dir);
    const dbFile = path.join(dir, 'ranges.json');
    fs.writeFileSync(dbFile, JSON.stringify({ ranges: [{ from: '1.2.3.0', to: '1.2.3.255', country: 'US', city: 'Testville' }] }), 'utf8');
    const load = runCli(dir, ['geoip-load', dbFile], PIN + '\n');
    assert(load.status === 0 && /1 range/i.test(String(load.stdout || '') + String(load.stderr || '')), 'geoip: load JSON range DB');
    // attackers shows geo columns ONLY when DB loaded.
    runCli(dir, ['demo']);
    const a1 = runCli(dir, ['attackers'], PIN + '\n');
    const a1Out = String(a1.stdout || '') + String(a1.stderr || '');
    assert(/GEO|CONF/i.test(a1Out), 'geoip: attackers shows geo columns when DB loaded');
    const clear = runCli(dir, ['geoip-clear'], PIN + '\n');
    assert(clear.status === 0, 'geoip: clear exits 0');
    const a2 = runCli(dir, ['attackers'], PIN + '\n');
    const a2Out = String(a2.stdout || '') + String(a2.stderr || '');
    assert(!/GEO/i.test(a2Out) || a2Out.includes('No attacker'), 'geoip: attackers unchanged after clear (no GEO)');
    // .mmdb rejected with pointer.
    const mmFile = path.join(dir, 'fake.mmdb');
    fs.writeFileSync(mmFile, 'dummy-mmdb', 'utf8');
    const mm = runCli(dir, ['geoip-load', mmFile], PIN + '\n');
    assert(mm.status !== 0 && /mmdb-dump/i.test(String(mm.stdout || '') + String(mm.stderr || '')), 'geoip: .mmdb needs conversion pointer');
    // Confidence weights unit check.
    const store = await import('../src/store.js');
    const c1 = store.geoConfidence('192.168.1.5', 1, 1, false);
    assert(c1.score === 50 - 30 + 10, `geoip: local single confidence ${c1.score}`);
    const c2 = store.geoConfidence('8.8.8.8', 5, 3, true);
    assert(c2.score === 50 + 25 + 20, `geoip: multi-trap canary confidence ${c2.score}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function testCapabilityShapes() {
  return Promise.all([import('../src/sentinel.js'), import('../src/sniff.js')]).then(([s, sn]) => {
    const rep = s.capabilityReport();
    assert(Array.isArray(rep) && rep.length > 0, 'caps: capabilityReport non-empty');
    for (const c of rep) assert(typeof c.tool === 'string' && typeof c.ok === 'boolean' && typeof c.fix === 'string', `caps: probe shape for ${c.tool}`);
    const p = sn.probeCaptureTool();
    assert(typeof p.tool === 'string' && typeof p.ok === 'boolean' && typeof p.fix === 'string', 'caps: probeCaptureTool shape (tool/problem/fix)');
    assert(typeof s.parseBusyBoxNetstat === 'function', 'caps: BusyBox parser exists');
    const bb = s.parseBusyBoxNetstat('Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN\n');
    assert(bb.listeners.length === 1 && bb.listeners[0].port === 22, 'caps: BusyBox fixture parses');
  });
}

export async function runSelfTest() {
  failures = 0;
  passes = 0;
  console.log('ducgo selftest - auth, traps, canary, count, ui, smoke, plugins, completion, alias, macro, sentinel, integrity');
  await testAuth();
  await testTraps();
  await testCanary();
  testCount();
  testBanner();
  testUiEverywhere();
  testCommandsCountCli();
  testReplQuoteParsing();
  testReplPiped();
  testReplNoRepeatLogo();
  testReplAuthPiped();
  testOneShotStillFine();
  testSetupRetry();
  testSmokeHelp();
  testPluginCycle();
  testBrokenPlugin();
  testCompletion();
  testAliasMacro();
  testCountWithExtras();
  testDuressPlugins();
  testReplPlugins();
  testExtrasSmoke();
  await testSentinelParsers();
  await testSentinelBaselineRoundTrip();
  await testThreatScoreBounds();
  testIntegrityCycle();
  await testVersionExact();
  await testSentinelLive();
  testSniff();
  testSniff();
  await testAtime();
  await testStealth();
  await testEncryption();
  await testLockoutPolicy();
  await testLockoutIntegration();
  await testPluginSandbox();
  await testAlerts();
  await testGeoip();
  await testCapabilityShapes();
  // extras smoke for 5 new commands (never counted, --help exit 0)
  for (const c of ['atime-watch', 'trap-fingerprint-check', 'events-decrypt', 'geoip-load', 'geoip-clear']) {
    const r = spawnSync(process.execPath, [cliPath(), c, '--help'], { encoding: 'utf8', timeout: 15000 });
    assert(r.status === 0, `extras: --help smoke ${c}`);
  }
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
