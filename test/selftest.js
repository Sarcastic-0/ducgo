// MirageNet v2 selftest — stdlib only.
// Run: node test/selftest.js  (also: "npm test", "mirage selftest").
// Prints PASS lines; exits non-zero on any failure.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import * as net from 'node:net';
import { fileURLToPath } from 'node:url';
import { setupPins, verifyPin } from '../src/auth.js';
import { startHoneyTcp, startHoneyHttp, getServerPort, watchDirs, deployCanaries, closeServer } from '../src/traps.js';

let failures = 0;
function pass(label) {
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

// (1) auth store tests
async function testAuth() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mirage-auth-'));
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

// (2) trap tests on ephemeral ports
async function testTraps() {
  // --- honey HTTP ---
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

  // --- honey TCP ---
  const tcpEvents = [];
  const tcpSrv = await startHoneyTcp(0, (ev) => tcpEvents.push(ev), { host: '127.0.0.1' });
  const tport = getServerPort(tcpSrv);
  assert(tport > 0, 'trap: honey TCP binds ephemeral port');

  await new Promise((resolve, reject) => {
    const s = net.connect(tport, '127.0.0.1', () => s.write('HELLO-SELFTEST'));
    s.on('data', () => {});
    s.on('error', reject);
    setTimeout(() => {
      try {
        s.destroy();
      } catch {
        /* ignore */
      }
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

// (3) canary test — deploy to temp dir, modify file, watcher fires
async function testCanary() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mirage-canary-'));
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
    await sleep(400); // let the watcher attach
    fs.appendFileSync(path.join(dir, 'aws-keys.txt'), '\n# touched by selftest\n');
    const ok = await waitFor(() => fired.some((e) => e.type === 'canary'), 5000);
    assert(ok, 'canary: watcher fires on modify');
    for (const w of watchers) {
      try {
        w.close();
      } catch {
        /* ignore */
      }
    }
    // Let in-flight Windows watch events settle before removing the dir:
    // deleting a still-watched directory can crash libuv (fs-event.c).
    await sleep(600);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export async function runSelfTest() {
  failures = 0;
  console.log('MirageNet selftest — auth, traps, canary');
  await testAuth();
  await testTraps();
  await testCanary();
  if (failures === 0) {
    console.log('\nSELFTEST PASS — all checks passed');
  } else {
    console.error(`\nSELFTEST FAIL — ${failures} check(s) failed`);
  }
  return failures === 0;
}

const invokedAsMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (invokedAsMain) {
  const ok = await runSelfTest();
  process.exit(ok ? 0 : 1);
}
