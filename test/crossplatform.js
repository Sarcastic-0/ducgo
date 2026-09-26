// ducgo v3.0.4 cross-platform tests - stdlib only.
// Run: node test/crossplatform.js  (existing suite test/selftest.js is untouched).
// Scratch MIRAGENET_DIR only - real data is never touched.
// Covers: platform.js units (injected os-platform strings / runners - the
// global os module is NEVER patched), Linux ss / ip-neigh / nmcli / iwlist
// fixtures, Darwin arp -a (BSD) / airport -s fixtures, tcpdump `-n -l -v`
// stdout (incl. an `A?` DNS line) through the shared parser + analyzer
// reuse (incl. a port-scan built from tcpdump lines), POSIX collector
// guidance shapes, and the 92-command contract + help smoke.
// Prints PASS lines; exits non-zero on any failure.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { platform, isAdmin, hostsPath, dataDir, hasCmd } from '../src/platform.js';
import * as sentinel from '../src/sentinel.js';
import * as sniff from '../src/sniff.js';
import { COMMANDS } from '../src/cli.js';

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
function cliPath() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.js');
}

// ---------- fixtures ----------
const SS_SAMPLE = [
  'Netid State      Recv-Q Send-Q Local Address:Port  Peer Address:Port Process',
  'tcp   LISTEN     0      128    0.0.0.0:22           0.0.0.0:*      users:(("sshd",pid=1234,fd=3))',
  'tcp   ESTAB      0      0      192.168.1.5:54321    93.184.216.34:443 users:(("chrome",pid=3333,fd=9))',
  'udp   UNCONN     0      0      0.0.0.0:5353         0.0.0.0:*      users:(("avahi-daemon",pid=4444,fd=12))',
].join('\n');

const IP_NEIGH_SAMPLE = [
  '192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE',
  '192.168.1.10 dev eth0 lladdr 11:22:33:44:55:66 STALE',
  '192.168.1.99 dev eth0 FAILED',
].join('\n');

const NMCLI_SAMPLE = [
  'HomeNet:90:WPA2:AA:BB:CC:DD:EE:FF',
  'HomeNet:75:WPA2:11:22:33:44:55:66',
  'CoffeeShop:60::DE:AD:BE:EF:00:01',
  'HomeNet:80::DE:AD:BE:EF:00:02',
  'EvilTwin:99::AA:AA:AA:AA:AA:AA',
].join('\n');

const IWLIST_SAMPLE = [
  'wlan0     Scan completed :',
  '          Cell 01 - Address: AA:BB:CC:DD:EE:FF',
  '                    ESSID:"HomeNet"',
  '                    Protocol:IEEE 802.11bgn',
  '                    Mode:Master',
  '                    Frequency:2.437 GHz (Channel 6)',
  '                    Quality=70/70  Signal level=-40 dBm',
  '                    Encryption key:on',
  '                    IE: WPA Version 1',
  '          Cell 02 - Address: 11:22:33:44:55:66',
  '                    ESSID:"OpenNet"',
  '                    Encryption key:off',
].join('\n');

const DARWIN_ARP_SAMPLE = [
  '? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]',
  '? (192.168.1.10) at 11:22:33:44:55:66 on en0 ifscope [ethernet]',
  '? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]',
  '? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]',
  '? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]',
].join('\n');

const AIRPORT_SAMPLE = [
  'SSID BSSID RSSI CHANNEL HT CC SECURITY (auth/privacy)',
  'HomeNet aa:bb:cc:dd:ee:ff -60 6 Y US WPA2(PSK/AES/AES)',
  'HomeNet 11:22:33:44:55:66 -70 6 Y US WPA2(PSK/AES/AES)',
  'My Home Net 22:33:44:55:66:77 -65 11 N US WPA2(PSK/AES/AES)',
  'Cafe de Flore aa:aa:aa:aa:aa:aa -80 1 Y US NONE',
].join('\n');

const TCPDUMP_CLEAN = [
  '12:00:01.123456 IP 192.168.1.5.5001 > 93.184.216.34.443: Flags [P.], seq 1:100, ack 1, win 502, length 99',
  '12:00:01.223456 IP 93.184.216.34.443 > 192.168.1.5.5001: Flags [.], ack 100, win 501, length 0',
  '12:00:02.000000 IP 192.168.1.5.53275 > 8.8.8.8.53: 12345+ A? example.com. (29)',
  '12:00:02.100000 IP 192.168.1.5.62380 > 8.8.8.8.443: UDP, length 103',
  '12:00:03.000000 ARP, Request who-has 192.168.1.1 tell 192.168.1.5, length 28',
].join('\n');

function tcpdumpScanLines() {
  const out = [];
  for (let i = 0; i < 16; i++) {
    out.push(`12:01:00.${String(100000 + i).slice(1)} IP 10.9.9.9.${40000 + i} > 192.168.1.5.${1000 + i}: Flags [S], seq 0, win 64240, length 0`);
  }
  return out.join('\n');
}

// ---------- tests ----------
function testPlatformUnits() {
  assert(platform('win32') === 'windows', 'platform: win32 -> windows');
  assert(platform('Windows') === 'windows', 'platform: Windows -> windows');
  assert(platform('linux') === 'linux', 'platform: linux -> linux');
  assert(platform('darwin') === 'darwin', 'platform: darwin -> darwin');
  assert(platform('freebsd') === 'linux', 'platform: other posix -> linux backends');
  assert(hostsPath('linux') === '/etc/hosts', 'platform: linux hosts path');
  assert(hostsPath('darwin') === '/etc/hosts', 'platform: darwin hosts path');
  const wh = hostsPath('windows');
  assert(wh.endsWith('hosts') && /etc/i.test(wh), 'platform: windows hosts path', wh);
  assert(String(dataDir()).endsWith('.miragenet'), 'platform: dataDir ends with .miragenet', dataDir());
  assert(hasCmd('node') === true, 'platform: hasCmd finds node on PATH');
  assert(hasCmd('definitely-not-a-real-cmd-xyz-123') === false, 'platform: hasCmd false for missing tool');
  assert(hasCmd('') === false, 'platform: hasCmd false for empty');
  assert(hasCmd('a;b') === false, 'platform: hasCmd rejects metacharacters');
  assert(typeof isAdmin() === 'boolean', 'platform: isAdmin returns boolean');
  const hi = (cmd, args) => ({ status: 0, stdout: 'GROUP INFORMATION\nMandatory Label\\High Mandatory Level  Label  S-1-16-12288' });
  assert(isAdmin('windows', hi) === true, 'platform: windows admin detected via SID (injected runner)');
  assert(isAdmin('windows', () => ({ status: 0, stdout: 'Medium Mandatory Level' })) === false, 'platform: windows non-admin (injected runner)');
  assert(isAdmin('windows', () => ({ status: 1, stdout: '' })) === false, 'platform: windows runner failure -> false');
  assert(isAdmin('linux', () => ({ status: 0, stdout: '0\n' })) === true, 'platform: posix uid 0 is admin (injected runner)');
  assert(isAdmin('linux', () => ({ status: 0, stdout: '1000\n' })) === false, 'platform: posix uid 1000 not admin (injected runner)');
  assert(isAdmin('darwin', () => ({ status: 0, stdout: '0' })) === true, 'platform: darwin uid 0 is admin (injected runner)');
}

function testLinuxParsers() {
  const p = sentinel.parseSs(SS_SAMPLE);
  assert(p.listeners.length === 2, `xplat: ss fixture 2 listeners (got ${p.listeners.length})`);
  assert(p.listeners.some((l) => l.port === 22 && l.pid === 1234), 'xplat: ss listener :22 with pid');
  assert(p.listeners.some((l) => l.proto === 'UDP' && l.port === 5353), 'xplat: ss UDP listener parsed');
  assert(p.conns.length === 1 && p.conns[0].remoteIp === '93.184.216.34' && p.conns[0].pid === 3333, 'xplat: ss established conn with remote IP + pid');
  assert(p.conns[0].state === 'ESTABLISHED', 'xplat: ss ESTAB mapped to ESTABLISHED');

  const neigh = sentinel.parseIpNeigh(IP_NEIGH_SAMPLE);
  assert(neigh.length === 2, `xplat: ip neigh 2 entries, FAILED skipped (got ${neigh.length})`);
  assert(neigh[0].iface === 'eth0' && neigh[0].mac === 'aa:bb:cc:dd:ee:ff', 'xplat: ip neigh mac/iface');
  const base = {};
  for (const e of neigh) base[e.ip] = e.mac;
  const mutated = [
    { ip: '192.168.1.1', mac: 'aa:bb:cc:dd:ee:00' },
    { ip: '192.168.1.10', mac: '11:22:33:44:55:66' },
    { ip: '192.168.1.200', mac: '00:11:22:33:44:55' },
  ];
  const d = sentinel.diffArp(base, mutated);
  assert(d.changed.length === 1 && d.changed[0].ip === '192.168.1.1', 'xplat: analyzer reuse - ip-neigh MAC change flagged');
  assert(d.added.length === 1 && d.added[0].ip === '192.168.1.200', 'xplat: analyzer reuse - ip-neigh new device flagged');

  const wifi = sentinel.parseNmcli(NMCLI_SAMPLE);
  assert(wifi.length === 3, `xplat: nmcli 3 SSIDs grouped (got ${wifi.length})`);
  const home = wifi.find((n) => n.ssid === 'HomeNet');
  assert(!!home && home.bssids.length === 3 && home.auth === 'WPA2', 'xplat: nmcli HomeNet grouped 3 BSSIDs, WPA2 kept');
  const cafe = wifi.find((n) => n.ssid === 'CoffeeShop');
  assert(!!cafe && cafe.auth === 'Open', 'xplat: nmcli empty SECURITY mapped to Open');
  const wifiBase = [{ ssid: 'HomeNet', auth: 'WPA2', encryption: '', bssids: [{ bssid: 'aa:bb:cc:dd:ee:ff', signal: '90%', radio: '', channel: '' }] },
    { ssid: 'EvilTwin', auth: 'WPA2-Personal', encryption: '', bssids: [{ bssid: '00:00:00:00:00:01', signal: '80%', radio: '', channel: '' }] }];
  const twins = sentinel.detectEvilTwin(wifiBase, wifi);
  assert(twins.some((t) => t.kind === 'new-bssid'), 'xplat: analyzer reuse - nmcli new BSSIDs flagged');
  assert(twins.some((t) => t.kind === 'open-twin' && t.ssid === 'EvilTwin'), 'xplat: analyzer reuse - nmcli open twin flagged');

  const iw = sentinel.parseIwlist(IWLIST_SAMPLE);
  assert(iw.length === 2, `xplat: iwlist 2 networks (got ${iw.length})`);
  const iwh = iw.find((n) => n.ssid === 'HomeNet');
  assert(!!iwh && iwh.bssids[0].channel === '6' && /WPA/.test(iwh.auth), 'xplat: iwlist channel + WPA auth', JSON.stringify(iwh));
  const iwo = iw.find((n) => n.ssid === 'OpenNet');
  assert(!!iwo && iwo.auth === 'Open', 'xplat: iwlist open network');
}

function testDarwinParsers() {
  const arp = sentinel.parseArpBsd(DARWIN_ARP_SAMPLE);
  assert(arp.length === 4, `xplat: darwin arp 4 entries, incomplete skipped (got ${arp.length})`);
  assert(arp.every((e) => e.iface === 'en0'), 'xplat: darwin arp iface');
  assert(arp.find((e) => e.ip === '224.0.0.251').type === 'permanent', 'xplat: darwin arp permanent type');
  const base = {};
  for (const e of arp) base[e.ip] = e.mac;
  const d = sentinel.diffArp(base, [
    { ip: '192.168.1.1', mac: 'aa:bb:cc:dd:ee:00' },
    ...arp.filter((e) => e.ip !== '192.168.1.1'),
    { ip: '192.168.1.200', mac: '00:11:22:33:44:55' },
  ]);
  assert(d.changed.length === 1 && d.added.length === 1, 'xplat: analyzer reuse - BSD arp change + new flagged');

  const wifi = sentinel.parseAirport(AIRPORT_SAMPLE);
  assert(wifi.length === 3, `xplat: airport 3 SSIDs (got ${wifi.length})`);
  const home = wifi.find((n) => n.ssid === 'HomeNet');
  assert(!!home && home.bssids.length === 2, 'xplat: airport HomeNet 2 BSSIDs');
  assert(wifi.some((n) => n.ssid === 'My Home Net' && n.bssids[0].channel === '11'), 'xplat: airport SSID with spaces');
  const airBase = [{ ssid: 'HomeNet', auth: 'WPA2(PSK/AES/AES)', encryption: '', bssids: [{ bssid: 'aa:bb:cc:dd:ee:ff', signal: '-60 dBm', radio: '', channel: '6' }] }];
  const twins = sentinel.detectEvilTwin(airBase, wifi);
  assert(twins.some((t) => t.kind === 'new-bssid' && t.ssid === 'HomeNet'), 'xplat: analyzer reuse - airport new BSSID flagged');
}

function testTcpdumpParser() {
  const p = sniff.parseEtlText(TCPDUMP_CLEAN);
  assert(p.packets === 3, `xplat: tcpdump clean 3 packets (got ${p.packets})`);
  assert(p.tcp === 2 && p.udp === 1, `xplat: tcpdump tcp/udp split (got ${p.tcp}/${p.udp})`);
  assert(p.flows.size === 3, `xplat: tcpdump 3 flows (got ${p.flows.size})`);
  assert(p.dns.has('example.com.'), 'xplat: tcpdump DNS A? line captured');
  assert(p.arpReq.has('192.168.1.1'), 'xplat: tcpdump ARP who-has parsed');
  const a0 = sniff.analyze(p);
  assert(a0.anomalies.length === 0, 'xplat: tcpdump clean traffic, no anomalies', JSON.stringify(a0.anomalies).slice(0, 300));

  const via = sniff.parseTcpdumpText(TCPDUMP_CLEAN);
  assert(via.packets === p.packets && via.tcp === p.tcp, 'xplat: parseTcpdumpText shares the parser');

  const scan = sniff.parseEtlText(tcpdumpScanLines());
  const aScan = sniff.analyze(scan);
  assert(aScan.anomalies.some((x) => x.severity === 'high' && /port scan/.test(x.title)), 'xplat: analyzer reuse - port scan via tcpdump lines flagged high');
}

function testCollectorGuidance() {
  // POSIX branches execute for real here; missing tools must yield clean
  // guidance shapes, never throws.
  const lin = sentinel.getNetstatSnapshot('linux');
  assert(Array.isArray(lin.listeners) && Array.isArray(lin.conns), 'xplat: linux netstat branch keeps shape');
  if (!lin.ok) assert(/not available on linux/.test(lin.error), 'xplat: linux netstat guidance when tools missing', lin.error);

  const dar = sentinel.getNetstatSnapshot('darwin');
  assert(Array.isArray(dar.listeners) && Array.isArray(dar.conns), 'xplat: darwin netstat branch keeps shape');

  const atl = sentinel.getArpTable('linux');
  assert(Array.isArray(atl.entries), 'xplat: linux arp branch keeps shape');
  if (!atl.ok) assert(/not available on linux/.test(atl.error), 'xplat: linux arp guidance when tools missing', atl.error);

  const wl = sentinel.getWifiNetworks('linux');
  assert(Array.isArray(wl.networks), 'xplat: linux wifi branch keeps shape');
  if (!wl.ok) assert(/not available on linux/.test(wl.error), 'xplat: linux wifi guidance when tools missing', wl.error);

  const wd = sentinel.getWifiNetworks('darwin');
  assert(Array.isArray(wd.networks), 'xplat: darwin wifi branch keeps shape');
  if (!wd.ok) assert(/not available on darwin/.test(wd.error), 'xplat: darwin wifi guidance when airport missing', wd.error);

  const tl = sentinel.getTasklistMap('linux');
  assert(tl.ok === false && tl.map instanceof Map && /not available on linux/.test(tl.error), 'xplat: linux tasklist guidance (PIDs only)');

  const native = sentinel.getNetstatSnapshot();
  assert(typeof native.ok === 'boolean' && Array.isArray(native.listeners), 'xplat: native netstat snapshot keeps shape');

  const desc = sentinel.describeCollectors('darwin');
  assert(desc.length === 5 && desc.every((r) => r.length === 2), 'xplat: describeCollectors rows for doctor/sysinfo');
}

function testSniffBackends() {
  assert(typeof sniff.isAdmin() === 'boolean', 'xplat: sniff isAdmin boolean');
  const dst = sniff.driverStatus();
  assert(typeof dst.present === 'boolean' && typeof dst.admin === 'boolean' && typeof dst.detail === 'string', 'xplat: driverStatus shape (+platform/backend)');
  const be = sniff.captureBackend();
  assert(['pktmon', 'tcpdump', 'dumpcap'].includes(be.kind), 'xplat: captureBackend kind known', be.kind);
  assert(typeof be.available === 'boolean' && typeof be.installHint === 'string' && be.installHint.length > 0, 'xplat: captureBackend availability + hint');
  assert(sniff.captureBackend('linux').kind === 'tcpdump', 'xplat: linux backend is tcpdump');
  assert(/tcpdump/i.test(sniff.captureBackend('linux').installHint), 'xplat: linux hint names tcpdump');
  assert(sniff.captureBackend('darwin').kind === 'tcpdump', 'xplat: darwin backend is tcpdump');
  assert(sniff.captureBackend('windows').kind === 'pktmon', 'xplat: windows backend is pktmon');
  assert(sniff.findPacketExe('windows') === null, 'xplat: no POSIX finder on windows');
  const dl = sniff.driverStatus('linux');
  assert(typeof dl.present === 'boolean' && typeof dl.detail === 'string', 'xplat: linux driverStatus shape');
}

function testContractAndSmoke() {
  const saved = Object.prototype.hasOwnProperty.call(process.env, 'MIRAGENET_DIR') ? process.env.MIRAGENET_DIR : undefined;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ducgo-xplat-'));
  try {
    assert(COMMANDS.length === 92, `xplat: built-ins exactly 92 (got ${COMMANDS.length})`);
    const env = { ...process.env, MIRAGENET_DIR: dir };
    const c = spawnSync(process.execPath, [cliPath(), 'commands', '--count'], { encoding: 'utf8', timeout: 15000, env });
    assert(c.status === 0 && String(c.stdout || '').trim() === '92', 'xplat: commands --count prints exactly 92');
    for (const cmd of ['doctor', 'sysinfo', 'sniff-check']) {
      const r = spawnSync(process.execPath, [cliPath(), cmd], { encoding: 'utf8', timeout: 15000, env });
      const out = String(r.stdout || '') + String(r.stderr || '');
      assert(r.status === 0, `xplat: smoke ${cmd} exits 0`);
      assert(/windows|linux|darwin/i.test(out), `xplat: ${cmd} shows detected platform`);
    }
    const chk = spawnSync(process.execPath, [cliPath(), 'sniff-check'], { encoding: 'utf8', timeout: 15000, env });
    assert(/pktmon|tcpdump|dumpcap/i.test(String(chk.stdout || '')), 'xplat: sniff-check names a backend');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    if (saved === undefined) delete process.env.MIRAGENET_DIR;
    else process.env.MIRAGENET_DIR = saved;
    assert(process.env.MIRAGENET_DIR === saved || (saved === undefined && !('MIRAGENET_DIR' in process.env)), 'xplat: env restored after scratch runs');
  }
}

export async function runCrossPlatform() {
  failures = 0;
  passes = 0;
  console.log('ducgo cross-platform tests - platform units, linux/darwin fixtures, tcpdump parser, guidance, 92-contract');
  testPlatformUnits();
  testLinuxParsers();
  testDarwinParsers();
  testTcpdumpParser();
  testCollectorGuidance();
  testSniffBackends();
  testContractAndSmoke();
  console.log(`\n${passes} check(s) passed.`);
  if (failures === 0) {
    console.log('XPLAT PASS - all checks passed');
  } else {
    console.error(`XPLAT FAIL - ${failures} check(s) failed`);
  }
  return failures === 0;
}

const invokedAsMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (invokedAsMain) {
  const ok = await runCrossPlatform();
  process.exit(ok ? 0 : 1);
}
