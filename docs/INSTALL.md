# ducgo v3.0.4 - Install & platform notes (Windows / Linux / macOS)

Same 92 commands everywhere (+ 14 extras, never counted). Platform gaps
degrade with clean guidance (never crash). Zero runtime dependencies
(Node.js stdlib only). No new OS prerequisites for the production-grade
update (atime, stealth, log encryption, caps, geoip, lockout, sandbox,
alerts): everything uses inbox tools + stdlib (`node:vm`, `node:crypto`).
`mmdb-dump` is external and OPTIONAL (only if you convert .mmdb to JSON/CSV
for `geoip-load`).

## 1. Prerequisites per OS

### Windows
- Node.js LTS (18+). Check: `node --version`.
- No extra tools: sentinel uses inbox `netstat` / `arp` / `netsh` / `tasklist`;
  capture uses inbox `PktMon.exe` (Windows 10 1809+ / 11).
- Packet capture needs an **elevated (Administrator) terminal**.
  Parsing a saved capture needs none. `ducgo sniff-check` reports readiness.

### Linux
- Node.js 18+ (distro package or nodejs.org).
- Sentinel tables: `ss -tunp` needs **iproute2**
  (`sudo apt install iproute2` / `sudo dnf install iproute`).
  Fallback: legacy `netstat -tulnp` from **net-tools**.
- ARP: `ip neigh show` (iproute2), fallback `arp -a` (net-tools).
- Wi-Fi: `nmcli dev wifi` needs **network-manager**;
  fallback `iwlist <iface> scan` needs **wireless-tools** + a wireless adapter.
- Capture: **tcpdump** (`sudo apt install tcpdump` /
  `sudo dnf install tcpdump`) or **dumpcap** (`wireshark-cli`).
  Capture needs root - re-run with `sudo`.
  Only the default interface is captured; loopback-only traffic is out of
  scope (capture it manually with `tcpdump -i lo`).
- Process names are not mapped (PIDs shown only);
  map them externally with `ps -o pid,comm`.

### macOS
- Node.js 18+ (`brew install node`).
- `tcpdump` ships with the OS; capture still needs `sudo`.
- Sentinel: `netstat -anv -p tcp/udp` (no PID column - PIDs shown as 0,
  map with `lsof -i`), `arp -a` (BSD format), `airport -s` (system tool at
  `/System/Library/PrivateFrameworks/Apple80211.framework/.../airport`).

## 2. Run / link

No install step is required - running from the checkout is sufficient:

```sh
node src/cli.js --help
node src/cli.js version
node src/cli.js commands --count   # -> 92
```

Optional global link (puts `ducgo` on PATH):

```sh
npm link        # may need sudo on Linux/macOS if the global prefix is root-owned
ducgo version
npm unlink      # removes the link again
```

## 3. Data locations per OS

Default data dir is `~/.miragenet` on every OS:

| OS | Default data dir | Hosts file |
|---|---|---|
| Windows | `%USERPROFILE%\.miragenet` | `%SystemRoot%\System32\drivers\etc\hosts` |
| Linux | `~/.miragenet` | `/etc/hosts` |
| macOS | `~/.miragenet` | `/etc/hosts` (-> `/private/etc/hosts`) |

Set `MIRAGENET_DIR` to override (used by all tests so they never touch
real data). Store files: `auth.json`, `events.jsonl`, `config.json`,
`sentinel-baseline.json`, `integrity.json`, `captures.jsonl`.

## 4. Support matrix (honest: executed vs fixture-tested)

Executed live in this environment (Windows 11, admin terminal):

| Group | Windows (executed) |
|---|---|
| auth / engine / traps / canary / events / attackers / reports / config / system | full selftest green |
| sentinel (netstat/arp/netsh/tasklist/hosts/dns/loopback) | live baseline + check + listen + threat-score green |
| integrity | add/verify-tamper/refresh cycle green |
| sniff (pktmon capture + UTF-16 parse + analyzer) | real 4s capture green (admin) |

Fixture-tested only (no Linux/macOS host in this environment):

| Area | Coverage |
|---|---|
| `src/platform.js` | unit tests with injected `os.platform()` strings (no global patching), admin-shape checks with injected runners |
| Linux `ss -tunp` / `ip neigh` / `nmcli` / `iwlist` | sample-output fixtures through the new parsers + `diffArp` / `detectEvilTwin` reuse |
| macOS `arp -a` (BSD) / `airport -s` | sample-output fixtures through the new parsers + diff/evil-twin reuse |
| tcpdump `-n -l -v` stdout (incl. `A?` DNS line) | extended `parseEtlText` / `parseTcpdumpText` + shared `analyze()` reuse (incl. port-scan via tcpdump lines) |
| POSIX collector branches | executed for shape: missing tools return `{ ok: false, error: "not available on <os>: ..." }`, never throw |
| 92-command contract + `--help` smoke | `commands --count` == 92, `doctor` / `sysinfo` / `sniff-check` smoke |

Not executed here (needs a real host): live Linux/macOS capture
(`sudo` + tcpdump), live Linux/macOS collector output, `npm link` on
Linux/macOS. POSIX branches are covered by fixtures + guidance-shape
tests instead.
