# ducgo v3.0.4 - Deception Tripwire Mesh + Network Sentinel (CLI only)

A lightweight **passive deception (tripwire)** tool for individuals and small teams:
honey TCP ports, a honey HTTP admin panel, and canary files. Any touch of a trap
is logged as an event with the visitor's fingerprint. Includes duress-PIN mode
(fake all-clear message + silent alert) plus a read-only **network sentinel**
(baseline + diff of local tables) and **file-integrity** tripwires.

> 100% passive/defensive. Zero offensive traffic - the tool only listens on
> ports, serves a fake login page, watches files, and reads local OS tables
> (netstat/ss, arp/ip-neigh, netsh/nmcli/airport, tasklist) plus a loopback-only self-scan. It never
> probes remote hosts, never captures packets, and never attacks anything.

English only (output). CLI only. **Zero runtime dependencies** (Node.js standard
library only - hand-rolled args, minimal ANSI colors with `NO_COLOR` support).
Exit codes: `0` success, `1` error. No daemon/background mode - `start` runs
foreground only until `Ctrl+C`.

```
██████╗ ██╗   ██╗ ██████╗  ██████╗  ██████╗
██╔══██╗██║   ██║██╔════╝ ██╔════╝ ██╔═══██╗
██║  ██║██║   ██║██║  ███╗██║  ███╗██║   ██║
██║  ██║██║   ██║██║   ██║██║   ██║██║   ██║
██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝
╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝
No one can race me
ducgo v3.0.4
```

(The dim line above is the English tagline.)

## Install

Requires Node.js 18+. Same 92 commands on Windows, Linux, and macOS
(see `docs/INSTALL.md` for per-OS prerequisites).

```powershell
cd "C:\Users\LORD laptop\Documents\MirageNet"
node src/cli.js --help
```

The bin is `ducgo` (`./src/cli.js`, shebang kept). Running
`node src/cli.js` is sufficient; optionally `npm link` puts `ducgo` on
PATH (`npm unlink` removes it). Per-OS notes: Windows needs nothing beyond
Node (inbox `netstat`/`arp`/`netsh`/`tasklist`/`PktMon.exe`, admin terminal
for capture); Linux needs `iproute2` (`ss`/`ip`) + `tcpdump` + `sudo` for
capture; macOS ships `tcpdump` (still needs `sudo` for capture).
`ducgo doctor` / `ducgo sysinfo` / `ducgo sniff-check` show the detected
platform + backend on every OS.

Set `NO_COLOR=1` to disable ANSI colors (plain logo; tagline + version still shown).

## Data

Data dir is `~/.miragenet` on every OS (Windows: `%USERPROFILE%\.miragenet`;
Linux/macOS: `~/.miragenet`) holding `auth.json`, `events.jsonl`,
`config.json`, `sentinel-baseline.json`, `integrity.json`. Set `MIRAGENET_DIR` to override the data directory (used for
testing so you never touch the real store). Hosts file per OS:
Windows `%SystemRoot%\System32\drivers\etc\hosts`, Linux/macOS `/etc/hosts`.

## Quick start

```powershell
node src/cli.js setup
node src/cli.js deploy ./decoys
node src/cli.js start
node src/cli.js events
node src/cli.js attackers
```

`setup` asks for an access PIN and a SECOND, different duress PIN (used only
under coercion). Each entry is confirmed: on a mismatch it shows only the
lengths entered (never content) and retries up to 3 times instead of failing
immediately. Non-interactive setup for scripting:

```powershell
$env:DUC_PIN = "alpha-9912"; $env:DUC_DURESS = "duress-4417"
node src/cli.js setup
Remove-Item Env:\DUC_PIN, Env:\DUC_DURESS   # clear secrets from the session
```

With a scratch dir for safe experiments:

```powershell
$env:MIRAGENET_DIR = "$env:TEMP\ducgo-test"
"alpha-9912`nalpha-9912`nduress-4417`nduress-4417" | node src/cli.js setup
node src/cli.js demo
"alpha-9912" | node src/cli.js deploy "$env:TEMP\ducgo-test\decoys"
node src/cli.js commands --count   # -> 92
```

## Interactive shell

Running bare `ducgo` (no arguments) prints the banner once and enters a
persistent `ducgo> ` prompt. It stays open until `exit`, `quit`, or `q`,
a second `Ctrl+C` within 2 seconds, or EOF (exit code 0). Piped stdin works
too: lines are executed in order and the shell exits at EOF. Inside the
shell, `help`/`commands`/`about` print results only (no repeated logo) —
type `banner` anytime to show it again.

```powershell
node src/cli.js
# ducgo> version
# ducgo> commands --count   # -> 92
# ducgo> attacker-note 1.2.3.4 "suspicious login"
# ducgo> exit

"banner`nversion`ncommands --count`nquit`n" | node src/cli.js
```

Notes:

- Every line is parsed quote-aware (`"double"`, `'single'`, `\` escapes) and
  dispatched through the same handlers as one-shot mode, so behavior is
  identical - including PIN prompts for auth-gated commands (hidden input on
  a TTY; PIN answers never touch the history file) and the unchanged duress
  all-clear (`All clear - no threats detected.`, silent alert, exit 0).
- `start` blocks the prompt while the engine runs - that is expected. `Ctrl+C`
  stops the engine and returns to the `ducgo> ` prompt (it does not exit the
  shell). A first `Ctrl+C` at an idle prompt prints `(type exit to quit)`.
- Unknown commands print an error plus up to 5 suggestions (built-ins +
  enabled plugins + aliases + macros); per-line errors never kill the shell.
  Tab completion + `help <name>` cover plugin/alias/macro (origin/expansion
  shown); history persists at `<dataDir>\history` (capped at ~500 lines,
  best-effort).
- One-shot mode (`ducgo <command> [options]`) is unchanged. The registry
  stays exactly 92 built-ins; extras (plugin mgmt, completion, alias, macro,
  plugin commands) are never counted - see the `commands` footer line.

## 92 commands

`ducgo commands` prints the grouped list. `ducgo commands --count` prints `92`.
Every command supports `--help` (exits 0, no side effects).

### auth (7)

| Command | Description |
|---|---|
| `setup` | Set access PIN + duress PIN (interactive with retries, or DUC_PIN/DUC_DURESS env) |
| `login-test` | Verify a PIN without revealing which one |
| `change-pin` | Change the access PIN (needs current PIN) |
| `change-duress` | Change the duress PIN (needs current PIN) |
| `lock-status` | Show whether auth is set up (no PIN) |
| `auth-status` | Whoami-style auth state + data dir (no PIN) |
| `reset-all` | Delete auth (PIN + double `RESET` confirmation) |

```powershell
node src/cli.js setup
"alpha-9912" | node src/cli.js login-test
"alpha-9912" | node src/cli.js change-pin
```

### engine (4)

| Command | Description |
|---|---|
| `start [--ports P,...] [--http PORT]` | Unlock with PIN, run the trap mesh foreground until `Ctrl+C` (honey TCP on `0.0.0.0` + honey HTTP on `127.0.0.1` + canary watch) |
| `status` | Check which configured ports are listening |
| `ports-list` | List configured honey ports |
| `engine-check` | Check if configured ports are free to bind |

```powershell
"alpha-9912" | node src/cli.js start --ports 2222,2323 --http 18080
node src/cli.js status
```

Foreground only - there is no `start-bg`/daemon. `status` checks ports; stop with `Ctrl+C`.

### traps (9)

| Command | Description |
|---|---|
| `trap-list` | List honey TCP traps + enabled state |
| `trap-add <port>` | Add a honey TCP port (needs PIN) |
| `trap-remove <port>` | Remove a honey TCP port (needs PIN) |
| `trap-enable <port>` | Re-enable a disabled trap (needs PIN) |
| `trap-disable <port>` | Disable a trap without deleting it (needs PIN) |
| `http-show` | Print the fake admin panel preview |
| `http-config [--port N] [--title TEXT]` | Configure honey HTTP port/title (needs PIN) |
| `banner-set <port> <text>` | Set a custom banner label for a port (needs PIN) |
| `banner-show [port]` | Show banner for a port (or all) |

### canary (6)

| Command | Description |
|---|---|
| `deploy <dir>` | Drop 3 decoys (`aws-keys.txt`, `passwords.csv`, `wallet-seed.txt` with `MIRAGETOKEN-*`) + watch the dir (needs PIN) |
| `canary-list` | List watched dirs + decoy files present |
| `canary-verify` | Verify decoys still carry canary tokens (needs PIN) |
| `canary-refresh [dir]` | Regenerate/refresh decoy tokens (needs PIN) |
| `canary-remove <dir> [--delete]` | Unwatch a dir, optionally delete decoys (needs PIN) |
| `canary-show <file>` | Print the canary token of a file (needs PIN) |

### events (7)

| Command | Description |
|---|---|
| `events [--json] [--export out.csv]` | Show history (table/JSON/CSV export, needs PIN) |
| `events-tail [--lines N] [--follow]` | Last N events, optionally follow live (needs PIN) |
| `event-show <id>` | Show one event by id (needs PIN) |
| `events-clear` | Clear the log (PIN + type `CLEAR`) |
| `events-export <file> [--format csv\|json]` | Export to file (needs PIN) |
| `events-import <file>` | Import JSON/JSONL events (needs PIN) |
| `events-stats` | Counts by type/severity/trap (needs PIN) |

### attackers (5)

| Command | Description |
|---|---|
| `attackers` | Group touches by IP (needs PIN) |
| `attacker-show <ip>` | Timeline for one IP (needs PIN) |
| `attacker-note <ip> <text...>` | Attach a text note to an IP (needs PIN) |
| `attacker-list-notes [ip]` | List notes (needs PIN) |
| `top-attackers [--limit N]` | Top N IPs by touches (needs PIN) |

### reports (4)

| Command | Description |
|---|---|
| `report-daily` | Last-24h events, grouped (needs PIN) |
| `report-summary` | Totals, range, severity (needs PIN) |
| `report-top [--limit N]` | Top traps + top IPs (needs PIN) |
| `report-export <file>` | Markdown report to file (needs PIN) |

### config (8)

| Command | Description |
|---|---|
| `config-set <key> <value>` | Set `ports\|httpPort\|httpTitle\|watchDirs` (needs PIN) |
| `config-get <key>` | Get a key (needs PIN) |
| `config-list` | Full config table (needs PIN) |
| `config-reset` | Defaults (needs PIN) |
| `data-dir` | Print the data directory path |
| `data-size` | Print store file sizes |
| `config-export <file>` | Export `config.json` |
| `config-import <file>` | Import `config.json` (needs PIN) |

### system (20)

| Command | Description |
|---|---|
| `help [command]` | Banner + help (or one command's usage) |
| `banner` | Print the DUCGO banner |
| `version` | Print `ducgo v3.0.4` |
| `commands [--count]` | Grouped one-liners; `--count` prints `92` |
| `doctor` | Node/data-dir/auth/ports health checks |
| `selftest` | Built-in suite (same as `npm test`) |
| `demo` | One synthetic `DEMO` event (no PIN) |
| `about` | About + honest limits |
| `backup <file>` | Back up auth+config+events (needs PIN) |
| `restore <file>` | Restore backup (PIN + type `RESTORE`) |
| `wipe` | Factory reset (PIN + type `WIPE`) |
| `log-path` | Print `events.jsonl` path |
| `sysinfo` | Node/OS/platform info |
| `uptime` | Process uptime + store age |
| `tips` | Practical usage tips |
| `license` | License summary |
| `verify-install` | Bin/shebang/node/data-dir checks |
| `paths` | All store paths |
| `stats` | Global overview (needs PIN) |
| `support` | Scope + support info |

### sentinel (11)

Read-only network watch (stdlib only - `child_process` + `net` + `dns`,
no packet capture). Every spawned OS command is killed after 8s with a clean
error. Only the tool data dir is ever written (baselines + `sentinel` events).
All commands need the normal PIN (duress sees the all-clear only).

| Command | Description |
|---|---|
| `listen [--interval 10] [--duration 0]` | Live watch until `Ctrl+C` (0 = forever); diffs quick tables vs baseline, color alerts + logs `sentinel` events; first run auto-creates the baseline |
| `sentinel-baseline` | Save a full baseline (netstat + arp + wifi + hosts + dns + loopback scan) |
| `sentinel-check` | One-shot diff vs baseline + threat score (logs one `sentinel` event) |
| `sentinel-report` | Summary of recent `sentinel` events |
| `open-ports` | Self-scan common ports on `127.0.0.1` (short timeout) + `netstat` listeners |
| `conn-summary` | Established TCP grouped by remote IP:port + PID/process via `tasklist` |
| `arp-watch` | Parse `arp -a`; flag new IPs / changed MACs vs baseline (possible spoofing) |
| `wifi-scan` | Parse `netsh wlan show networks mode=bssid`; flag duplicate SSIDs / new BSSIDs (possible evil twin) + open twins |
| `hosts-verify` | Hash the hosts file vs stored baseline; alert on change |
| `dns-check` | Resolve a fixed list via stdlib lookup; flag changes vs baseline |
| `threat-score` | Score 0-100 from recent events with a transparent factor table |

```powershell
"alpha-9912" | node src/cli.js sentinel-baseline
"alpha-9912" | node src/cli.js sentinel-check
"alpha-9912" | node src/cli.js listen --interval 10 --duration 60
"alpha-9912" | node src/cli.js threat-score
```

Honest sentinel notes (read before trusting alerts):

- Per-OS backends (same commands, same output shapes): Windows
  `netstat -ano` + `tasklist` / `arp -a` / `netsh wlan`; Linux `ss -tunp`
  (fallback legacy `netstat`) / `ip neigh` (fallback `arp -a`) /
  `nmcli dev wifi` (fallback `iwlist scan`); macOS `netstat -anv -p tcp/udp`
  (no PID column - PIDs shown as 0) / `arp -a` (BSD format) / `airport -s`.
  Missing tools degrade to `not available on <os>: <what to install>` -
  never a crash. Full matrix: `docs/INSTALL.md`.
- Heuristics only, not proof. New listeners, ARP changes, new BSSIDs, DNS
  rotations, and hosts edits all have benign causes (updates, DHCP, mesh /
  repeaters, CDN rotation, VPNs). Confirm unknown MACs / BSSIDs against your
  router admin page before acting.
- No packet capture is used or claimed by the sentinel group. For real
  sniffing use the `sniff` group below (pktmon on Windows, tcpdump/dumpcap
  on Linux/macOS) or a companion such as Npcap / Wireshark alongside this tool.
- `open-ports` touches `127.0.0.1` only (loopback self-check). Nothing here
  probes remote hosts.
- `wifi-scan` needs a WLAN adapter; on other setups it reports
  cleanly and the parsers remain unit-tested with fixtures.
- First `listen` / `sentinel-check` run with no baseline auto-creates one and
  says so - re-run to get diffs.

### integrity (5)

File-integrity tripwires for arbitrary paths (sha256). All commands need the
normal PIN (duress sees the all-clear only).

| Command | Description |
|---|---|
| `integrity-add <file...>` | Start watching file(s) by hash |
| `integrity-list` | List watched files |
| `integrity-verify` | Report changed / missing (exits 1 on tamper) |
| `integrity-remove <file>` | Stop watching a file |
| `integrity-baseline-refresh` | Re-hash current files as the new baseline |

```powershell
"alpha-9912" | node src/cli.js integrity-add C:\important\notes.txt
"alpha-9912" | node src/cli.js integrity-verify
```

### sniff (6)

Real packet capture with per-OS backends: inbox Windows pktmon (no
third-party driver), Linux `tcpdump` or `dumpcap`, macOS system `tcpdump`.
Capture needs privilege - an **elevated (Administrator) terminal** on
Windows, `sudo`/root on Linux/macOS; parsing a saved capture needs none.
All commands need the normal PIN (duress sees the all-clear only). Captures are parsed locally (flows, DNS, ARP, HTTP auth)
and anomalies are logged as `pcap` events, so `events` and `threat-score`
see them too.

| Command | Description |
|---|---|
| `sniff-check` | Show pktmon/admin readiness (no PIN needed) |
| `sniff [--duration 30] [--pkt-size 0] [--keep]` | Capture N seconds, parse + flag anomalies |
| `sniff-live [--interval 15] [--duration 0]` | Repeat capture windows until Ctrl+C |
| `sniff-report` | Summary of the last capture |
| `sniff-top [--n 10]` | Top talker flows of the last capture |
| `sniff-dns [--n 20]` | DNS names of the last capture, suspicious flagged |

```powershell
node src/cli.js sniff-check
"alpha-9912" | node src/cli.js sniff --duration 15
"alpha-9912" | node src/cli.js sniff-report
```

Detection heuristics: port scans (one host, 15+ ports), SYN scans (10+
unanswered SYNs), sweeps (20+ IPs), heavy flows, DNS tunneling (30+
subdomains, over-long/high-entropy names, odd ports), ARP conflicts/storms,
and cleartext HTTP credentials (values never stored). Heuristics only, not
proof - benign causes exist (updates, CDN, VPNs). ETL/TXT (Windows) or pcap
(Linux/macOS) files are deleted after parsing unless `--keep`; summaries (no payloads) stay in
`captures.jsonl` (last 20). Linux/macOS parse `tcpdump -n -l -v` text
in-memory (no intermediate text file); only the default interface is
captured, loopback-only traffic is out of scope.

## Duress PIN

Entering the duress PIN at **any** PIN prompt prints exactly:

```text
All clear - no threats detected.
```

...appends a silent `{type:"duress", ...}` event to `events.jsonl`, and exits 0.
The screen never reveals that duress mode was triggered.

## Security model

- Local PIN auth: PBKDF2-SHA256, 200k iterations, per-PIN 16-byte random salt,
  `auth.json` under the data dir. Nothing leaves the machine. Timing-safe
  comparison; duress hash stored separately.
- PIN entry uses stdin raw mode (no echo). When stdin is piped, lines are read
  sequentially so scripted flows still work.
- Honey HTTP binds `127.0.0.1` only (local review); honey TCP binds `0.0.0.0`
  **by design** so LAN touches trip the wire. Usernames from fake logins are
  logged (capped at 120 chars); passwords are never stored anywhere.
- Sentinel is read-only: OS table reads + loopback self-scan only. Baselines
  (`sentinel-baseline.json`, `integrity.json`) and `sentinel` events live under
  the data dir. System state is never modified.
- No dependencies = minimal supply-chain surface. No network calls except the
  local listeners themselves, loopback self-scan, and stdlib DNS lookups for
  `dns-check`.

## Honest limits

- `fs.watch` reports **modify/rename/delete** - it does **NOT** detect silent
  reads (opening a canary in Notepad without saving trips nothing). This is an
  OS limitation, not a bug.
- Honey TCP ports are **LAN-visible by design**; anyone port-scanning you will
  see open ports. That is the point of a tripwire, but don't run this on
  networks where unexplained open ports violate policy.
- Default ports (2222/2323/8080) may already be in use - the mesh logs a
  `system` event per unavailable port and keeps the rest running.
- No encryption-at-rest beyond OS file permissions for the event log; the log
  contains visitor IPs, banner bytes, and usernames (never passwords).
- The `attackers` table is naive IP grouping - no attribution, and
  spoofed/internal IPs mean little on their own.
- Duress mode hides the real view but cannot hide that the tool is installed.
- `demo` injects a synthetic event clearly tagged `DEMO` / type `sim`.
- Engine is foreground only (no daemon). `status`/`engine-check` inspect ports;
  stop with `Ctrl+C`.
- Sentinel `threat-score` is a 0-100 heuristic from local events with a shown
  factor table - not a verdict. ARP / evil-twin / DNS flags are heuristics;
  expect false positives (DHCP, repeaters, CDN rotation). No packet capture:
  pair with Npcap / Wireshark for real traffic review.

## Plugins (commands only)

Plugin dir is `<dataDir>\plugins`. A plugin = one `.js` file exporting
`{ name, version?, commands: [{ name, desc, usage?, run(ctx) }] }` where
`ctx = { ui, args, config, store, callBuiltIn(name,args), dataDir }`.

Limits: plugins may ONLY add commands. They may NOT hook the trap engine
or auth. Collisions with built-ins are skipped with a warning. Broken
plugins warn and are skipped - the tool continues.

Trust warning: `plugin-add <file>` copies the file, prints SHA-256,
DISABLED by default + warning. Only enable plugins you trust - they run
as your user with your privileges. Management (`plugin-add`,
`plugin-enable`, `plugin-disable`, `plugin-list`, `plugin-show`,
`plugin-remove`) requires the normal PIN; the duress PIN never reveals
the plugin list (all-clear + silent log, behaves as if no plugins exist).
Plugin commands also require the normal PIN to run (duress-safe).

Example (`examples/hello-plugin.js`, commands `hello`, `threat-tip`):

```powershell
"alpha-9912" | node src/cli.js plugin-add examples/hello-plugin.js
"alpha-9912" | node src/cli.js plugin-list
"alpha-9912" | node src/cli.js plugin-enable hello-plugin
"alpha-9912" | node src/cli.js hello
"alpha-9912" | node src/cli.js threat-tip
```

## Completion

```powershell
node src/cli.js completion powershell   # print PowerShell script + manual instructions
node src/cli.js completion bash         # print bash script + manual instructions
node src/cli.js completion --install    # install to PowerShell $PROFILE / ~/.bashrc (idempotent marked block)
node src/cli.js completion --uninstall  # remove the marked block
```

Hidden `__complete <prefix...>` (never counted/listed) feeds the scripts
with built-in (92) + enabled-plugin + alias + macro names.

## Aliases + Macros (never counted)

Stored in `config.json`. Management requires the normal PIN like other
config commands (duress sees nothing extra).

```powershell
"alpha-9912" | node src/cli.js alias set ll "events --json"
node src/cli.js ll
"alpha-9912" | node src/cli.js alias list
"alpha-9912" | node src/cli.js macro set daily "version; banner"
"alpha-9912" | node src/cli.js macro run daily
"alpha-9912" | node src/cli.js macro list
```

Aliases have a recursion guard (depth 10, cycle -> clean error).
Macros are `;`-separated: stop-on-first-error in one-shot mode, per-line
(continue) in REPL.

The 92 contract: `commands --count` stays exactly 92. Extras
(plugin commands, aliases, macros, plus 9 extra built-ins) appear only in
the footer line (`+ N plugin command(s), ...`) and are never counted.

## Project layout

```text
package.json        ESM ("type": "module"), bin { ducgo: ./src/cli.js }, no deps
src/cli.js          hand-rolled args, hidden PIN prompt, 92 built-ins + extras (plugins/completion/alias/macro, never counted)
src/ui.js           banner/box/table/severity/ok/err/info/dim/event-format/progress (NO_COLOR aware)
src/auth.js         PBKDF2 PIN + duress store (dataDir-injected, testable)
src/traps.js        honey TCP / honey HTTP / canary watch / decoy deploy (stdlib only)
src/platform.js     windows/linux/darwin mapping + isAdmin/hostsPath/dataDir/hasCmd (stdlib only)
src/sentinel.js     read-only network watch parsers + baselines + threat score + integrity (stdlib only, no capture; per-OS backends)
src/sniff.js        per-OS capture (pktmon/tcpdump/dumpcap) + shared local parser + analyzer (stdlib only)
src/store.js        data dir: config.json (now +plugins/aliases/macros) + events.jsonl (+disabled/banners/notes) + sentinel-baseline.json + integrity.json
docs/INSTALL.md     per-OS prerequisites, npm link/unlink, data locations, executed-vs-fixture-tested matrix
examples/hello-plugin.js   example plugin (commands hello, threat-tip) used by tests
test/selftest.js    auth + traps (ephemeral) + canary + count==92 + ui + per-command --help smoke + plugins/completion/alias/macro + sentinel/integrity
test/crossplatform.js   platform unit tests (injected os strings, no global patching) + linux/macOS parser fixtures + tcpdump analyzer reuse + count==92 smoke
```
