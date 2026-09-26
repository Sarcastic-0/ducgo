# MirageNet v2 — Deception Tripwire Mesh (CLI only)

A lightweight **passive deception (tripwire)** tool for individuals and small teams:
honey TCP ports, a honey HTTP admin panel, and canary files. Any touch of a trap
is logged as an event with the visitor's fingerprint. Includes duress-PIN mode
(fake all-clear message + silent alert).

> 100% passive/defensive. Zero offensive traffic — the tool only listens on
> ports, serves a fake login page, and watches files. It never scans, probes,
> or attacks anything.

English only. CLI only. **Zero runtime dependencies** (Node.js standard library
only). Exit codes: `0` success, `1` error.

## Install

Requires Node.js 18+.

```powershell
cd "C:\Users\LORD laptop\Documents\MirageNet"
npm link        # exposes the global `mirage` command
```

Or run without installing:

```powershell
node src/cli.js --help
```

Set `NO_COLOR=1` to disable ANSI colors.

## Commands

All commands store data in `%USERPROFILE%\.miragenet\`
(`auth.json`, `events.jsonl`, `config.json`). Set `MIRAGENET_DIR` to override
the data directory (used for testing).

### `mirage setup`

Interactive first-run setup. Sets an access PIN (min 6 chars) and a **different**
duress PIN (min 6 chars). Only salted PBKDF2-SHA256 hashes (200k iterations,
random 16-byte salts) are stored — never any PIN material.

```powershell
mirage setup
```

### `mirage start [--ports 2222,2323,8080] [--http 18080]`

Prompts for the PIN first, then arms the trap mesh live until `Ctrl+C`:

- **(a) Honey TCP listeners** (default `2222,2323,8080`, LAN-visible `0.0.0.0`
  by design). Each connection logs `{time, trap, remoteIP, remotePort,
  bannerBytes up to 256B}`, serves a fake banner, and is closed after 5s.
- **(b) Honey HTTP** on `127.0.0.1` (default `18080`) serving a fake
  "Admin Login" page. Each request logs `{time, ip, method, path, userAgent,
  loginAttempted, username?}`. **Posted passwords are never logged or stored.**
- **(c) Canary watch** on all deployed directories (`fs.watch` → modify/rename
  events).

Events print live, color-coded by severity, and every event is appended to
`events.jsonl`.

```powershell
mirage start
mirage start --ports 2222,2323 --http 18080
```

### `mirage deploy <dir>`

Prompts for the PIN, drops three realistic decoys (`aws-keys.txt`,
`passwords.csv`, `wallet-seed.txt`, each with a random `MIRAGETOKEN-*` canary
marker) into `<dir>`, and adds the directory to the watch list in
`config.json`.

```powershell
mirage deploy ./decoys
```

### `mirage events [--json] [--export out.csv]`

Prompts for the PIN, then shows history: a table by default, raw JSON with
`--json`, or a CSV export with `--export`.

```powershell
mirage events
mirage events --json
mirage events --export report.csv
```

### `mirage attackers`

Prompts for the PIN, then groups touches by IP: touches, first/last seen,
top trap.

```powershell
mirage attackers
```

### `mirage demo`

No PIN needed. Records one synthetic event labeled `DEMO` so you can review
the output format.

```powershell
mirage demo
```

### `mirage selftest` (also `npm test`)

Runs the built-in suite: auth-store tests, trap tests on ephemeral ports, and
a canary watcher test. Prints `PASS` lines; exits non-zero on failure.

```powershell
mirage selftest
npm test
```

## Duress PIN

Entering the duress PIN at **any** PIN prompt prints exactly:

```text
All clear — no threats detected.
```

…appends a silent `{type:"duress", ...}` event to `events.jsonl`, and exits 0.
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
- No dependencies = minimal supply-chain surface. No network calls except the
  local listeners themselves.

## Honest limits

- `fs.watch` reports **modify/rename/delete** — it does **NOT** detect silent
  reads (opening a canary in Notepad without saving trips nothing). This is an
  OS limitation, not a bug.
- Honey TCP ports are **LAN-visible by design**; anyone port-scanning you will
  see open ports. That is the point of a tripwire, but don't run this on
  networks where unexplained open ports violate policy.
- Default ports (2222/2323/8080) may already be in use — the mesh logs a
  `system` event per unavailable port and keeps the rest running.
- No encryption-at-rest beyond OS file permissions for the event log; the log
  contains visitor IPs, banner bytes, and usernames (never passwords).
- The `attackers` table is naive IP grouping — no attribution, and
  spoofed/internal IPs mean little on their own.
- Duress mode hides the real view but cannot hide that the tool is installed.
- `demo` injects a synthetic event clearly tagged `DEMO` / type `sim`.

## Project layout

```text
package.json        ESM ("type": "module"), bin { mirage: ./src/cli.js }, no deps
src/cli.js          hand-rolled arg parsing, hidden PIN prompt, all commands
src/auth.js         PBKDF2 PIN + duress store (dataDir-injected, testable)
src/traps.js        honey TCP / honey HTTP / canary watch / decoy deploy (stdlib only)
src/store.js        data dir: config.json + events.jsonl
test/selftest.js    auth + trap (ephemeral ports) + canary tests
```
