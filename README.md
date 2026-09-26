# ducgo v2.0.0 - Deception Tripwire Mesh (CLI only)

A lightweight **passive deception (tripwire)** tool for individuals and small teams:
honey TCP ports, a honey HTTP admin panel, and canary files. Any touch of a trap
is logged as an event with the visitor's fingerprint. Includes duress-PIN mode
(fake all-clear message + silent alert).

> 100% passive/defensive. Zero offensive traffic - the tool only listens on
> ports, serves a fake login page, and watches files. It never scans, probes,
> or attacks anything.

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
ducgo v2.0.0
```

(The dim line above is the English tagline.)

## Install

Requires Node.js 18+.

```powershell
cd "C:\Users\LORD laptop\Documents\MirageNet"
node src/cli.js --help
```

The bin is `ducgo` (`./src/cli.js`, shebang kept). Do NOT `npm link` - running
`node src/cli.js` is sufficient.

Set `NO_COLOR=1` to disable ANSI colors (plain logo; tagline + version still shown).

## Data

Data dir stays `%USERPROFILE%\.miragenet\` (`auth.json`, `events.jsonl`,
`config.json`). Set `MIRAGENET_DIR` to override the data directory (used for
testing so you never touch the real store).

## Quick start

```powershell
node src/cli.js setup
node src/cli.js deploy ./decoys
node src/cli.js start
node src/cli.js events
node src/cli.js attackers
```

With a scratch dir for safe experiments:

```powershell
$env:MIRAGENET_DIR = "$env:TEMP\ducgo-test"
"alpha-9912`nalpha-9912`nduress-4417`nduress-4417" | node src/cli.js setup
node src/cli.js demo
"alpha-9912" | node src/cli.js deploy "$env:TEMP\ducgo-test\decoys"
node src/cli.js commands --count   # -> 70
```

## Interactive shell

Running bare `ducgo` (no arguments) prints the banner once and enters a
persistent `ducgo> ` prompt. It stays open until `exit`, `quit`, or `q`,
a second `Ctrl+C` within 2 seconds, or EOF (exit code 0). Piped stdin works
too: lines are executed in order and the shell exits at EOF.

```powershell
node src/cli.js
# ducgo> version
# ducgo> commands --count   # -> 70
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
  stays exactly 70 built-ins; extras (plugin mgmt, completion, alias, macro,
  plugin commands) are never counted - see the `commands` footer line.

## 70 commands

`ducgo commands` prints the grouped list. `ducgo commands --count` prints `70`.
Every command supports `--help` (exits 0, no side effects).

### auth (7)

| Command | Description |
|---|---|
| `setup` | Set access PIN + duress PIN (interactive, min 6 chars) |
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
| `version` | Print `ducgo v2.0.0` |
| `commands [--count]` | Grouped one-liners; `--count` prints `70` |
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
- No dependencies = minimal supply-chain surface. No network calls except the
  local listeners themselves.

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
with built-in (70) + enabled-plugin + alias + macro names.

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

The 70 contract: `commands --count` stays exactly 70. Extras
(plugin commands, aliases, macros, plus 9 extra built-ins) appear only in
the footer line (`+ N plugin command(s), ...`) and are never counted.

## Project layout

```text
package.json        ESM ("type": "module"), bin { ducgo: ./src/cli.js }, no deps
src/cli.js          hand-rolled args, hidden PIN prompt, 70 built-ins + extras (plugins/completion/alias/macro, never counted)
src/ui.js           banner/box/table/severity/ok/err/info/dim/event-format/progress (NO_COLOR aware)
src/auth.js         PBKDF2 PIN + duress store (dataDir-injected, testable)
src/traps.js        honey TCP / honey HTTP / canary watch / decoy deploy (stdlib only)
src/store.js        data dir: config.json (now +plugins/aliases/macros) + events.jsonl (+disabled/banners/notes)
examples/hello-plugin.js   example plugin (commands hello, threat-tip) used by tests
test/selftest.js    auth + traps (ephemeral) + canary + count==70 + ui + per-command --help smoke + plugins/completion/alias/macro
```
