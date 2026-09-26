# MirageNet — Deception Tripwire Mesh

A lightweight **deception-defense (tripwire)** system for individuals & small teams:
honey TCP ports, a honey HTTP admin panel, canary files, and a bilingual SOC-style
dashboard. Any touch of a trap = instant event with attacker fingerprint.
Includes duress-PIN mode (fake clean view + silent alert).

> 100% passive/defensive. Zero offensive traffic — the engine only listens, serves a
> fake login page, and watches files. It never scans, probes, or attacks anything.

## Run

```powershell
cd "C:\Users\LORD laptop\Documents\MirageNet"
npm install              # then, if electron postinstall was blocked:
node node_modules/electron/install.js
npm run dev              # live dev window (Electron + Vite HMR)
```

Production build / preview:

```powershell
npm run build            # typecheck (node+web) + electron-vite build → out/
npm start                # electron-vite preview
npm run smoke            # trap smoke test (honey HTTP+TCP on ports 18081/12222)
```

First launch: set a **PIN** (min 6 chars) + a **different duress PIN**, then unlock.
The trap mesh auto-starts on boot (TCP 2222/2323/8080, HTTP 127.0.0.1:18080).

## What it does

- **Honey TCP ports** (`src/main/traps.ts`): listeners on configurable ports
  (defaults 2222 fake-SSH banner, 2323 telnet-style, 8080 fake-HTTP). On connect:
  sends a fake banner, logs `{remoteIP, remotePort, time, bytes + preview}` as
  `honey-tcp` / `banner-grab` events, closes after ~5s.
- **Honey HTTP panel** on `127.0.0.1:18080`: fake "Admin Login" page. Every request
  logged `{ip, method, path, user-agent, time}`; POST /login also captures the
  **username only + `attempted:true` — posted passwords are NEVER stored.**
- **Canary files**: pick a folder → engine drops `aws-keys.txt`, `passwords.csv`,
  `wallet-seed.txt` (each with a random `MIRAGETOKEN-*` canary + obvious DECOY
  markings) and watches via `fs.watch`, logging modify/rename events.
- **Dashboard** (AR default RTL / EN): stat cards, live feed with severity colors,
  traps manager (start/stop, add/remove ports, deploy canaries), attackers-by-IP
  table, JSON/CSV export, PIN settings, and a clearly-labeled **DEMO "Simulate
  touch"** button that injects a synthetic event.
- **Duress PIN**: opens a decoy "all clear" dashboard AND silently appends a
  `duress` critical event to the real log.

## Security model

- Local PIN auth: PBKDF2-SHA256, 200k iterations, per-PIN 16-byte random salt,
  `auth.json` in Electron `userData`. Nothing leaves the machine. Timing-safe
  comparison; duress hash stored separately.
- Renderer is sandboxed (`sandbox:true`, `contextIsolation:true`, no
  `nodeIntegration`); all privileged work goes through a minimal typed
  `window.mirage` preload bridge (`ipcMain.handle` only).
- Honey HTTP binds `127.0.0.1` only (local review); honey TCP binds `0.0.0.0`
  **by design** so LAN touches trip the wire.
- IPC surface is allow-listed; event history persisted to
  `userData/trap-events.json` (capped, best-effort writes).

## Honest limits

- `fs.watch` detects **modify/rename/delete** — it does **NOT** detect silent
  reads (opening a canary in Notepad without saving trips nothing). This is an OS
  limitation, not a bug.
- Honey TCP ports are **LAN-visible by design**; anyone port-scanning you will see
  open ports. That is the point of a tripwire, but don't run this on networks
  where unexplained open ports violate policy.
- Default ports (2222/2323/8080) may already be in use — the engine logs a
  `system` event per unavailable port and keeps the rest running.
- No encryption-at-rest beyond OS file permissions for the event log; the log
  contains attacker IPs, banner bytes, and usernames (never passwords).
- The "attackers" table is naive IP grouping — no attribution, and spoofed/internal
  IPs mean little on their own.
- Duress mode hides the real view but cannot hide that the app is installed.
- DEMO simulate button injects synthetic events clearly tagged `demo:true` /
  type `sim` — excluded from nothing, but labeled in the feed.

## Project layout

```
electron.vite.config.ts  main/preload/renderer builds → out/
tsconfig.{json,node.json,web.json}
src/main/index.ts        single-instance window 1280×800 + IPC wiring
src/main/traps.ts        TrapEngine (net/http/fs/crypto only)
src/main/auth.ts         PBKDF2 PIN + duress store (dataDir-injected, testable)
src/preload/index.ts     contextBridge window.mirage
src/preload/index.d.ts   typed API (standalone, no Node imports)
src/renderer/index.html  CSP-hardened entry
src/renderer/src/        main.tsx App.tsx i18n.ts lib.ts types.ts styles.css
src/renderer/src/components/  SetupPin Login Dashboard EventFeed TrapsManager AttackersTable DecoyView
tools/trap-smoke.mjs     honey HTTP+TCP verification (ports 18081/12222)
```
