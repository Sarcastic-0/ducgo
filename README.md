# MirageNet — Deception Tripwire Mesh

A lightweight deception-defense system for individuals & small teams:
canary files, honey ports, a honey HTTP panel, and a SOC-style dashboard.
Any touch of a trap = instant encrypted-style alert with attacker fingerprint.
Includes duress-PIN mode (fake clean view + silent alert).

> Full app is under construction by the build agent. See below once complete.

## Run (after build)

```powershell
npm install
npm run dev
```

## Security model

- Local PIN (PBKDF2) + first-run setup, nothing leaves the machine
- Traps are passive listeners/watchers; no offensive traffic ever
- Duress PIN shows a decoy dashboard and logs a silent alert
