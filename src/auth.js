// ducgo v3 - PIN + duress-PIN store (PBKDF2-SHA256, 200k iterations).
// Node.js stdlib only. Never stores PIN material - only salted hashes.
// Lockout: escalating delays as pure function of failCount (unit-tested):
//   0-2 fails: 0ms, 3-4: 5s, 5-9: 60s, 10+: 15min lock (lockUntil in auth.json).
// Successful normal OR duress auth resets {failCount, lockUntil}.
// Every failed attempt appends auth_failure (no PIN content, source command).
// Delays sleep in requireAuth (cli.js); tests use pure policy + file helpers
// with a short-circuit env (DUC_NO_LOCK_SLEEP=1) so they never sleep 60s.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export const ITERATIONS = 200_000;
const KEYLEN = 32;
const DIGEST = 'sha256';

export const LOCK_DELAY_3 = 5000;
export const LOCK_DELAY_5 = 60000;
export const LOCK_DELAY_10 = 15 * 60 * 1000;

function pbkdf2(pin, saltHex) {
  return crypto.pbkdf2Sync(pin, Buffer.from(saltHex, 'hex'), ITERATIONS, KEYLEN, DIGEST).toString('hex');
}

export function authFile(dataDir) {
  return path.join(dataDir, 'auth.json');
}

export function isSetup(dataDir) {
  try {
    return fs.existsSync(authFile(dataDir));
  } catch {
    return false;
  }
}

export function loadAuth(dataDir) {
  try {
    const j = JSON.parse(fs.readFileSync(authFile(dataDir), 'utf8'));
    if (!j || typeof j !== 'object') return null;
    if (!j.salt || !j.hash || !j.duressSalt || !j.duressHash) return null;
    if (!Number.isInteger(j.failCount) || j.failCount < 0) j.failCount = 0;
    if (!Number.isInteger(j.lockUntil) || j.lockUntil < 0) j.lockUntil = 0;
    return j;
  } catch {
    return null;
  }
}

function saveAuth(dataDir, st) {
  fs.writeFileSync(authFile(dataDir), JSON.stringify(st, null, 2), 'utf8');
}

// Pure policy: delay ms for a given consecutive failCount. No I/O, no sleep.
export function getLockoutDelay(failCount) {
  const n = Number(failCount) || 0;
  if (n >= 10) return LOCK_DELAY_10;
  if (n >= 5) return LOCK_DELAY_5;
  if (n >= 3) return LOCK_DELAY_3;
  return 0;
}

// Pure: is locked at nowMs given lockUntil.
export function isLockedAt(lockUntil, nowMs) {
  return Number(lockUntil) > Number(nowMs);
}

export function loadLockState(dataDir) {
  const st = loadAuth(dataDir);
  if (!st) return { failCount: 0, lockUntil: 0 };
  return { failCount: st.failCount || 0, lockUntil: st.lockUntil || 0 };
}

export function recordAuthFailure(dataDir, nowMs) {
  const st = loadAuth(dataDir);
  if (!st) return { failCount: 1, lockUntil: 0 };
  st.failCount = (st.failCount || 0) + 1;
  if (st.failCount >= 10) {
    st.lockUntil = Number(nowMs) + LOCK_DELAY_10;
  }
  try { saveAuth(dataDir, st); } catch { /* ignore */ }
  return { failCount: st.failCount, lockUntil: st.lockUntil || 0 };
}

export function resetLockState(dataDir) {
  const st = loadAuth(dataDir);
  if (!st) return;
  if (st.failCount !== 0 || st.lockUntil !== 0) {
    st.failCount = 0;
    st.lockUntil = 0;
    try { saveAuth(dataDir, st); } catch { /* ignore */ }
  }
}

export function setupPins(dataDir, pin, duressPin) {
  if (!pin || pin.length < 6) return { ok: false, error: 'PIN must be at least 6 characters' };
  if (!duressPin || duressPin.length < 6) return { ok: false, error: 'Duress PIN must be at least 6 characters' };
  if (pin === duressPin) return { ok: false, error: 'Duress PIN must differ from the access PIN' };
  const salt = crypto.randomBytes(16).toString('hex');
  const duressSalt = crypto.randomBytes(16).toString('hex');
  const state = {
    salt,
    hash: pbkdf2(pin, salt),
    duressSalt,
    duressHash: pbkdf2(duressPin, duressSalt),
    createdAt: new Date().toISOString(),
    failCount: 0,
    lockUntil: 0,
  };
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(authFile(dataDir), JSON.stringify(state, null, 2), { mode: 0o600 });
    try {
      fs.chmodSync(authFile(dataDir), 0o600);
    } catch {
      /* Windows ACLs: best effort */
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err) };
  }
}

// Returns 'normal' | 'duress' | null. Timing-safe comparison on both hashes.
// Does NOT touch lockout counters (cli.js requireAuth owns lockout + reset).
export function verifyPin(dataDir, pin) {
  const st = loadAuth(dataDir);
  if (!st || !pin) return null;
  try {
    const h = pbkdf2(pin, st.salt);
    const dh = pbkdf2(pin, st.duressSalt);
    if (crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(st.hash, 'hex'))) return 'normal';
    if (crypto.timingSafeEqual(Buffer.from(dh, 'hex'), Buffer.from(st.duressHash, 'hex'))) return 'duress';
    return null;
  } catch {
    return null;
  }
}

export function changeAccessPin(dataDir, newPin) {
  if (!newPin || newPin.length < 6) return { ok: false, error: 'PIN must be at least 6 characters' };
  const st = loadAuth(dataDir);
  if (!st) return { ok: false, error: 'Not set up yet' };
  try {
    const duressCheck = pbkdf2(newPin, st.duressSalt);
    if (crypto.timingSafeEqual(Buffer.from(duressCheck, 'hex'), Buffer.from(st.duressHash, 'hex'))) {
      return { ok: false, error: 'New PIN must differ from the duress PIN' };
    }
  } catch {
    /* continue */
  }
  const salt = crypto.randomBytes(16).toString('hex');
  st.salt = salt;
  st.hash = pbkdf2(newPin, salt);
  try {
    fs.writeFileSync(authFile(dataDir), JSON.stringify(st, null, 2), 'utf8');
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err) };
  }
}

export function changeDuressPin(dataDir, newDuress) {
  if (!newDuress || newDuress.length < 6) return { ok: false, error: 'Duress PIN must be at least 6 characters' };
  const st = loadAuth(dataDir);
  if (!st) return { ok: false, error: 'Not set up yet' };
  try {
    const normalCheck = pbkdf2(newDuress, st.salt);
    if (crypto.timingSafeEqual(Buffer.from(normalCheck, 'hex'), Buffer.from(st.hash, 'hex'))) {
      return { ok: false, error: 'Duress PIN must differ from the access PIN' };
    }
  } catch {
    /* continue */
  }
  const duressSalt = crypto.randomBytes(16).toString('hex');
  st.duressSalt = duressSalt;
  st.duressHash = pbkdf2(newDuress, duressSalt);
  try {
    fs.writeFileSync(authFile(dataDir), JSON.stringify(st, null, 2), 'utf8');
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err) };
  }
}
