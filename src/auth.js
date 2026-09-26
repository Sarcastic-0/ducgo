// MirageNet v2 - PIN + duress-PIN store (PBKDF2-SHA256, 200k iterations).
// Node.js stdlib only. Never stores PIN material - only salted hashes.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

export const ITERATIONS = 200_000;
const KEYLEN = 32;
const DIGEST = 'sha256';

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
    return j;
  } catch {
    return null;
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
