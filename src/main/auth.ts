import * as fs from 'node:fs'
import * as path from 'node:path'
import * as crypto from 'node:crypto'

export interface AuthState {
  salt: string
  hash: string
  duressSalt: string
  duressHash: string
  createdAt: string
}

const ITER = 200_000
const KEYLEN = 32
const DIGEST = 'sha256'

function pbkdf2(pin: string, saltHex: string): string {
  return crypto.pbkdf2Sync(pin, Buffer.from(saltHex, 'hex'), ITER, KEYLEN, DIGEST).toString('hex')
}

export function authFile(dataDir: string): string {
  return path.join(dataDir, 'auth.json')
}

export function isSetup(dataDir: string): boolean {
  try {
    return fs.existsSync(authFile(dataDir))
  } catch {
    return false
  }
}

export function loadAuth(dataDir: string): AuthState | null {
  try {
    const raw = fs.readFileSync(authFile(dataDir), 'utf8')
    const j = JSON.parse(raw) as AuthState
    if (!j.salt || !j.hash || !j.duressSalt || !j.duressHash) return null
    return j
  } catch {
    return null
  }
}

export function setupPins(dataDir: string, pin: string, duressPin: string): { ok: boolean; error?: string } {
  if (!pin || pin.length < 6) return { ok: false, error: 'PIN must be at least 6 characters' }
  if (!duressPin || duressPin.length < 6) return { ok: false, error: 'Duress PIN must be at least 6 characters' }
  if (pin === duressPin) return { ok: false, error: 'Duress PIN must differ from the real PIN' }
  const salt = crypto.randomBytes(16).toString('hex')
  const duressSalt = crypto.randomBytes(16).toString('hex')
  const st: AuthState = {
    salt,
    hash: pbkdf2(pin, salt),
    duressSalt,
    duressHash: pbkdf2(duressPin, duressSalt),
    createdAt: new Date().toISOString()
  }
  try {
    fs.mkdirSync(dataDir, { recursive: true })
    fs.writeFileSync(authFile(dataDir), JSON.stringify(st, null, 2), { mode: 0o600 })
    return { ok: true }
  } catch (err) {
    return { ok: false, error: String((err as Error).message) }
  }
}

export type VerifyResult = 'normal' | 'duress' | null

export function verifyPin(dataDir: string, pin: string): VerifyResult {
  const st = loadAuth(dataDir)
  if (!st || !pin) return null
  try {
    const h = pbkdf2(pin, st.salt)
    const dh = pbkdf2(pin, st.duressSalt)
    if (crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(st.hash, 'hex'))) return 'normal'
    if (crypto.timingSafeEqual(Buffer.from(dh, 'hex'), Buffer.from(st.duressHash, 'hex'))) return 'duress'
    return null
  } catch {
    return null
  }
}
