import * as net from 'node:net'
import * as http from 'node:http'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as crypto from 'node:crypto'

export type TrapSeverity = 'low' | 'medium' | 'high' | 'critical'
export type TrapEventType =
  | 'honey-tcp'
  | 'banner-grab'
  | 'honey-http'
  | 'canary'
  | 'duress'
  | 'system'
  | 'sim'

export interface TrapEvent {
  id: string
  time: string
  type: TrapEventType
  trap: string
  ip: string
  detail: string
  severity: TrapSeverity
  meta?: Record<string, string | number | boolean | null>
}

export interface TrapStatus {
  running: boolean
  tcpPorts: number[]
  httpPort: number
  httpHost: string
  canaryDir: string | null
  canaryCount: number
  eventCount: number
  uptimeSec: number
}

export interface DeployResult {
  ok: boolean
  dir: string
  files: string[]
  error?: string
}

function uid(): string {
  return crypto.randomBytes(8).toString('hex')
}

function nowISO(): string {
  return new Date().toISOString()
}

function fakeBanner(port: number): string {
  if (port === 2222) return 'SSH-2.0-OpenSSH_9.2 MirageNet\r\n'
  if (port === 2323) return 'Welcome to Telnet service. Login: '
  // 8080 and others: fake HTTP
  return 'HTTP/1.1 200 OK\r\nServer: MirageNet/1.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
}

function sanitizePreview(buf: Buffer, max = 220): string {
  let s = buf.subarray(0, max).toString('utf8')
  // strip non-printables except basic whitespace
  s = s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '·')
  if (buf.length > max) s += ` …(+${buf.length - max}B)`
  return s.slice(0, 400)
}

export const FAKE_LOGIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Admin Login</title>
<style>body{font-family:Arial,sans-serif;background:#0b1220;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#111c33;padding:32px;border-radius:12px;width:320px;box-shadow:0 10px 40px rgba(0,0,0,.5)}
h2{margin:0 0 16px}input{width:100%;padding:10px;margin:6px 0;border-radius:6px;border:1px solid #334155;background:#0b1220;color:#fff;box-sizing:border-box}
button{width:100%;padding:10px;margin-top:10px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-weight:bold;cursor:pointer}</style>
</head><body><div class="card"><h2>Admin Login</h2>
<form method="POST" action="/login"><input name="username" placeholder="Username" autocomplete="off"><input name="password" type="password" placeholder="Password"><button type="submit">Sign in</button></form>
<p style="font-size:11px;color:#64748b">Restricted area. All access is logged.</p></div></body></html>`

export class TrapEngine {
  private tcpServers: Map<number, net.Server> = new Map()
  private httpServer: http.Server | null = null
  private watchers: fs.FSWatcher[] = []
  private events: TrapEvent[] = []
  private running = false
  private tcpPorts: number[]
  private httpPort: number
  private httpHost = '127.0.0.1'
  private canaryDir: string | null = null
  private startedAt: number | null = null
  private maxEvents = 5000
  private persistPath: string | null = null
  onEvent: ((ev: TrapEvent) => void) | null = null

  constructor(opts?: {
    tcpPorts?: number[]
    httpPort?: number
    onEvent?: (ev: TrapEvent) => void
    persistPath?: string | null
  }) {
    this.tcpPorts = opts?.tcpPorts ?? [2222, 2323, 8080]
    this.httpPort = opts?.httpPort ?? 18080
    if (opts?.onEvent) this.onEvent = opts.onEvent
    this.persistPath = opts?.persistPath ?? null
  }

  setPersistPath(p: string | null): void {
    this.persistPath = p
  }

  loadPersisted(maxLoad = 2000): void {
    if (!this.persistPath) return
    try {
      if (fs.existsSync(this.persistPath)) {
        const raw = fs.readFileSync(this.persistPath, 'utf8')
        const arr = JSON.parse(raw) as TrapEvent[]
        if (Array.isArray(arr)) this.events = arr.slice(-maxLoad)
      }
    } catch {
      /* ignore corrupt history */
    }
  }

  private save(): void {
    if (!this.persistPath) return
    try {
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true })
      fs.writeFileSync(this.persistPath, JSON.stringify(this.events.slice(-2000)), 'utf8')
    } catch {
      /* best effort */
    }
  }

  log(type: TrapEventType, trap: string, ip: string, detail: string, severity: TrapSeverity, meta?: TrapEvent['meta']): TrapEvent {
    const ev: TrapEvent = { id: uid(), time: nowISO(), type, trap, ip, detail, severity, meta }
    this.events.push(ev)
    if (this.events.length > this.maxEvents) this.events = this.events.slice(-this.maxEvents)
    this.save()
    try {
      this.onEvent?.(ev)
    } catch {
      /* never throw from logger */
    }
    return ev
  }

  getEvents(limit = 1000): TrapEvent[] {
    return this.events.slice(-limit)
  }

  clearEvents(): void {
    this.events = []
    this.save()
  }

  status(): TrapStatus {
    return {
      running: this.running,
      tcpPorts: [...this.tcpPorts],
      httpPort: this.httpPort,
      httpHost: this.httpHost,
      canaryDir: this.canaryDir,
      canaryCount: this.watchers.length,
      eventCount: this.events.length,
      uptimeSec: this.startedAt ? Math.floor((Date.now() - this.startedAt) / 1000) : 0
    }
  }

  isRunning(): boolean {
    return this.running
  }

  getPorts(): number[] {
    return [...this.tcpPorts]
  }

  async start(): Promise<void> {
    if (this.running) return
    // start TCP honey ports (each best-effort; EADDRINUSE logs a system event and continues)
    for (const port of this.tcpPorts) {
      await this.listenTcp(port)
    }
    await this.listenHttp()
    this.running = true
    this.startedAt = Date.now()
    this.log('system', 'engine', '127.0.0.1', `Trap mesh started — TCP [${this.tcpPorts.join(', ')}], HTTP ${this.httpHost}:${this.httpPort}`, 'low')
  }

  async stop(): Promise<void> {
    for (const [, srv] of this.tcpServers) {
      await new Promise<void>((resolve) => {
        try {
          srv.close(() => resolve())
        } catch {
          resolve()
        }
        setTimeout(resolve, 800)
      })
    }
    this.tcpServers.clear()
    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        try {
          this.httpServer!.close(() => resolve())
        } catch {
          resolve()
        }
        setTimeout(resolve, 800)
      })
      this.httpServer = null
    }
    this.closeWatchers()
    this.running = false
    this.startedAt = null
    this.log('system', 'engine', '127.0.0.1', 'Trap mesh stopped', 'low')
  }

  private listenTcp(port: number): Promise<void> {
    return new Promise((resolve) => {
      const server = net.createServer((socket) => {
        const remoteIP = socket.remoteAddress?.replace(/^::ffff:/, '') ?? 'unknown'
        const remotePort = socket.remotePort ?? 0
        const label = `honey-tcp:${port}`
        let collected = Buffer.alloc(0)
        let logged = false

        const finishConnectLog = (): void => {
          if (logged) return
          logged = true
          this.log(
            'honey-tcp',
            label,
            remoteIP,
            `Connection on fake port ${port} from ${remoteIP}:${remotePort}`,
            port === 2222 ? 'high' : 'medium',
            { remotePort, port }
          )
        }

        // banner first (fake service), then watch for banner-grab data
        try {
          socket.write(fakeBanner(port))
        } catch {
          /* ignore */
        }
        finishConnectLog()

        const chunks: Buffer[] = []
        socket.on('data', (d: Buffer) => {
          chunks.push(d)
          collected = Buffer.concat(chunks).subarray(0, 4096)
          const preview = sanitizePreview(collected)
          this.log(
            'banner-grab',
            label,
            remoteIP,
            `Banner grab on :${port} — ${collected.length}B: "${preview}"`,
            'high',
            { remotePort, port, bytes: collected.length, preview }
          )
        })
        socket.on('error', () => {
          /* ignore resets */
        })
        // close after 5s (tar-pit lightly, then drop)
        const t = setTimeout(() => {
          try {
            socket.end()
          } catch {
            /* ignore */
          }
          try {
            socket.destroy()
          } catch {
            /* ignore */
          }
        }, 5000)
        try {
          socket.setTimeout(6000)
        } catch {
          /* ignore */
        }
        socket.on('close', () => clearTimeout(t))
        socket.on('timeout', () => {
          try {
            socket.destroy()
          } catch {
            /* ignore */
          }
        })
      })
      server.on('error', (err: NodeJS.ErrnoException) => {
        this.log('system', `honey-tcp:${port}`, '127.0.0.1', `Port ${port} unavailable (${err.code ?? err.message}) — continuing without it`, 'medium')
        resolve()
      })
      server.listen(port, '0.0.0.0', () => {
        this.tcpServers.set(port, server)
        resolve()
      })
    })
  }

  private listenHttp(): Promise<void> {
    return new Promise((resolve) => {
      const srv = http.createServer((req, res) => {
        const ip = (req.socket.remoteAddress ?? 'unknown').replace(/^::ffff:/, '')
        const ua = String(req.headers['user-agent'] ?? '')
        const method = req.method ?? 'GET'
        const urlPath = (req.url ?? '/').split('?')[0]
        void ua

        if (method === 'POST' && (urlPath === '/login' || urlPath === '/')) {
          let body = ''
          req.on('data', (c) => {
            body += String(c)
            if (body.length > 8192) {
              try {
                req.destroy()
              } catch {
                /* ignore */
              }
            }
          })
          req.on('end', () => {
            const username = this.extractUsername(body, req.headers['content-type'])
            // NEVER store passwords — only a boolean
            this.log(
              'honey-http',
              'honey-http:18080',
              ip,
              `Fake-admin login attempt by "${username || 'unknown'}" — ${method} ${urlPath}`,
              'critical',
              { method, path: urlPath, userAgent: ua.slice(0, 300), username: (username || 'unknown').slice(0, 120), attempted: true }
            )
            res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' })
            res.end(FAKE_LOGIN_PAGE.replace('Admin Login', 'Invalid credentials — try again'))
          })
          return
        }

        this.log(
          'honey-http',
          'honey-http:18080',
          ip,
          `${method} ${urlPath} on fake admin panel`,
          urlPath === '/' ? 'medium' : 'high',
          { method, path: urlPath, userAgent: ua.slice(0, 300) }
        )
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(FAKE_LOGIN_PAGE)
      })
      srv.on('error', (err) => {
        this.log('system', 'honey-http:18080', '127.0.0.1', `Honey HTTP unavailable: ${String((err as Error).message)}`, 'medium')
        resolve()
      })
      srv.listen(this.httpPort, this.httpHost, () => {
        this.httpServer = srv
        resolve()
      })
    })
  }

  private extractUsername(body: string, ctype: unknown): string {
    const ct = String(ctype ?? '')
    try {
      if (ct.includes('application/json')) {
        const j = JSON.parse(body) as Record<string, unknown>
        const u = j['username'] ?? j['user'] ?? j['email'] ?? j['login']
        return String(u ?? '').slice(0, 120)
      }
    } catch {
      /* fall through to form parse */
    }
    // application/x-www-form-urlencoded
    const m = body.match(/(?:^|&)(?:username|user|email|login)=([^&]*)/i)
    if (m) {
      try {
        return decodeURIComponent(m[1].replace(/\+/g, ' ')).slice(0, 120)
      } catch {
        return m[1].slice(0, 120)
      }
    }
    return ''
  }

  addPort(port: number): { ok: boolean; error?: string } {
    if (!Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, error: 'Port must be 1–65535' }
    if (this.tcpPorts.includes(port)) return { ok: false, error: 'Port already watched' }
    this.tcpPorts.push(port)
    if (this.running) {
      void this.listenTcp(port).then(() => {
        this.log('system', 'engine', '127.0.0.1', `Added honey port ${port}`, 'low', { port })
      })
    }
    return { ok: true }
  }

  async removePort(port: number): Promise<{ ok: boolean; error?: string }> {
    const idx = this.tcpPorts.indexOf(port)
    if (idx === -1) return { ok: false, error: 'Port not watched' }
    this.tcpPorts.splice(idx, 1)
    const srv = this.tcpServers.get(port)
    if (srv) {
      await new Promise<void>((resolve) => {
        try {
          srv.close(() => resolve())
        } catch {
          resolve()
        }
        setTimeout(resolve, 800)
      })
      this.tcpServers.delete(port)
    }
    this.log('system', 'engine', '127.0.0.1', `Removed honey port ${port}`, 'low', { port })
    return { ok: true }
  }

  deployCanaries(dir: string): DeployResult {
    try {
      const target = path.resolve(dir)
      fs.mkdirSync(target, { recursive: true })
      const token = (p: string): string => `MIRAGETOKEN-${crypto.randomBytes(6).toString('hex')}-${p}`
      const files: Array<{ name: string; content: string }> = [
        {
          name: 'aws-keys.txt',
          content: `# AWS credentials — ROTATED DECOY, NOT REAL\n# canary: ${token('aws')}\n[default]\naws_access_key_id = AKIAIOSFODNN7DECOY${crypto.randomBytes(3).toString('hex').toUpperCase()}\naws_secret_access_key = ${crypto.randomBytes(20).toString('base64')}\nregion = us-east-1\n# If you are reading this outside an authorized review, stop — this access is logged.\n`
        },
        {
          name: 'passwords.csv',
          content: `site,username,password,canary\nvpn,admin,DECOY-NOT-REAL-${crypto.randomBytes(4).toString('hex')},${token('csv')}\nmail,backup,DECOY-NOT-REAL-${crypto.randomBytes(4).toString('hex')},${token('csv2')}\n# decoy file — any use of these credentials triggers an alert\n`
        },
        {
          name: 'wallet-seed.txt',
          content: `BITCOIN WALLET SEED — DECOY, DO NOT USE, FUNDS DO NOT EXIST\ncanary: ${token('seed')}\n${Array.from({ length: 12 }, () => crypto.randomBytes(4).toString('hex')).join(' ')}\nContact security if you found this file unexpectedly.\n`
        }
      ]
      const written: string[] = []
      for (const f of files) {
        const fp = path.join(target, f.name)
        if (!fs.existsSync(fp)) fs.writeFileSync(fp, f.content, 'utf8')
        written.push(f.name)
      }
      this.watchCanaries(target, written)
      this.log('system', 'canary', '127.0.0.1', `Deployed ${written.length} canary files to ${target}`, 'low', { dir: target })
      return { ok: true, dir: target, files: written }
    } catch (err) {
      return { ok: false, dir, files: [], error: String((err as Error).message) }
    }
  }

  private watchCanaries(dir: string, names: string[]): void {
    this.closeWatchers()
    this.canaryDir = dir
    const targets = names.length > 0 ? names.map((n) => path.join(dir, n)) : [dir]
    for (const t of targets) {
      try {
        const w = fs.watch(t, (eventType, filename) => {
          const label = `canary:${path.basename(t)}`
          if (eventType === 'rename') {
            const exists = fs.existsSync(t)
            this.log(
              'canary',
              label,
              '127.0.0.1',
              exists ? `Canary file touched (rename/recreate): ${path.basename(t)} (${String(filename ?? '')})` : `Canary file DELETED/RENAMED AWAY: ${path.basename(t)} — possible tampering`,
              'critical',
              { file: path.basename(t), event: 'rename' }
            )
          } else {
            this.log('canary', label, '127.0.0.1', `Canary file MODIFIED: ${path.basename(t)} — opened/saved by someone`, 'critical', {
              file: path.basename(t),
              event: 'change'
            })
          }
        })
        w.on('error', () => {
          /* watcher errors are non-fatal */
        })
        this.watchers.push(w)
      } catch {
        /* ignore unwatched */
      }
    }
    // also watch the directory itself for deletes/renames
    try {
      const dw = fs.watch(dir, (eventType, filename) => {
        const fn = String(filename ?? '')
        if (/aws-keys|passwords|wallet-seed/i.test(fn)) {
          this.log('canary', `canary:${fn}`, '127.0.0.1', `Canary directory event (${eventType}): ${fn}`, 'high', { file: fn, event: eventType })
        }
      })
      dw.on('error', () => undefined)
      this.watchers.push(dw)
    } catch {
      /* ignore */
    }
  }

  private closeWatchers(): void {
    for (const w of this.watchers) {
      try {
        w.close()
      } catch {
        /* ignore */
      }
    }
    this.watchers = []
  }

  /** Clearly-labeled DEMO helper — injects a synthetic touch so reviewers can see the dashboard alive. */
  simulateTouch(): TrapEvent {
    const ips = ['185.220.70.4', '45.148.10.88', '103.99.0.25', '91.240.118.41']
    const traps = ['honey-tcp:2222', 'honey-tcp:2323', 'honey-tcp:8080', 'honey-http:18080', 'canary:aws-keys.txt']
    const ip = ips[Math.floor(Math.random() * ips.length)]
    const trap = traps[Math.floor(Math.random() * traps.length)]
    const isCanary = trap.startsWith('canary')
    return this.log(
      'sim',
      trap,
      ip,
      isCanary ? `DEMO — simulated canary touch on ${trap}` : `DEMO — simulated probe on ${trap} from ${ip}`,
      'high',
      { demo: true }
    )
  }
}
