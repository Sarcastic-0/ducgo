import { app, BrowserWindow, ipcMain, dialog } from 'electron'
import { join } from 'node:path'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { TrapEngine, type TrapEvent } from './traps'
import { isSetup, setupPins, verifyPin } from './auth'

const gotLock = app.requestSingleInstanceLock()
if (!gotLock) app.quit()

let win: BrowserWindow | null = null
let engine: TrapEngine | null = null

function dataDir(): string {
  return app.getPath('userData')
}

function eventsPath(): string {
  return path.join(dataDir(), 'trap-events.json')
}

function configPath(): string {
  return path.join(dataDir(), 'trap-config.json')
}

function loadPorts(): number[] {
  try {
    if (fs.existsSync(configPath())) {
      const j = JSON.parse(fs.readFileSync(configPath(), 'utf8')) as { ports?: number[] }
      if (Array.isArray(j.ports) && j.ports.length > 0) {
        return j.ports.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535).slice(0, 20)
      }
    }
  } catch {
    /* ignore */
  }
  return [2222, 2323, 8080]
}

function savePorts(ports: number[]): void {
  try {
    fs.mkdirSync(dataDir(), { recursive: true })
    fs.writeFileSync(configPath(), JSON.stringify({ ports }), 'utf8')
  } catch {
    /* best effort */
  }
}

function ensureEngine(): TrapEngine {
  if (!engine) {
    engine = new TrapEngine({
      tcpPorts: loadPorts(),
      httpPort: 18080,
      persistPath: eventsPath(),
      onEvent: (ev: TrapEvent) => {
        for (const w of BrowserWindow.getAllWindows()) {
          try {
            w.webContents.send('trap:event', ev)
          } catch {
            /* ignore */
          }
        }
      }
    })
    engine.loadPersisted()
  }
  return engine
}

function createWindow(): void {
  win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 640,
    backgroundColor: '#06090f',
    title: 'MirageNet — Deception Tripwire Mesh',
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  if (process.env['ELECTRON_RENDERER_URL']) {
    void win.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    void win.loadFile(join(__dirname, '../renderer/index.html'))
  }

  win.on('closed', () => {
    win = null
  })
}

function registerIpc(): void {
  // ---- auth ----
  ipcMain.handle('auth:status', () => ({ setup: isSetup(dataDir()) }))
  ipcMain.handle('auth:setup', (_e, pin: string, duressPin: string) => {
    if (isSetup(dataDir())) return { ok: false, error: 'Already set up' }
    return setupPins(dataDir(), String(pin ?? ''), String(duressPin ?? ''))
  })
  ipcMain.handle('auth:verify', (_e, pin: string) => {
    const r = verifyPin(dataDir(), String(pin ?? ''))
    if (r === 'duress') {
      // silently append a duress alert to the REAL log
      try {
        ensureEngine().log('duress', 'duress-pin', '127.0.0.1', 'Duress PIN was used — operator under pressure. Decoy view shown.', 'critical')
      } catch {
        /* ignore */
      }
    }
    return { result: r }
  })
  ipcMain.handle('auth:change', (_e, current: string, next: string, nextDuress: string) => {
    const r = verifyPin(dataDir(), String(current ?? ''))
    if (r !== 'normal') return { ok: false, error: 'Current PIN incorrect' }
    // rewrite file: remove old then setup
    try {
      fs.rmSync(path.join(dataDir(), 'auth.json'), { force: true })
    } catch {
      /* ignore */
    }
    return setupPins(dataDir(), String(next ?? ''), String(nextDuress ?? ''))
  })

  // ---- traps ----
  ipcMain.handle('traps:start', async () => {
    const e = ensureEngine()
    await e.start()
    return e.status()
  })
  ipcMain.handle('traps:stop', async () => {
    const e = ensureEngine()
    await e.stop()
    return e.status()
  })
  ipcMain.handle('traps:status', () => ensureEngine().status())
  ipcMain.handle('traps:events', (_e, limit?: number) => {
    const n = typeof limit === 'number' && limit > 0 ? Math.min(limit, 5000) : 1000
    return ensureEngine().getEvents(n)
  })
  ipcMain.handle('traps:deploy-canaries', async (_e, dir?: string) => {
    let target = String(dir ?? '').trim()
    if (!target) {
      const picked = await dialog.showOpenDialog({ properties: ['openDirectory', 'createDirectory'] })
      if (picked.canceled || picked.filePaths.length === 0) return { ok: false, error: 'No folder selected' }
      target = picked.filePaths[0]
    }
    return ensureEngine().deployCanaries(target)
  })
  ipcMain.handle('traps:add-port', (_e, port: number) => {
    const e = ensureEngine()
    const r = e.addPort(Number(port))
    if (r.ok) savePorts(e.getPorts())
    return r
  })
  ipcMain.handle('traps:remove-port', async (_e, port: number) => {
    const e = ensureEngine()
    const r = await e.removePort(Number(port))
    if (r.ok) savePorts(e.getPorts())
    return r
  })
  ipcMain.handle('traps:simulate', () => ensureEngine().simulateTouch())
}

void app.whenReady().then(() => {
  ensureEngine()
  registerIpc()
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('second-instance', () => {
  const w = BrowserWindow.getAllWindows()[0]
  if (w) {
    if (w.isMinimized()) w.restore()
    w.focus()
  }
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
