import { contextBridge, ipcRenderer } from 'electron'
import type { TrapEvent, TrapStatus, DeployResult } from '../main/traps'

export interface MirageAPI {
  authStatus: () => Promise<{ setup: boolean }>
  authSetup: (pin: string, duressPin: string) => Promise<{ ok: boolean; error?: string }>
  authVerify: (pin: string) => Promise<{ result: 'normal' | 'duress' | null }>
  authChange: (current: string, next: string, nextDuress: string) => Promise<{ ok: boolean; error?: string }>
  trapsStart: () => Promise<TrapStatus>
  trapsStop: () => Promise<TrapStatus>
  trapsStatus: () => Promise<TrapStatus>
  trapsEvents: (limit?: number) => Promise<TrapEvent[]>
  trapsDeployCanaries: (dir?: string) => Promise<DeployResult>
  trapsAddPort: (port: number) => Promise<{ ok: boolean; error?: string }>
  trapsRemovePort: (port: number) => Promise<{ ok: boolean; error?: string }>
  trapsSimulate: () => Promise<TrapEvent>
  onTrapEvent: (cb: (ev: TrapEvent) => void) => () => void
}

const api: MirageAPI = {
  authStatus: () => ipcRenderer.invoke('auth:status'),
  authSetup: (pin, duressPin) => ipcRenderer.invoke('auth:setup', pin, duressPin),
  authVerify: (pin) => ipcRenderer.invoke('auth:verify', pin),
  authChange: (current, next, nextDuress) => ipcRenderer.invoke('auth:change', current, next, nextDuress),
  trapsStart: () => ipcRenderer.invoke('traps:start'),
  trapsStop: () => ipcRenderer.invoke('traps:stop'),
  trapsStatus: () => ipcRenderer.invoke('traps:status'),
  trapsEvents: (limit) => ipcRenderer.invoke('traps:events', limit),
  trapsDeployCanaries: (dir) => ipcRenderer.invoke('traps:deploy-canaries', dir),
  trapsAddPort: (port) => ipcRenderer.invoke('traps:add-port', port),
  trapsRemovePort: (port) => ipcRenderer.invoke('traps:remove-port', port),
  trapsSimulate: () => ipcRenderer.invoke('traps:simulate'),
  onTrapEvent: (cb) => {
    const listener = (_e: unknown, ev: TrapEvent): void => cb(ev)
    ipcRenderer.on('trap:event', listener as (...args: unknown[]) => void)
    return () => ipcRenderer.removeListener('trap:event', listener as (...args: unknown[]) => void)
  }
}

contextBridge.exposeInMainWorld('mirage', api)
