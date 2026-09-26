export type TrapSeverity = 'low' | 'medium' | 'high' | 'critical'
export type TrapEventType = 'honey-tcp' | 'banner-grab' | 'honey-http' | 'canary' | 'duress' | 'system' | 'sim'

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

declare global {
  interface Window {
    mirage: MirageAPI
  }
}

export {}
