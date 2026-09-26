// Shared renderer-side shapes (mirrors src/main/traps.ts — kept dependency-free
// so the web tsconfig never pulls in Node builtins).
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
