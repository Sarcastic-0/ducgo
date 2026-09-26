import type { TrapEvent } from './types'

export type { TrapEvent }

export function groupByIp(events: TrapEvent[]): Array<{ ip: string; count: number; first: string; last: string; traps: string[] }> {
  const m = new Map<string, { count: number; first: string; last: string; traps: Set<string> }>()
  for (const e of events) {
    if (e.ip === '127.0.0.1' || e.ip === 'unknown') continue
    if (e.type === 'system' || e.type === 'duress') continue
    const g = m.get(e.ip) ?? { count: 0, first: e.time, last: e.time, traps: new Set<string>() }
    g.count += 1
    if (e.time < g.first) g.first = e.time
    if (e.time > g.last) g.last = e.time
    g.traps.add(e.trap)
    m.set(e.ip, g)
  }
  return [...m.entries()]
    .map(([ip, g]) => ({ ip, count: g.count, first: g.first, last: g.last, traps: [...g.traps] }))
    .sort((a, b) => b.count - a.count)
}

export function toCSV(events: TrapEvent[]): string {
  const q = (s: string): string => `"${s.replace(/"/g, '""')}"`
  const head = 'id,time,type,trap,ip,severity,detail'
  const rows = events.map((e) => [e.id, e.time, e.type, e.trap, e.ip, e.severity, e.detail.replace(/[\r\n]+/g, ' ')].map(q).join(','))
  return [head, ...rows].join('\n')
}

export function download(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}
