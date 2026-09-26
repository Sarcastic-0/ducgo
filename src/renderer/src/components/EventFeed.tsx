import { useEffect, useMemo, useRef, useState } from 'react'
import type { TrapEvent } from '../types'
import type { Strings } from '../i18n'

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return iso
  }
}

export default function EventFeed({ t, events }: { t: Strings; events: TrapEvent[] }) {
  const [q, setQ] = useState('')
  const boxRef = useRef<HTMLDivElement>(null)
  const [stick, setStick] = useState(true)

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    const list = [...events].reverse()
    if (!needle) return list.slice(0, 300)
    return list.filter((e) => `${e.ip} ${e.trap} ${e.detail} ${e.type} ${e.severity}`.toLowerCase().includes(needle)).slice(0, 300)
  }, [events, q])

  useEffect(() => {
    if (stick && boxRef.current) boxRef.current.scrollTop = 0
  }, [events.length, stick])

  return (
    <div className="panel">
      <h3>
        <span className="dot" /> {t.liveFeed} <span className="mono" style={{ color: 'var(--dim)' }}>({events.length})</span>
      </h3>
      <div className="row" style={{ marginBottom: 10 }}>
        <input className="txt" style={{ flex: 1 }} placeholder={t.search} value={q} onChange={(e) => setQ(e.target.value)} />
        <label style={{ fontSize: 12, color: 'var(--mut)', display: 'flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={stick} onChange={(e) => setStick(e.target.checked)} /> auto-scroll
        </label>
      </div>
      {filtered.length === 0 ? (
        <div className="empty">
          <span className="big">🕸️</span>
          {t.noEvents}
        </div>
      ) : (
        <div className="feed" ref={boxRef}>
          {filtered.map((e) => (
            <div key={e.id} className={`ev ${e.severity}`}>
              <div className="meta">
                <span className={`sev ${e.severity}`}>{e.severity}</span>
                <span className="ip">{e.ip}</span>
                <span>{e.trap}</span>
                <span>{fmtTime(e.time)}</span>
                <span>{e.type}</span>
                {e.meta?.demo === true && <span className="demo-tag">{t.demoBadge}</span>}
              </div>
              <div className="detail">{e.detail}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
