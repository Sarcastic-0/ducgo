import { useMemo, useState } from 'react'
import type { TrapEvent, TrapStatus } from '../types'
import type { Strings } from '../i18n'
import { download, groupByIp, toCSV } from '../lib'
import EventFeed from './EventFeed'
import TrapsManager from './TrapsManager'
import AttackersTable from './AttackersTable'

export default function Dashboard({
  t,
  events,
  status,
  onRefresh,
  onLock,
  onChangePins
}: {
  t: Strings
  events: TrapEvent[]
  status: TrapStatus | null
  onRefresh: () => void
  onLock: () => void
  onChangePins: () => void
}) {
  const [showSettings, setShowSettings] = useState(false)
  const [cur, setCur] = useState('')
  const [nxt, setNxt] = useState('')
  const [nxtD, setNxtD] = useState('')
  const [msg, setMsg] = useState('')

  const stats = useMemo(() => {
    const today = new Date().toISOString().slice(0, 10)
    const touchesToday = events.filter((e) => e.time.slice(0, 10) === today && e.type !== 'system').length
    const uniq = groupByIp(events).length
    const byTrap = new Map<string, number>()
    for (const e of events) {
      if (e.type === 'system') continue
      byTrap.set(e.trap, (byTrap.get(e.trap) ?? 0) + 1)
    }
    let hot = '—'
    let hotN = 0
    for (const [k, v] of byTrap) {
      if (v > hotN) {
        hotN = v
        hot = k
      }
    }
    return { touchesToday, uniq, hot, hotN, canaries: status?.canaryCount ?? 0 }
  }, [events, status])

  async function simulate(): Promise<void> {
    await window.mirage.trapsSimulate()
    onRefresh()
  }

  function exportJSON(): void {
    download(`miragenet-${Date.now()}.json`, JSON.stringify(events, null, 2), 'application/json')
  }

  function exportCSV(): void {
    download(`miragenet-${Date.now()}.csv`, toCSV(events), 'text/csv')
  }

  async function savePins(): Promise<void> {
    setMsg('')
    const r = await window.mirage.authChange(cur, nxt, nxtD)
    setMsg(r.ok ? '✓ saved' : (r.error ?? 'failed'))
    if (r.ok) {
      setCur('')
      setNxt('')
      setNxtD('')
    }
  }

  return (
    <>
      <div className="cards">
        <div className="stat red">
          <div className="k">{t.touchesToday}</div>
          <div className="v">{stats.touchesToday}</div>
          <div className="s">events · system excluded</div>
        </div>
        <div className="stat amber">
          <div className="k">{t.uniqueIps}</div>
          <div className="v">{stats.uniq}</div>
          <div className="s">distinct remote IPs</div>
        </div>
        <div className="stat blue">
          <div className="k">{t.hotTrap}</div>
          <div className="v" style={{ fontSize: 16, wordBreak: 'break-all' }}>{stats.hot}</div>
          <div className="s">×{stats.hotN} touches</div>
        </div>
        <div className="stat">
          <div className="k">{t.canaries}</div>
          <div className="v">{stats.canaries}</div>
          <div className="s">active watchers</div>
        </div>
      </div>

      <div className="dash" style={{ padding: 0, maxWidth: 'none' }}>
        <div className="side">
          <TrapsManager t={t} status={status} onRefresh={onRefresh} />
          <div className="panel">
            <h3>⚙️ {t.settings}</h3>
            <div className="row">
              <button className="btn small" onClick={() => void simulate()}>
                ⚡ {t.simulate}
              </button>
              <span className="demo-tag">{t.demoBadge}</span>
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <button className="btn small ghost" onClick={exportJSON}>
                ⬇ {t.exportJson}
              </button>
              <button className="btn small ghost" onClick={exportCSV}>
                ⬇ {t.exportCsv}
              </button>
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <button className="btn small ghost" onClick={() => setShowSettings((s) => !s)}>
                🔑 {t.changePins}
              </button>
              <button className="btn small danger" onClick={onLock}>
                🔒 {t.logout}
              </button>
            </div>
            {showSettings && (
              <div style={{ marginTop: 12 }}>
                <div className="field">
                  <label>{t.currentPin}</label>
                  <input type="password" value={cur} onChange={(e) => setCur(e.target.value)} />
                </div>
                <div className="field">
                  <label>{t.newPin}</label>
                  <input type="password" value={nxt} onChange={(e) => setNxt(e.target.value)} />
                </div>
                <div className="field">
                  <label>{t.newDuress}</label>
                  <input type="password" value={nxtD} onChange={(e) => setNxtD(e.target.value)} />
                </div>
                <button className="btn small primary" onClick={() => void savePins()}>
                  {t.save}
                </button>
                {msg && <div className="mono" style={{ fontSize: 12, marginTop: 6 }}>{msg}</div>}
              </div>
            )}
          </div>
        </div>
        <div className="maincol">
          <EventFeed t={t} events={events} />
          <AttackersTable t={t} events={events} />
        </div>
      </div>
    </>
  )
}
