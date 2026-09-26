import { groupByIp } from '../lib'
import type { TrapEvent } from '../types'
import type { Strings } from '../i18n'

export default function AttackersTable({ t, events }: { t: Strings; events: TrapEvent[] }) {
  const rows = groupByIp(events)
  return (
    <div className="panel">
      <h3>
        <span className="dot red" /> {t.attackers}
      </h3>
      {rows.length === 0 ? (
        <div className="empty">
          <span className="big">🌫️</span>
          {t.noAttackers}
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="atk">
            <thead>
              <tr>
                <th>{t.ip}</th>
                <th>{t.touches}</th>
                <th>{t.firstSeen}</th>
                <th>{t.lastSeen}</th>
                <th>{t.trap}</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 50).map((r) => (
                <tr key={r.ip}>
                  <td style={{ color: 'var(--em)' }}>{r.ip}</td>
                  <td>{r.count}</td>
                  <td>{new Date(r.first).toLocaleString()}</td>
                  <td>{new Date(r.last).toLocaleString()}</td>
                  <td style={{ fontSize: 11 }}>{r.traps.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
