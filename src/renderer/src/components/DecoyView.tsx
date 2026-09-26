import type { Strings } from '../i18n'

export default function DecoyView({ t, onLock }: { t: Strings; onLock: () => void }) {
  return (
    <div className="center" style={{ flexDirection: 'column' }}>
      <div className="pill" style={{ marginBottom: 12 }}>
        {t.duressNote}
      </div>
      <div className="auth-card" style={{ width: 560, textAlign: 'center' }}>
        <div className="decoy" style={{ padding: 10 }}>
          <div className="shield">🛡️</div>
          <h2>{t.allClear} ✓</h2>
          <p style={{ color: 'var(--mut)' }}>{t.decoySub}</p>
          <div className="ok-grid">
            <div className="ok">✅ Network
              <br />0 threats</div>
            <div className="ok">✅ Files
              <br />0 changes</div>
            <div className="ok">✅ Logins
              <br />0 failed</div>
          </div>
          <div className="row" style={{ justifyContent: 'center', marginTop: 22 }}>
            <button className="btn" onClick={onLock}>
              {t.logout}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
