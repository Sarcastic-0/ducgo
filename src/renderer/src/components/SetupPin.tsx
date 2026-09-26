import { useState } from 'react'
import type { Strings } from '../i18n'

export default function SetupPin({ t, onDone }: { t: Strings; onDone: () => void }) {
  const [pin, setPin] = useState('')
  const [duress, setDuress] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(): Promise<void> {
    setErr('')
    setBusy(true)
    try {
      const r = await window.mirage.authSetup(pin, duress)
      if (!r.ok) setErr(r.error ?? 'Failed')
      else onDone()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-card">
      <h2>🛡️ {t.setupTitle}</h2>
      <p className="sub">{t.setupSub}</p>
      <div className="field">
        <label>{t.pin}</label>
        <input type="password" value={pin} onChange={(e) => setPin(e.target.value)} maxLength={64} />
      </div>
      <div className="field">
        <label>{t.duress}</label>
        <input type="password" value={duress} onChange={(e) => setDuress(e.target.value)} maxLength={64} />
      </div>
      <div className="hint">⚠️ {t.pinHint}</div>
      {err && <div className="err">{err}</div>}
      <div className="row" style={{ marginTop: 14 }}>
        <button className="btn primary" onClick={() => void submit()} disabled={busy}>
          {t.create}
        </button>
      </div>
    </div>
  )
}
