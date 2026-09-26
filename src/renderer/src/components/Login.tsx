import { useState } from 'react'
import type { Strings } from '../i18n'

export default function Login({ t, onAuth }: { t: Strings; onAuth: (kind: 'normal' | 'duress') => void }) {
  const [pin, setPin] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(): Promise<void> {
    setErr('')
    setBusy(true)
    try {
      const r = await window.mirage.authVerify(pin)
      if (!r.result) setErr(t.wrongPin)
      else {
        setPin('')
        onAuth(r.result)
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-card">
      <h2>🛡️ MirageNet</h2>
      <p className="sub">{t.tagline}</p>
      <div className="field">
        <label>{t.enterPin}</label>
        <input
          type="password"
          value={pin}
          maxLength={64}
          onChange={(e) => setPin(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') void submit()
          }}
          autoFocus
        />
      </div>
      {err && <div className="err">{err}</div>}
      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn primary" onClick={() => void submit()} disabled={busy || pin.length === 0}>
          {t.unlock}
        </button>
      </div>
    </div>
  )
}
