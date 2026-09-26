import { useState } from 'react'
import type { TrapStatus } from '../types'
import type { Strings } from '../i18n'

export default function TrapsManager({
  t,
  status,
  onRefresh
}: {
  t: Strings
  status: TrapStatus | null
  onRefresh: () => void
}) {
  const [port, setPort] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  async function toggle(): Promise<void> {
    setBusy(true)
    setMsg('')
    try {
      if (status?.running) await window.mirage.trapsStop()
      else await window.mirage.trapsStart()
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  async function add(): Promise<void> {
    const p = Number(port)
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      setMsg('Port must be 1–65535')
      return
    }
    setBusy(true)
    try {
      const r = await window.mirage.trapsAddPort(p)
      setMsg(r.ok ? `+ ${p}` : (r.error ?? 'failed'))
      setPort('')
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  async function remove(p: number): Promise<void> {
    setBusy(true)
    try {
      await window.mirage.trapsRemovePort(p)
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  async function deploy(): Promise<void> {
    setBusy(true)
    setMsg('')
    try {
      const r = await window.mirage.trapsDeployCanaries()
      setMsg(r.ok ? `✓ ${r.dir} (${r.files.join(', ')})` : (r.error ?? 'cancelled'))
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel">
      <h3>
        <span className={`dot ${status?.running ? '' : 'red'}`} /> {t.trapsMgr}
      </h3>
      <div className="row" style={{ marginBottom: 10 }}>
        <span className="pill" style={{ fontFamily: 'var(--sans)' }}>
          {t.engine}: {status?.running ? t.running : t.stopped}
        </span>
        <button className={`btn small ${status?.running ? 'danger' : 'primary'}`} onClick={() => void toggle()} disabled={busy}>
          {status?.running ? t.stop : t.start}
        </button>
      </div>
      <div style={{ fontSize: 12, color: 'var(--mut)', marginBottom: 6 }}>{t.ports}</div>
      <div className="row" style={{ marginBottom: 10 }}>
        {(status?.tcpPorts ?? []).map((p) => (
          <span key={p} className="port-chip">
            :{p}
            <button title="remove" onClick={() => void remove(p)}>
              ✕
            </button>
          </span>
        ))}
        {(status?.tcpPorts ?? []).length === 0 && <span style={{ color: 'var(--dim)', fontSize: 12 }}>—</span>}
      </div>
      <div className="row" style={{ marginBottom: 10 }}>
        <input className="txt" placeholder="e.g. 3306" value={port} onChange={(e) => setPort(e.target.value)} style={{ width: 120 }} />
        <button className="btn small" onClick={() => void add()} disabled={busy}>
          {t.addPort}
        </button>
      </div>
      <div style={{ fontSize: 12, color: 'var(--mut)', marginBottom: 6 }}>
        {t.httpPanel} · <span className="mono">{t.openPanel}</span>
      </div>
      <div className="row">
        <button className="btn small ghost" onClick={() => void deploy()} disabled={busy}>
          📁 {t.deploy}
        </button>
      </div>
      <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 6 }}>{t.deployHint}</div>
      {msg && (
        <div className="mono" style={{ fontSize: 11, color: 'var(--em)', marginTop: 8, wordBreak: 'break-all' }}>
          {msg}
        </div>
      )}
      {status?.canaryDir && (
        <div className="mono" style={{ fontSize: 11, color: 'var(--mut)', marginTop: 6, wordBreak: 'break-all' }}>
          🐤 {status.canaryDir} ({status.canaryCount} watchers)
        </div>
      )}
    </div>
  )
}
