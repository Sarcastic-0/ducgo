import { useCallback, useEffect, useState } from 'react'
import type { TrapEvent, TrapStatus } from './types'
import { getStrings, type Lang } from './i18n'
import SetupPin from './components/SetupPin'
import Login from './components/Login'
import Dashboard from './components/Dashboard'
import DecoyView from './components/DecoyView'

type Screen = 'boot' | 'setup' | 'login' | 'dash' | 'decoy'

export default function App() {
  const [screen, setScreen] = useState<Screen>('boot')
  const [lang, setLang] = useState<Lang>('ar')
  const [events, setEvents] = useState<TrapEvent[]>([])
  const [status, setStatus] = useState<TrapStatus | null>(null)
  const t = getStrings(lang)

  useEffect(() => {
    document.documentElement.lang = lang
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr'
  }, [lang])

  const refresh = useCallback(async () => {
    try {
      const [ev, st] = await Promise.all([window.mirage.trapsEvents(1000), window.mirage.trapsStatus()])
      setEvents(ev)
      setStatus(st)
    } catch {
      /* backend not ready yet */
    }
  }, [])

  useEffect(() => {
    let off: (() => void) | null = null
    void (async () => {
      try {
        const s = await window.mirage.authStatus()
        setScreen(s.setup ? 'login' : 'setup')
        await refresh()
        // auto-start engine on boot for a live mesh
        try {
          await window.mirage.trapsStart()
          await refresh()
        } catch {
          /* ports may be busy — dashboard still works */
        }
        off = window.mirage.onTrapEvent((ev) => {
          setEvents((prev) => [...prev.slice(-1999), ev])
          setStatus((prev) => (prev ? { ...prev, eventCount: prev.eventCount + 1 } : prev))
        })
      } catch {
        setScreen('login')
      }
    })()
    return () => {
      if (off) off()
    }
  }, [refresh])

  return (
    <div className="app">
      <div className="grid-bg" />
      <header className="topbar">
        <div className="logo">🕸️</div>
        <div className="brand">
          <h1>
            Mirage<span className="net">Net</span>
          </h1>
          <p>{t.tagline}</p>
        </div>
        <div className="spacer" />
        {status && (
          <span className={`pill ${status.running ? 'live' : 'dead'}`}>
            {status.running ? `● ${t.running}` : `○ ${t.stopped}`} · :{status.tcpPorts.join(' :')} · ⏱ {status.uptimeSec}s
          </span>
        )}
        <button className="btn small ghost" onClick={() => setLang((l) => (l === 'ar' ? 'en' : 'ar'))}>
          🌐 {t.lang}
        </button>
      </header>

      {screen === 'boot' && (
        <div className="center">
          <div className="mono" style={{ color: 'var(--mut)' }}>
            …loading mesh
          </div>
        </div>
      )}
      {screen === 'setup' && (
        <div className="center">
          <SetupPin t={t} onDone={() => setScreen('login')} />
        </div>
      )}
      {screen === 'login' && (
        <div className="center">
          <Login
            t={t}
            onAuth={(kind) => {
              void refresh()
              setScreen(kind === 'duress' ? 'decoy' : 'dash')
            }}
          />
        </div>
      )}
      {screen === 'dash' && (
        <div style={{ padding: '16px 20px 30px', maxWidth: 1400, width: '100%', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Dashboard t={t} events={events} status={status} onRefresh={() => void refresh()} onLock={() => setScreen('login')} onChangePins={() => undefined} />
        </div>
      )}
      {screen === 'decoy' && <DecoyView t={t} onLock={() => setScreen('login')} />}

      <footer className="footer">MirageNet v1 · 100% passive tripwires · no offensive traffic · LAN-visible by design</footer>
    </div>
  )
}
