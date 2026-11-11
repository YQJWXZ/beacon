import { lazy, Suspense, useEffect, useState } from 'react'
import { tokenStore } from './api'
import { Nav } from './components/ui'
import { AlertsPage } from './pages/Alerts'
import { EventsPage } from './pages/Events'
import { Login } from './pages/Login'
import { Overview } from './pages/Overview'

function currentPath(): string {
  const raw = location.hash.replace(/^#/, '')
  return raw === '' ? '/' : raw
}

export function App() {
  const [path, setPath] = useState(currentPath())
  const [authed, setAuthed] = useState(() => tokenStore.get() !== '')

  useEffect(() => {
    const onHash = () => setPath(currentPath())
    const onUnauthorized = () => {
      tokenStore.clear()
      setAuthed(false)
    }
    window.addEventListener('hashchange', onHash)
    window.addEventListener('beacon:unauthorized', onUnauthorized)
    return () => {
      window.removeEventListener('hashchange', onHash)
      window.removeEventListener('beacon:unauthorized', onUnauthorized)
    }
  }, [])

  if (!authed) {
    return (
      <Login onDone={() => setAuthed(true)} />
    )
  }

  const HostPage = lazy(() => import('./pages/Host').then((m) => ({ default: m.HostPage })))

const hostMatch = path.match(/^\/host\/(.+)$/)

  return (
    <div className="shell">
      <Nav path={path} />
      <main className="main">
        {hostMatch ? (
          <Suspense fallback={<div className="empty">加载图表…</div>}>
            <HostPage host={decodeURIComponent(hostMatch[1])} />
          </Suspense>
        ) : path.startsWith('/alerts') ? (
          <AlertsPage />
        ) : path.startsWith('/events') ? (
          <EventsPage />
        ) : (
          <Overview path={path} />
        )}
      </main>
    </div>
  )
}
