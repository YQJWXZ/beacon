import { useEffect, useState } from 'react'
import { tokenStore } from './api'
import { Nav } from './components/ui'
import { AlertsPage } from './pages/Alerts'
import { EventsPage } from './pages/Events'
import { HostPage } from './pages/Host'
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

  const hostMatch = path.match(/^\/host\/(.+)$/)

  return (
    <div className="shell">
      <Nav path={path} />
      <main className="main">
        {hostMatch ? (
          <HostPage host={decodeURIComponent(hostMatch[1])} />
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
