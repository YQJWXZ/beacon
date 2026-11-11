import type { ReactNode } from 'react'

export function Nav({ path }: { path: string }) {
  const links = [
    { href: '#/', label: '总览' },
    { href: '#/alerts', label: '告警' },
    { href: '#/events', label: '事件' },
  ]
  return (
    <header className="nav">
      <span className="brand">BEACON</span>
      <nav className="nav-links">
        {links.map((l) => (
          <a
            key={l.href}
            className={'nav-link' + (isActive(path, l.href) ? ' active' : '')}
            href={l.href}
          >
            {l.label}
          </a>
        ))}
      </nav>
      <span className="nav-spacer" />
      <button
        className="tab"
        onClick={() => {
          localStorage.removeItem('beacon.token')
          location.reload()
        }}
      >
        退出
      </button>
    </header>
  )
}

function isActive(path: string, href: string): boolean {
  if (href === '#/') return path === '/' || path.startsWith('/host')
  return path.startsWith(href.slice(1))
}

export function Hero({ eyebrow, title, lede }: { eyebrow: string; title: string; lede: string }) {
  return (
	<section className="hero">
      <div className="grid-backdrop" aria-hidden="true" />
      <div className="hero-content">
        <div className="eyebrow">{eyebrow}</div>
        <h1 className="display">{title}</h1>
        <p className="lede">{lede}</p>
      </div>
    </section>
  )
}

export function Card({
  title,
  sub,
  children,
  className = '',
}: {
  title?: string
  sub?: string
  children: ReactNode
  className?: string
}) {
  return (
    <section className={'card ' + className}>
      {title && <h2 className="card-title">{title}</h2>}
      {sub && <div className="card-sub">{sub}</div>}
      {children}
    </section>
  )
}

export function Severity({ value }: { value?: string }) {
  const v = (value || 'P2').toUpperCase()
  return <span className={`badge ${v}`}>{v}</span>
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="error-banner">{message}</div>
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function RangeTabs({
  value,
  onChange,
}: {
  value: string
  onChange: (v: string) => void
}) {
  const ranges = [
    ['15m', '15 分钟'],
    ['1h', '1 小时'],
    ['6h', '6 小时'],
    ['24h', '24 小时'],
  ]
  return (
    <div className="tabs" role="tablist">
      {ranges.map(([key, label]) => (
        <button
          key={key}
          role="tab"
          aria-selected={value === key}
          className={'tab' + (value === key ? ' active' : '')}
          onClick={() => onChange(key)}
        >
          {label}
        </button>
      ))}
    </div>
  )
}

export function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="card stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  )
}
