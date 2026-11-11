import { useState } from 'react'
import { hosts, tokenStore } from '../api'
import { ErrorBanner } from '../components/ui'

export function Login({ onDone }: { onDone: () => void }) {
  const [token, setToken] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setErr('')
    tokenStore.set(token.trim())
    try {
      await hosts()
      onDone()
    } catch (e) {
      tokenStore.clear()
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="grid-backdrop" aria-hidden="true" />
      <div className="card login-card">
        <div className="eyebrow">Beacon Console</div>
        <h1 className="login-title">接入中心</h1>
        <p className="lede" style={{ marginBottom: 20, fontSize: 15 }}>
          输入中心的 enroll token（与 <code>BEACON_ENROLL_TOKEN</code> 相同），仅保存在本机浏览器。
        </p>
        {err && <ErrorBanner message={err} />}
        <form onSubmit={submit}>
          <label className="field-label" htmlFor="token">
            管理员 Token
          </label>
          <input
            id="token"
            className="input"
            type="password"
            autoFocus
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="enroll token"
          />
          <div style={{ marginTop: 16 }}>
            <button className="btn" disabled={busy || token.trim() === ''}>
              {busy ? '验证中…' : '进入'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
