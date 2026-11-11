import { useEffect, useState } from 'react'
import { alerts, ApiError, type Alert } from '../api'
import { Card, Empty, ErrorBanner, Severity } from '../components/ui'
import { ts } from '../format'

export function AlertsPage() {
  const [rows, setRows] = useState<Alert[]>([])
  const [err, setErr] = useState('')
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    let alive = true
    async function load() {
      try {
        const a = await alerts()
        if (!alive) return
        setRows(a)
        setErr('')
      } catch (e) {
        if (!alive) return
        if (e instanceof ApiError && (e.status === 502 || e.status === 503)) {
          setErr('告警服务不可用（Alertmanager 未启动或未配置）')
        } else {
          setErr(e instanceof Error ? e.message : String(e))
        }
      } finally {
        if (alive) setLoaded(true)
      }
    }
    load()
    const t = setInterval(load, 30000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  const sorted = [...rows].sort((a, b) => rank(a) - rank(b))

  return (
    <>
      <div className="section-head">
        <h1 className="display" style={{ fontSize: 34, margin: 0 }}>
          告警
        </h1>
        <span className="card-sub">{rows.length} 条活跃</span>
      </div>

      {err && <ErrorBanner message={'加载失败：' + err} />}
      {loaded && !err && rows.length === 0 && <Empty>没有活跃告警</Empty>}

      {rows.length > 0 && (
        <Card>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>级别</th>
                  <th>规则</th>
                  <th>主机</th>
                  <th>摘要</th>
                  <th>开始</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((a) => (
                  <tr key={a.fingerprint}>
                    <td>
                      <Severity value={a.labels.severity} />
                    </td>
                    <td>{a.labels.alertname}</td>
                    <td className="mono">{a.labels.host ?? '—'}</td>
                    <td>
                      {a.annotations.summary ?? '—'}
                      {a.annotations.description && (
                        <div className="card-sub" style={{ marginTop: 4 }}>
                          {a.annotations.description}
                        </div>
                      )}
                    </td>
                    <td className="mono muted">{ts(a.startsAt)}</td>
                    <td className="mono">{a.status.silencedBy?.length ? '已静默' : a.status.state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </>
  )
}

function rank(a: Alert): number {
  switch (a.labels.severity) {
    case 'P0':
      return 0
    case 'P1':
      return 1
    default:
      return 2
  }
}
