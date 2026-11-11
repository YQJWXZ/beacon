import { useEffect, useState } from 'react'
import { alerts, ApiError, silence, type Alert } from '../api'
import { Card, Empty, ErrorBanner, Pager, Severity } from '../components/ui'
import { ts } from '../format'

const PAGE_SIZE = 10

export function AlertsPage() {
  const [rows, setRows] = useState<Alert[]>([])
  const [err, setErr] = useState('')
  const [loaded, setLoaded] = useState(false)
  const [page, setPage] = useState(1)
  const [refresh, setRefresh] = useState(0)
  const [pending, setPending] = useState<string | null>(null)

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
  }, [refresh])

  const sorted = [...rows].sort((a, b) => rank(a) - rank(b))
  const pages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE))
  const safePage = Math.min(page, pages)
  const visible = sorted.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE)

  async function onSilence(a: Alert) {
    const host = a.labels.host
    const alert = a.labels.alertname
    if (!host || !alert) return
    setPending(a.fingerprint)
    try {
      await silence(host, alert, '1h')
      setRefresh((v) => v + 1)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setPending(null)
    }
  }

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
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((a) => (
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
                    <td className="mono">{a.status.silencedBy?.length ? "已静默" : a.status.state}</td>
                    <td>
                      <button
                        className="btn-ghost"
                        disabled={pending === a.fingerprint || Boolean(a.status.silencedBy?.length)}
                        onClick={() => onSilence(a)}
                      >
                        {a.status.silencedBy?.length
                          ? "已静默"
                          : pending === a.fingerprint
                            ? "处理中…"
                            : "静默 1h"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={safePage} pageSize={PAGE_SIZE} total={sorted.length} onChange={setPage} />
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
