import { useEffect, useState } from 'react'
import { events, type AuditEvent } from '../api'
import { Card, Empty, ErrorBanner, Pager, Severity } from '../components/ui'
import { ts } from '../format'

const PAGE_SIZE = 20

export function EventsPage() {
  const [rows, setRows] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [type, setType] = useState('')
  const [host, setHost] = useState('')
  const [err, setErr] = useState('')
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    let alive = true
    async function load() {
      try {
        const res = await events({
          host: host || undefined,
          type: type || undefined,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        })
        if (!alive) return
        setRows(res.events)
        setTotal(res.total)
        setErr('')
      } catch (e) {
        if (!alive) return
        setErr(e instanceof Error ? e.message : String(e))
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
  }, [type, host, page])

  return (
    <>
      <div className="section-head">
        <h1 className="display" style={{ fontSize: 34, margin: 0 }}>
          审计事件
        </h1>
        <span className="card-sub">共 {total} 条</span>
      </div>

      <div className="tabs">
        <input
          className="input"
          style={{ maxWidth: 220 }}
          placeholder="按主机过滤"
          value={host}
          onChange={(e) => {
            setHost(e.target.value)
            setPage(1)
          }}
        />
        <input
          className="input"
          style={{ maxWidth: 220 }}
          placeholder="按类型过滤，如 port_added"
          value={type}
          onChange={(e) => {
            setType(e.target.value)
            setPage(1)
          }}
        />
      </div>

      {err && <ErrorBanner message={'加载失败：' + err} />}
      {loaded && !err && rows.length === 0 && <Empty>没有匹配的事件</Empty>}

      {rows.length > 0 && (
        <Card>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>级别</th>
                  <th>主机</th>
                  <th>类型</th>
                  <th>详情</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e, i) => (
                  <tr key={`${e.time}-${i}`}>
                    <td className="mono muted">{ts(e.time)}</td>
                    <td>
                      <Severity value={e.severity} />
                    </td>
                    <td className="mono">{e.host}</td>
                    <td>{e.type}</td>
                    <td>
                      <details>
                        <summary className="mono" style={{ cursor: 'pointer' }}>
                          展开
                        </summary>
                        <pre className="mono" style={{ whiteSpace: 'pre-wrap', margin: '8px 0 0' }}>
                          {JSON.stringify(e.data, null, 2)}
                        </pre>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} pageSize={PAGE_SIZE} total={total} onChange={setPage} />
        </Card>
      )}
    </>
  )
}
