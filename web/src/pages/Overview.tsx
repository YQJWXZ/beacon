import { useEffect, useState } from 'react'
import { alerts, byHost, hosts, instant, type Alert, type Host } from '../api'
import { Card, Empty, ErrorBanner, Hero, Severity, Stat } from '../components/ui'
import { age, pct, shortHost, ts } from '../format'

interface Snapshot {
  cpu: Map<string, number>
  mem: Map<string, number>
  disk: Map<string, number>
  beat: Map<string, number>
  firing: Map<string, number>
}

export function Overview({ path }: { path: string }) {
  const [hostList, setHostList] = useState<Host[]>([])
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const [activeAlerts, setActiveAlerts] = useState<Alert[]>([])
  const [alertsDown, setAlertsDown] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true

    async function load() {
      let down = false
      try {
        const [hs, cpu, mem, disk, beat, firing, al] = await Promise.all([
          hosts(),
          instant('sum by (host)(beacon_cpu_usage_ratio{mode=~"user|system"})'),
          instant('beacon_mem_used_ratio'),
          instant('max by (host)(beacon_disk_used_ratio)'),
          instant('beacon_agent_heartbeat'),
          instant('sum by (host)(ALERTS{alertstate="firing"})'),
          // Alertmanager may be down; that must not blank the whole page.
          alerts().catch(() => {
            down = true
            return [] as Alert[]
          }),
        ])
        if (!alive) return
        setHostList(hs)
        setSnap({
          cpu: byHost(cpu),
          mem: byHost(mem),
          disk: byHost(disk),
          beat: byHost(beat),
          firing: byHost(firing),
        })
        setActiveAlerts(al)
        setAlertsDown(down)
        setErr("")
      } catch (e) {
        if (!alive) return
        setErr(e instanceof Error ? e.message : String(e))
      }
    }

    load()
    const t = setInterval(load, 15000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  const now = Date.now() / 1000
  const online = hostList.filter((h) => {
    const beat = snap?.beat.get(h.name) ?? snap?.beat.get(h.id)
    return beat !== undefined && now - beat < 120
  }).length
  const cpuValues = hostList
    .map((h) => snap?.cpu.get(h.name) ?? snap?.cpu.get(h.id))
    .filter((v): v is number => v !== undefined)
  const avgCPU = cpuValues.length ? cpuValues.reduce((a, b) => a + b, 0) / cpuValues.length : NaN

  return (
    <>
      <Hero
        eyebrow="Fleet Overview"
        title="主机与流量，一眼看完"
        lede="CPU、内存、磁盘、连接与审计状态。数据每 15 秒刷新一次，详情点进单机。"
      />

      {err && <ErrorBanner message={"加载失败：" + err} />}

      {hostList.length > 0 && (
        <div className="grid grid-4 stats">
          <Stat label="主机" value={String(hostList.length)} hint="已注册" />
          <Stat label="在线" value={String(online)} hint={online === hostList.length ? "全部正常" : "有主机失联"} />
          <Stat label="活跃告警" value={String(activeAlerts.length)} hint="来自 Alertmanager" />
          <Stat label="平均 CPU" value={pct(avgCPU)} hint="user + system" />
        </div>
      )}

      {hostList.length === 0 ? (
        <Empty>
          还没有主机上报。
          <br />
          在目标机器上执行 <code>beacon agent enroll</code> 后即可出现在这里。
        </Empty>
      ) : (
        <div className="host-grid">
          {hostList.map((h) => {
            const beat = snap?.beat.get(h.name) ?? snap?.beat.get(h.id)
            const heartbeatAge = beat ? now - beat : Infinity
            const up = heartbeatAge < 120
            const cpu = snap?.cpu.get(h.name) ?? snap?.cpu.get(h.id)
            const mem = snap?.mem.get(h.name) ?? snap?.mem.get(h.id)
            const disk = snap?.disk.get(h.name) ?? snap?.disk.get(h.id)
            const firing = snap?.firing.get(h.name) ?? snap?.firing.get(h.id) ?? 0

            return (
              <a className="card-link" href={`#/host/${encodeURIComponent(h.name)}`} key={h.id}>
                <Card>
                  <div className="host-card-head">
                    <span className={'dot ' + (up ? 'up' : 'down')} />
                    <span className="host-name" title={h.name}>
                      {shortHost(h.name)}
                    </span>
                    <span style={{ marginLeft: 'auto' }}>
                      {firing > 0 && <span className="badge P0">{firing} 告警</span>}
                    </span>
                  </div>
                  <div className="card-sub">{up ? age(heartbeatAge) : '失联 ' + age(heartbeatAge)}</div>

                  <Metric label="CPU" value={cpu} />
                  <Metric label="内存" value={mem} />
                  <Metric label="磁盘" value={disk} warnAt={0.85} />
                </Card>
              </a>
            )
          })}
        </div>
      )}

      <div className="section">
        <div className="section-head">
          <h2 className="section-title">活跃告警</h2>
          <span className="card-sub">
            {alertsDown ? '告警服务不可用' : `${activeAlerts.length} 条`}
          </span>
        </div>
        {alertsDown ? (
          <Empty>Alertmanager 未启动或未配置，暂时看不到告警状态</Empty>
        ) : activeAlerts.length === 0 ? (
          <Empty>当前没有活跃告警</Empty>
        ) : (
          <Card>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>级别</th>
                    <th>主机</th>
                    <th>规则</th>
                    <th>摘要</th>
                    <th>开始</th>
                  </tr>
                </thead>
                <tbody>
                  {activeAlerts.slice(0, 8).map((a) => (
                    <tr key={a.fingerprint}>
                      <td>
                        <Severity value={a.labels.severity} />
                      </td>
                      <td className="mono">{a.labels.host ?? '—'}</td>
                      <td>{a.labels.alertname}</td>
                      <td>{a.annotations.summary ?? a.annotations.description ?? '—'}</td>
                      <td className="mono muted">{ts(a.startsAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>
    </>
  )
}

function Metric({ label, value, warnAt = 0.9 }: { label: string; value?: number; warnAt?: number }) {
  const p = value ?? NaN
  const warn = Number.isFinite(p) && p >= warnAt
  return (
    <div>
      <div className="metric-row">
        <span>{label}</span>
        <span className="metric-value">{pct(value)}</span>
      </div>
      <div className={'bar' + (warn ? ' warn' : '')}>
        <span style={{ width: Number.isFinite(p) ? Math.min(100, p * 100) + '%' : '0%' }} />
      </div>
    </div>
  )
}
