import { useEffect, useMemo, useState } from 'react'
import type { EChartsOption } from 'echarts'
import { instant, range, type PromSeries } from '../api'
import { Chart } from '../components/Chart'
import { Card, Empty, ErrorBanner, RangeTabs } from '../components/ui'
import { areaGradient, PALETTE } from '../theme'
import { pct } from '../format'

const RANGES: Record<string, number> = { '15m': 900, '1h': 3600, '6h': 21600, '24h': 86400 }

interface Loaded {
  cpu: PromSeries[]
  mem: PromSeries[]
  disk: PromSeries[]
  netRx: PromSeries[]
  netTx: PromSeries[]
  ports: PromSeries[]
  flow: PromSeries[]
  fw: PromSeries[]
  fwReadable: PromSeries[]
}

export function HostPage({ host }: { host: string }) {
  const [rangeKey, setRangeKey] = useState('1h')
  const [data, setData] = useState<Loaded | null>(null)
  const [showAllPorts, setShowAllPorts] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    const seconds = RANGES[rangeKey]
    const end = Math.floor(Date.now() / 1000)
    const start = end - seconds
    const step = Math.max(15, Math.floor(seconds / 300))
    const h = JSON.stringify(host)

    async function load() {
      try {
        const [cpu, mem, disk, netRx, netTx, ports, flow, fw, fwReadable] = await Promise.all([
          range(`sum by (mode)(beacon_cpu_usage_ratio{host=${h},mode=~"user|system|iowait|steal"})`, start, end, step),
          range(`beacon_mem_used_ratio{host=${h}}`, start, end, step),
          range(`beacon_disk_used_ratio{host=${h}}`, start, end, step),
          range(`sum(rate(beacon_net_rx_bytes_total{host=${h},iface!~"lo|br-.*|veth.*|docker.*"}[1m]))*8`, start, end, step),
          range(`sum(rate(beacon_net_tx_bytes_total{host=${h},iface!~"lo|br-.*|veth.*|docker.*"}[1m]))*8`, start, end, step),
          instant(`beacon_port_listen_info{host=${h}}`),
          instant(`beacon_flow_conns{host=${h}}`),
          instant(`beacon_fw_risky_rules{host=${h}} or beacon_exposure_unexpected{host=${h}}`),
          instant(`beacon_fw_readable{host=${h}}`),
        ])
        if (!alive) return
        setData({ cpu, mem, disk, netRx, netTx, ports, flow, fw, fwReadable })
        setErr('')
      } catch (e) {
        if (alive) setErr(e instanceof Error ? e.message : String(e))
      }
    }

    load()
    const t = setInterval(load, 30000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [host, rangeKey])

  const opts = useMemo(() => (data ? buildOptions(data) : null), [data])

  return (
    <>
      <div className="section-head">
        <h1 className="display" style={{ fontSize: 34, margin: 0 }}>
          {host}
        </h1>
      </div>

      <RangeTabs value={rangeKey} onChange={setRangeKey} />
      {err && <ErrorBanner message={'查询失败：' + err} />}

      {!data || !opts ? (
        <Empty>加载中…</Empty>
      ) : (
        <>
          <div className="chart-grid">
            <Card title="CPU 使用率">
              <Chart option={opts.cpu} />
            </Card>
            <Card title="内存使用率">
              <Chart option={opts.mem} />
            </Card>
            <Card title="磁盘使用率">
              <Chart option={opts.disk} />
            </Card>
            <Card title="网络吞吐">
              <Chart option={opts.net} />
            </Card>
          </div>

          <div className="section">
            <div className="section-head">
              <h2 className="section-title">链路状态</h2>
            </div>
            <div className="grid grid-3">
              <Card title="连接">
                {data.flow.length === 0 ? (
                  <div className="muted">无数据（需要 root 读 conntrack）</div>
                ) : (
                  data.flow.map((s) => (
                    <div className="metric-row" key={s.metric.dir}>
                      <span>{s.metric.dir === 'in' ? '入站' : '出站'}</span>
                      <span className="metric-value">{s.value ? Number(s.value[1]).toFixed(0) : '—'}</span>
                    </div>
                  ))
                )}
              </Card>
              <Card title="防火墙 / 暴露面">
                {data.fwReadable[0]?.value?.[1] !== "1" ? (
                  <div className="muted">不可读（需要 root）</div>
                ) : data.fw.length === 0 ? (
                  <div className="muted">无风险项</div>
                ) : (
                  data.fw.map((s, i) => (
                    <div className="metric-row" key={i}>
                      <span>{s.metric.__name__ === 'beacon_fw_risky_rules' ? '高危规则' : '意外暴露'}</span>
                      <span className="metric-value">{s.value ? Number(s.value[1]).toFixed(0) : '—'}</span>
                    </div>
                  ))
                )}
              </Card>
              <Card title="监听端口">
                <div className="metric-value" style={{ fontSize: 32 }}>
                  {data.ports.length}
                </div>
                <div className="card-sub">见下表</div>
              </Card>
            </div>
          </div>

          <div className="section">
            <div className="section-head">
              <h2 className="section-title">监听端口</h2>
            </div>
            {data.ports.length === 0 ? (
              <Empty>没有端口数据</Empty>
            ) : (
              <Card>
                <div className="table-wrap">
                  <table className="data">
                    <thead>
                      <tr>
                        <th>协议</th>
                        <th>地址</th>
                        <th>端口</th>
                        <th>UID</th>
                        <th>进程</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(showAllPorts ? sortPorts(data.ports) : sortPorts(data.ports).slice(0, 20)).map((p, i) => (
                        <tr key={i}>
                          <td>{p.metric.proto}</td>
                          <td className="mono">{p.metric.addr}</td>
                          <td className="mono">{p.metric.port}</td>
                          <td className="mono">{p.metric.uid}</td>
                          <td>{p.metric.comm || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {data.ports.length > 20 && (
                  <div style={{ marginTop: 16 }}>
                    <button className="btn-ghost" onClick={() => setShowAllPorts((v) => !v)}>
                      {showAllPorts ? "只显示前 20 条" : `显示全部  条`}
                    </button>
                  </div>
                )}
              </Card>
            )}
          </div>
        </>
      )}
    </>
  )
}

function sortPorts(series: PromSeries[]): PromSeries[] {
  return [...series].sort((a, b) => Number(a.metric.port) - Number(b.metric.port))
}

function buildOptions(d: Loaded) {
  return {
    cpu: cpuOption(d.cpu),
    mem: simpleOption(d.mem, '内存', 100),
    disk: diskOption(d.disk),
    net: netOption(d.netRx, d.netTx),
  }
}

function cpuOption(series: PromSeries[]): EChartsOption {
  const modes = ['user', 'system', 'iowait', 'steal']
  return {
    tooltip: { trigger: 'axis', valueFormatter: (v) => (v as number).toFixed(1) + '%' },
    legend: { top: 0, right: 0 },
    xAxis: { type: 'time' },
    yAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } },
    series: modes
      .map((mode, i) => {
        const s = series.find((x) => x.metric.mode === mode)
        return {
          name: mode,
          type: 'line' as const,
          stack: 'cpu',
          showSymbol: false,
          smooth: true,
          lineStyle: { width: 1.5 },
          areaStyle: { color: areaGradient(PALETTE[i % PALETTE.length]), opacity: 0.55 },
          data: (s?.values ?? []).map(([t, v]) => [t * 1000, Number(v) * 100]),
        }
      })
      .filter((s) => s.data.length > 0),
  }
}

function simpleOption(series: PromSeries[], name: string, scale: number): EChartsOption {
  const s = series[0]
  return {
    tooltip: { trigger: 'axis', valueFormatter: (v) => (v as number).toFixed(1) + '%' },
    xAxis: { type: 'time' },
    yAxis: { type: 'value', max: scale, axisLabel: { formatter: '{value}%' } },
    series: [
      {
        name,
        type: 'line',
        showSymbol: false,
        smooth: true,
        lineStyle: { width: 2, color: PALETTE[0] },
        areaStyle: { color: areaGradient(PALETTE[0]) },
        data: (s?.values ?? []).map(([t, v]) => [t * 1000, Number(v) * 100]),
      },
    ],
  }
}

function diskOption(series: PromSeries[]): EChartsOption {
  return {
    tooltip: { trigger: 'axis', valueFormatter: (v) => (v as number).toFixed(1) + '%' },
    legend: { top: 0, right: 0 },
    xAxis: { type: 'time' },
    yAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } },
    series: series.map((s, i) => ({
      name: s.metric.mount ?? 'disk',
      type: 'line' as const,
      showSymbol: false,
      lineStyle: { width: 2, color: PALETTE[i % PALETTE.length] },
      data: (s.values ?? []).map(([t, v]) => [t * 1000, Number(v) * 100]),
    })),
  }
}

function netOption(rx: PromSeries[], tx: PromSeries[]): EChartsOption {
  const toData = (s: PromSeries[]) => (s[0]?.values ?? []).map(([t, v]) => [t * 1000, Number(v)])
  return {
    tooltip: {
      trigger: 'axis',
      valueFormatter: (v) => {
        const n = Number(v)
        return n >= 1e6 ? (n / 1e6).toFixed(2) + ' Mbps' : (n / 1e3).toFixed(1) + ' Kbps'
      },
    },
    legend: { top: 0, right: 0 },
    xAxis: { type: 'time' },
    yAxis: { type: 'value', axisLabel: { formatter: (v: number) => (v >= 1e6 ? v / 1e6 + 'M' : v / 1e3 + 'K') } },
    series: [
      {
        name: '入站',
        type: 'line',
        showSymbol: false,
        smooth: true,
        lineStyle: { width: 2, color: PALETTE[1] },
        areaStyle: { color: areaGradient(PALETTE[1]) },
        data: toData(rx),
      },
      {
        name: '出站',
        type: 'line',
        showSymbol: false,
        smooth: true,
        lineStyle: { width: 2, color: PALETTE[0] },
        data: toData(tx),
      },
    ],
  }
}

export { pct }
