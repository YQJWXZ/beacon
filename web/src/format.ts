export function pct(v: number | undefined): string {
  if (v === undefined || Number.isNaN(v)) return '—'
  return (v * 100).toFixed(1) + '%'
}

export function bps(v: number | undefined): string {
  if (v === undefined || Number.isNaN(v)) return '—'
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps']
  let n = v
  let i = 0
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000
    i++
  }
  return n.toFixed(n >= 100 ? 0 : 1) + ' ' + units[i]
}

export function age(seconds: number): string {
  if (!Number.isFinite(seconds)) return '未知'
  if (seconds < 60) return Math.round(seconds) + ' 秒前'
  if (seconds < 3600) return Math.round(seconds / 60) + ' 分钟前'
  if (seconds < 86400) return Math.round(seconds / 3600) + ' 小时前'
  return Math.round(seconds / 86400) + ' 天前'
}

export function shortHost(host: string): string {
  return host.length > 16 ? host.slice(0, 8) + '…' + host.slice(-4) : host
}

export function ts(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString('zh-CN', { hour12: false })
}
