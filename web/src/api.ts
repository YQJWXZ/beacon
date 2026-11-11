// Minimal API client. The dashboard is same-origin with beacon-server, so the
// only auth is a bearer token kept in localStorage.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

const TOKEN_KEY = 'beacon.token'

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY) ?? '',
  set: (v: string) => localStorage.setItem(TOKEN_KEY, v),
  clear: () => localStorage.removeItem(TOKEN_KEY),
}

async function getJSON<T>(path: string): Promise<T> {
  const token = tokenStore.get()
  const res = await fetch(path, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (res.status === 401) {
    window.dispatchEvent(new Event('beacon:unauthorized'))
    throw new ApiError(401, '未授权：token 无效或已过期')
  }
  if (!res.ok) {
    const body = (await res.text()).trim()
    throw new ApiError(res.status, body || res.statusText || `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

export type LabelSet = Record<string, string>
export type PromValue = [number, string]
export interface PromSeries {
  metric: LabelSet
  value?: PromValue
  values?: PromValue[]
}
interface PromResponse {
  status: string
  data: { resultType: string; result: PromSeries[] }
}

export async function instant(q: string): Promise<PromSeries[]> {
  const r = await getJSON<PromResponse>('/api/v1/query?query=' + encodeURIComponent(q))
  return r.data.result
}

export async function range(q: string, start: number, end: number, step: number): Promise<PromSeries[]> {
  const p = new URLSearchParams({
    query: q,
    start: String(Math.floor(start)),
    end: String(Math.floor(end)),
    step: String(Math.floor(step)),
  })
  const r = await getJSON<PromResponse>('/api/v1/query_range?' + p.toString())
  return r.data.result
}

export interface Host {
  id: string
  name: string
  created_at: string
  last_seen: string
}

export async function hosts(): Promise<Host[]> {
  const r = await getJSON<{ hosts: Host[] | null }>('/api/v1/hosts')
  return r.hosts ?? []
}

export interface Alert {
  labels: LabelSet
  annotations: LabelSet
  startsAt: string
  endsAt: string
  status: { state: string; silencedBy?: string[] }
  fingerprint: string
}

export async function alerts(): Promise<Alert[]> {
  return getJSON<Alert[]>('/api/v1/alerts')
}

export interface AuditEvent {
  time: string
  host: string
  type: string
  severity: string
  data: unknown
}

export async function events(params: { host?: string; type?: string; limit?: number }): Promise<AuditEvent[]> {
  const p = new URLSearchParams()
  if (params.host) p.set('host', params.host)
  if (params.type) p.set('type', params.type)
  p.set('limit', String(params.limit ?? 200))
  const r = await getJSON<{ events: AuditEvent[] | null }>('/api/v1/events?' + p.toString())
  return r.events ?? []
}

// ---- helpers over Prometheus matrices ----

export function byHost(series: PromSeries[]): Map<string, number> {
  const out = new Map<string, number>()
  for (const s of series) {
    const host = s.metric.host
    if (!host || !s.value) continue
    out.set(host, Number(s.value[1]))
  }
  return out
}

export function scalar(series: PromSeries[]): number {
  const v = series[0]?.value
  return v ? Number(v[1]) : NaN
}

export function labels(series: PromSeries[]): LabelSet[] {
  return series.map((s) => s.metric)
}
