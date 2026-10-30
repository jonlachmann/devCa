// Every call carries X-DevCA: the server refuses API requests without it,
// which is what keeps other websites from driving DevCA (CSRF).
export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'X-DevCA': '1' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) throw new Error(data?.error ?? `HTTP ${res.status}`)
  return data as T
}

// Downloads go through fetch (for the header) and a blob URL.
export async function download(path: string) {
  const res = await fetch(path, { headers: { 'X-DevCA': '1' } })
  if (!res.ok) {
    const data = await res.json().catch(() => null)
    throw new Error(data?.error ?? `HTTP ${res.status}`)
  }
  const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '')?.[1] ?? 'download.pem'
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000) // some browsers read it after click() returns
}

export type Problem = { type: string; detail: string }
export type Event = { time: string; level: 'info' | 'warn' | 'error'; kind: string; message: string }
export type Health = { up: boolean; error?: string; checked: string }
export type TrustStatus = { trusted: boolean; detail: string; notes?: string[] }

export type Cert = {
  id: number
  names: string[]
  serial: string
  notBefore: string
  notAfter: string
  status: 'valid' | 'expiring' | 'expired' | 'revoked'
  owner: string
  ownerLabel: string
  keyType: string
  fingerprint: string
  issuer: string
  current: boolean
  hasKey: boolean
  pem?: string
}

export type Mode = 'proxy' | 'export' | 'acme'

export type Service = {
  hostname: string
  mode: Mode
  target?: string
  exportDir?: string
  validationPort?: number
  address?: string
  enabled: boolean
  autoRenew: boolean
  url?: string
  cert?: Cert
  health?: Health
  inHosts: boolean
  certDir?: string
  resolves: 'hosts' | 'browser' | 'missing'
}

export type Listener = { addr: string; error?: string }

export type Status = {
  version: string
  ca: { subject: string; fingerprint: string; notAfter: string; trust: TrustStatus }
  gateway: { enabled: boolean; listeners: Listener[]; httpPort: number; httpsPort: number }
  counts: Record<'services' | 'activeCerts' | 'expiring' | 'acmeFailures24h' | 'upstreamsDown' | 'upstreams', number>
  expiring: Cert[] | null
  recent: Event[] | null
  acmeDirectory: string
  mgmtURL: string
  dataDir: string
}

export type Settings = {
  httpPort: number
  httpsPort: number
  mgmtPort: number
  acmePort: number
  gatewayEnabled: boolean
  leafDays: number
  renewDays: number
  logLevel: string
  defaultSuffix: string
}
