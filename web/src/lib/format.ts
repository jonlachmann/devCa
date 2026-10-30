export function date(s: string) {
  return new Date(s).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function ago(s: string) {
  const sec = Math.round((Date.now() - new Date(s).getTime()) / 1000)
  if (sec < 60) return 'just now'
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`
  return date(s)
}

export function daysLeft(s: string) {
  const d = Math.floor((new Date(s).getTime() - Date.now()) / 86400000)
  if (d < 0) return 'expired'
  if (d === 0) return 'expires today'
  return `${d} day${d === 1 ? '' : 's'} left`
}

export const modeLabel = { proxy: 'Proxy', export: 'Files', acme: 'ACME client' } as const
