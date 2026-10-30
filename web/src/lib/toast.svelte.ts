export const toast = $state<{ message: string; kind: 'ok' | 'error' } | { message: ''; kind: 'ok' }>({ message: '', kind: 'ok' })
let timer: ReturnType<typeof setTimeout>

export function notify(message: string, kind: 'ok' | 'error' = 'ok') {
  toast.message = message
  toast.kind = kind
  clearTimeout(timer)
  timer = setTimeout(() => (toast.message = ''), kind === 'error' ? 7000 : 3000)
}

// Runs fn, reporting failures as a toast. Returns true on success.
export async function attempt(fn: () => Promise<unknown>, ok?: string): Promise<boolean> {
  try {
    await fn()
    if (ok) notify(ok)
    return true
  } catch (e) {
    notify((e as Error).message, 'error')
    return false
  }
}
