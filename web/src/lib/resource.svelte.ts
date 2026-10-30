import { api } from './api'

// A polled GET endpoint. Call during component init; polling stops on unmount.
export function resource<T>(path: string, everyMs = 3000) {
  let data = $state<T>()
  let error = $state<string>()
  async function reload() {
    try {
      data = await api<T>('GET', path)
      error = undefined
    } catch (e) {
      error = (e as Error).message
    }
  }
  $effect(() => {
    reload()
    const t = setInterval(reload, everyMs)
    return () => clearInterval(t)
  })
  return {
    get data() { return data },
    get error() { return error },
    reload,
  }
}
