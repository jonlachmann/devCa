<script lang="ts">
  import { api, type Event, type Problem } from '../lib/api'
  import { resource } from '../lib/resource.svelte'
  import { ago } from '../lib/format'
  import Badge from '../lib/Badge.svelte'
  import Code from '../lib/Code.svelte'
  import Icon from '../lib/Icon.svelte'

  type Info = {
    directory: string
    accounts: { id: number; contact: string[] | null; status: string; internal: boolean; created: string; orders: number }[] | null
    orders:
      | {
          id: number
          accountId: number
          status: string
          identifiers: string[]
          created: string
          certId?: number
          error?: Problem
          authorizations: { identifier: string; status: string; challenges: { type: string; status: string; error?: Problem }[] }[]
        }[]
      | null
    failures: Event[] | null
  }
  type Step = { name: string; ok: boolean; detail?: string; hint?: string; ms: number }

  const info = resource<Info>('/api/acme', 4000)
  let d = $derived(info.data)

  let testHost = $state('')
  let testing = $state(false)
  let result = $state<{ ok: boolean; steps: Step[] } | { error: string } | null>(null)

  async function runTest(e: SubmitEvent) {
    e.preventDefault()
    testing = true
    result = null
    try {
      result = await api('POST', '/api/test/acme', { hostname: testHost.trim() })
    } catch (err) {
      result = { error: (err as Error).message }
    }
    testing = false
    info.reload()
  }

  const tone = (s: string) => (s === 'valid' ? 'ok' : s === 'invalid' ? 'bad' : s === 'pending' || s === 'processing' || s === 'ready' ? 'warn' : 'neutral')
</script>

<div class="page-head">
  <div>
    <h1>ACME</h1>
    <p>Point any ACME client at DevCA instead of Let's Encrypt.</p>
  </div>
</div>

{#if d}
  <div class="card">
    <h2>Directory URL</h2>
    <Code text={d.directory} />
    <p class="small muted">
      Supports the HTTP-01 challenge. Validation is <strong>local</strong>: DevCA checks the token over loopback, which proves the name points at this
      machine, not that it's reachable from the Internet. Clients need to trust DevCA's root (<code>devca trust install</code>), or pass
      <code>ca.pem</code> explicitly.
    </p>
    <details>
      <summary class="small">Example commands</summary>
      <h3 style="margin-top:.75rem">lego</h3>
      <Code text={`lego --server ${d.directory} --email you@example.com --domains app.localhost --http --http.port :5002 run`} />
      <h3>certbot</h3>
      <Code text={`certbot certonly --server ${d.directory} --standalone --http-01-port 5002 -d app.localhost`} />
      <p class="small muted">DevCA's gateway uses port 80, so run the client's challenge server on another port and set it as the service's validation port (<code>devca acme claim app.localhost --port 5002</code>).</p>
    </details>
  </div>

  <form class="card" onsubmit={runTest}>
    <h2>Test the ACME workflow</h2>
    <p class="small muted">Runs a real issuance against DevCA with an independent ACME client: account, order, HTTP-01 challenge served by DevCA's gateway, finalize, chain check, revoke.</p>
    <div class="actions">
      <input type="text" bind:value={testHost} placeholder="api.localhost" required style="max-width:20rem" />
      <button class="btn primary" disabled={testing}>{testing ? 'Running…' : 'Run test'}</button>
    </div>
    {#if result}
      {#if 'error' in result}
        <p class="error-text" style="margin-top:.75rem">{result.error}</p>
      {:else}
        <ul class="plain steps">
          {#each result.steps as s}
            <li>
              <span class:ok={s.ok} class:bad={!s.ok}><Icon name={s.ok ? 'check' : 'x'} size={16} /></span>
              <div>
                <strong>{s.name}</strong> <span class="muted small">{s.ms} ms</span>
                {#if s.detail}<div class="small" class:error-text={!s.ok}>{s.detail}</div>{/if}
                {#if s.hint}<div class="small hint">{s.hint}</div>{/if}
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  </form>

  {#if d.failures?.length}
    <div class="card">
      <h2>Recent failures</h2>
      <ul class="plain events">
        {#each d.failures as f}<li><span class="time">{ago(f.time)}</span><span>{f.message}</span></li>{/each}
      </ul>
    </div>
  {/if}

  <div class="card tight">
    <h2 class="pad">Orders</h2>
    {#if d.orders?.length}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Names</th><th>Status</th><th>Challenge</th><th>Account</th><th>Created</th></tr></thead>
          <tbody>
            {#each d.orders as o (o.id)}
              <tr>
                <td>
                  {#if o.certId}<a href={`#/certificates?${o.certId}`}>{o.identifiers.join(', ')}</a>{:else}{o.identifiers.join(', ')}{/if}
                  {#if o.error}<div class="small error-text">{o.error.detail}</div>{/if}
                </td>
                <td><Badge tone={tone(o.status)}>{o.status}</Badge></td>
                <td class="small">
                  {#each o.authorizations as a}
                    {#each a.challenges as c}<div>{c.type}: {c.status}</div>{/each}
                  {/each}
                </td>
                <td class="muted">#{o.accountId}</td>
                <td class="muted">{ago(o.created)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="empty">No orders yet.</div>
    {/if}
  </div>

  <div class="card tight">
    <h2 class="pad">Accounts</h2>
    {#if d.accounts?.length}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Account</th><th>Contact</th><th>Status</th><th>Orders</th><th>Created</th></tr></thead>
          <tbody>
            {#each d.accounts as a (a.id)}
              <tr>
                <td>#{a.id}</td>
                <td>{a.internal ? 'DevCA self-test' : a.contact?.join(', ') || '—'}</td>
                <td><Badge tone={a.status === 'valid' ? 'ok' : 'neutral'}>{a.status}</Badge></td>
                <td>{a.orders}</td>
                <td class="muted">{ago(a.created)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="empty">No ACME clients have registered yet.</div>
    {/if}
  </div>
{/if}

<style>
  .pad { padding: 1rem 1.15rem 0; }
  .steps { margin-top: 1rem; }
  .steps li { display: flex; gap: .6rem; padding: .35rem 0; }
  .ok { color: var(--ok); }
  .bad { color: var(--bad); }
  .hint { color: var(--warn); }
  details summary { cursor: pointer; }
</style>
