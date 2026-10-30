<script lang="ts">
  import { api, download, type Cert } from '../lib/api'
  import { resource } from '../lib/resource.svelte'
  import { attempt } from '../lib/toast.svelte'
  import { date, daysLeft } from '../lib/format'
  import Badge from '../lib/Badge.svelte'
  import Copy from '../lib/Copy.svelte'
  import Icon from '../lib/Icon.svelte'

  const certs = resource<Cert[]>('/api/certs', 5000)
  let showAll = $state(false)
  let selectedId = $state<number | null>(Number(location.hash.split('?')[1]) || null)
  let detail = $state<Cert | null>(null)

  const isHistory = (c: Cert) =>
    c.status === 'revoked' || c.status === 'expired' || c.owner === 'test' || (c.owner.startsWith('service:') && !c.current)
  let list = $derived((certs.data ?? []).filter((c) => showAll || !isHistory(c)))
  let hidden = $derived((certs.data?.length ?? 0) - list.length)

  $effect(() => {
    if (selectedId == null) {
      detail = null
      return
    }
    api<Cert>('GET', `/api/certs/${selectedId}`).then((c) => (detail = c), () => (detail = null))
  })

  const tone = (s: Cert['status']) => (s === 'valid' ? 'ok' : s === 'expiring' ? 'warn' : 'bad')

  async function revoke(c: Cert) {
    const managed = c.owner.startsWith('service:') && c.current
    const msg = managed
      ? `Revoke the certificate for ${c.names[0]}? DevCA immediately issues a replacement with a new private key.`
      : `Revoke this certificate for ${c.names.join(', ')}? This can't be undone.`
    if (!confirm(msg)) return
    await attempt(() => api('POST', `/api/certs/${c.id}/revoke`), 'Certificate revoked')
    certs.reload()
    selectedId = null
  }
</script>

<div class="page-head">
  <div>
    <h1>Certificates</h1>
    <p>Everything DevCA has issued.</p>
  </div>
  <label class="check"><input type="checkbox" bind:checked={showAll} /> Show history {#if hidden && !showAll}<span class="muted">({hidden})</span>{/if}</label>
</div>

{#if detail}
  <div class="card">
    <div class="actions" style="justify-content:space-between">
      <h2 style="margin:0">{detail.names.join(', ')}</h2>
      <button class="btn ghost small" onclick={() => (selectedId = null)} aria-label="Close"><Icon name="x" size={16} /></button>
    </div>
    <dl class="kv" style="margin:.75rem 0 1rem">
      <dt>Status</dt><dd><Badge tone={tone(detail.status)}>{detail.status}</Badge></dd>
      <dt>Names (SANs)</dt><dd>{detail.names.join(', ')}</dd>
      <dt>Valid</dt><dd>{date(detail.notBefore)} – {date(detail.notAfter)} <span class="muted">({daysLeft(detail.notAfter)})</span></dd>
      <dt>Owner</dt><dd>{detail.ownerLabel}</dd>
      <dt>Issuer</dt><dd>{detail.issuer}</dd>
      <dt>Key</dt><dd>{detail.keyType}</dd>
      <dt>Serial</dt><dd class="mono">{detail.serial}</dd>
      <dt>SHA-256</dt><dd class="mono">{detail.fingerprint} <Copy text={detail.fingerprint} /></dd>
    </dl>
    <div class="actions">
      <button class="btn small" onclick={() => attempt(() => download(`/api/certs/${detail!.id}/download?part=cert`))}><Icon name="download" size={16} /> Certificate</button>
      <button class="btn small" onclick={() => attempt(() => download(`/api/certs/${detail!.id}/download?part=chain`))}><Icon name="download" size={16} /> With root</button>
      {#if detail.hasKey}
        <button class="btn small" onclick={() => attempt(() => download(`/api/certs/${detail!.id}/download?part=key`))}><Icon name="download" size={16} /> Private key</button>
        <button class="btn small" onclick={() => attempt(() => download(`/api/certs/${detail!.id}/download?part=bundle`))}><Icon name="download" size={16} /> Key + certificate</button>
      {/if}
      <span style="flex:1"></span>
      {#if detail.status !== 'revoked'}
        <button class="btn small danger" onclick={() => revoke(detail!)}>Revoke</button>
      {/if}
    </div>
    <details style="margin-top:1rem">
      <summary class="small muted">PEM</summary>
      <pre>{detail.pem}</pre>
    </details>
  </div>
{/if}

<div class="card tight">
  {#if list.length}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Hostname</th><th>Status</th><th>Expires</th><th>Owner</th><th>Key</th></tr></thead>
        <tbody>
          {#each list as c (c.id)}
            <tr class="clickable" class:selected={c.id === selectedId} onclick={() => (selectedId = c.id)}>
              <td><strong>{c.names.join(', ')}</strong></td>
              <td><Badge tone={tone(c.status)}>{c.status}</Badge></td>
              <td>{date(c.notAfter)}</td>
              <td class="muted">{c.ownerLabel}</td>
              <td class="muted">{c.keyType}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else if certs.data}
    <div class="empty">No certificates yet. Add a service and DevCA issues one right away.</div>
  {/if}
</div>

<style>
  tr.selected td { background: var(--accent-soft); }
  details summary { cursor: pointer; margin-bottom: .5rem; }
</style>
