<script lang="ts">
  import { api, type Mode, type Service, type Settings } from '../lib/api'
  import { resource } from '../lib/resource.svelte'
  import { attempt } from '../lib/toast.svelte'
  import { daysLeft, modeLabel } from '../lib/format'
  import Icon from '../lib/Icon.svelte'
  import Badge from '../lib/Badge.svelte'
  import Code from '../lib/Code.svelte'

  const services = resource<Service[]>('/api/services')
  const settings = resource<{ settings: Settings }>('/api/settings', 60000)
  let suffix = $derived(settings.data?.settings.defaultSuffix ?? 'localhost')

  let adding = $state(location.hash.includes('?new'))
  let form = $state({ hostname: '', mode: 'proxy' as Mode, target: '', exportDir: '', validationPort: '', address: '', passthrough: '' })
  let busy = $state(false)
  let expanded = $state<string | null>(null)

  const modes: { id: Mode; title: string; text: string }[] = [
    { id: 'proxy', title: 'Proxy', text: 'DevCA serves HTTPS and forwards to your app.' },
    { id: 'export', title: 'Files', text: 'Your app does TLS with certificate files DevCA keeps fresh.' },
    { id: 'acme', title: 'ACME client', text: 'Your own ACME client (lego, certbot, Caddy…) gets certificates.' },
  ]

  // Typing "api" means "api.localhost".
  function fullHost(h: string) {
    h = h.trim().toLowerCase()
    return h && !h.includes('.') ? `${h}.${suffix}` : h
  }

  async function create(e: SubmitEvent) {
    e.preventDefault()
    busy = true
    const ok = await attempt(
      () =>
        api('POST', '/api/services', {
          hostname: fullHost(form.hostname),
          mode: form.mode,
          target: form.target,
          exportDir: form.exportDir,
          validationPort: Number(form.validationPort) || 0,
          address: form.mode === 'proxy' ? '' : form.address,
          passthrough: form.mode === 'proxy' ? '' : form.passthrough,
        }),
      `Added ${fullHost(form.hostname)}`,
    )
    busy = false
    if (ok) {
      expanded = fullHost(form.hostname)
      form = { hostname: '', mode: form.mode, target: '', exportDir: '', validationPort: '', address: '', passthrough: '' }
      adding = false
      services.reload()
    }
  }

  // Bumped after a rejected update so inputs re-render from server state
  // instead of keeping the value the server refused.
  let rev = $state(0)

  async function update(v: Service, patch: Partial<Service>) {
    const next = { ...v, ...patch }
    const ok = await attempt(() =>
      api('PUT', `/api/services/${v.hostname}`, {
        mode: next.mode,
        target: next.target ?? '',
        exportDir: next.exportDir ?? '',
        validationPort: next.validationPort ?? 0,
        address: next.address ?? '',
        passthrough: next.passthrough ?? '',
        enabled: next.enabled,
        autoRenew: next.autoRenew,
      }),
    )
    await services.reload()
    if (!ok) rev++
  }

  // Proxy mode needs a target, which Files/ACME services don't have yet.
  function changeMode(v: Service, mode: Mode) {
    let target = v.target ?? ''
    if (mode === 'proxy' && !target) {
      target = prompt(`Proxy ${v.hostname} to which port or address on this computer?`, '3000')?.trim() ?? ''
      if (!target) {
        rev++
        return
      }
    }
    update(v, { mode, target, address: mode === 'proxy' ? '' : v.address })
  }

  async function renew(v: Service) {
    await attempt(() => api('POST', `/api/services/${v.hostname}/renew`), `Renewed ${v.hostname}`)
    services.reload()
  }

  async function remove(v: Service) {
    if (!confirm(`Remove ${v.hostname}? DevCA stops serving and renewing it. Files in a custom export directory are left alone.`)) return
    await attempt(() => api('DELETE', `/api/services/${v.hostname}`), `Removed ${v.hostname}`)
    services.reload()
  }
</script>

<div class="page-head">
  <div>
    <h1>Services</h1>
    <p>Hostnames DevCA provides HTTPS for.</p>
  </div>
  {#if !adding}
    <button class="btn primary" onclick={() => (adding = true)}><Icon name="plus" size={16} /> Add service</button>
  {/if}
</div>

{#if adding}
  <form class="card" onsubmit={create}>
    <h2>Add a service</h2>
    <div class="field">
      <label for="host">Hostname</label>
      <input id="host" type="text" bind:value={form.hostname} placeholder={`app.${suffix}`} autocomplete="off" spellcheck="false" required />
      {#if form.hostname && fullHost(form.hostname) !== form.hostname.trim().toLowerCase()}
        <div class="hint">Will be <strong>{fullHost(form.hostname)}</strong></div>
      {:else}
        <div class="hint">
          Must end in .localhost or .local. <strong>.localhost</strong> works in Chrome, Firefox and Edge without any setup.
        </div>
      {/if}
    </div>
    <div class="field">
      <span class="label">How does your app use it?</span>
      <div class="segmented" role="radiogroup" aria-label="Mode">
        {#each modes as m}
          <button type="button" role="radio" aria-checked={form.mode === m.id} class:active={form.mode === m.id} onclick={() => (form.mode = m.id)}>
            <strong>{m.title}</strong><span>{m.text}</span>
          </button>
        {/each}
      </div>
    </div>
    {#if form.mode === 'proxy'}
      <div class="field">
        <label for="target">Your app's port or address</label>
        <input id="target" type="text" bind:value={form.target} placeholder="3000" autocomplete="off" required />
        <div class="hint">For example <code>3000</code> or <code>http://127.0.0.1:8080</code>. Only addresses on this computer are allowed.</div>
      </div>
    {:else if form.mode === 'export'}
      <div class="field">
        <label for="dir">Also write files to <span class="muted">(optional)</span></label>
        <input id="dir" type="text" bind:value={form.exportDir} placeholder="/path/to/your/app/certs" autocomplete="off" />
        <div class="hint">Absolute path. Files are always available in DevCA's data directory too.</div>
      </div>
    {:else}
      <div class="field">
        <label for="vport">HTTP-01 validation port <span class="muted">(optional)</span></label>
        <input id="vport" type="number" min="1" max="65535" bind:value={form.validationPort} placeholder="80" />
        <div class="hint">DevCA's gateway uses port 80, so run your client's challenge server on another port (e.g. <code>lego --http.port :5002</code>) and enter it here.</div>
      </div>
    {/if}
    {#if form.mode !== 'proxy'}
      <div class="field">
        <label for="fwd">Forward <code>https://{fullHost(form.hostname) || `app.${suffix}`}</code> to your app <span class="muted">(optional)</span></label>
        <input id="fwd" type="text" bind:value={form.passthrough} placeholder="8443" autocomplete="off" />
        <div class="hint">The port where your app serves HTTPS itself. DevCA passes connections on port 443 straight through, still encrypted, so your app's own certificate is used.</div>
      </div>
      <div class="field">
        <label for="addr">Loopback address <span class="muted">(optional)</span></label>
        <input id="addr" type="text" bind:value={form.address} placeholder="127.0.0.1" autocomplete="off" spellcheck="false" />
        <div class="hint">Give this hostname its own address, e.g. <code>127.0.0.2</code>, so its app can use the same port as another service. Used for the hosts file; bind your app to it.</div>
      </div>
    {/if}
    <div class="actions">
      <button class="btn primary" disabled={busy}>{busy ? 'Adding…' : 'Add service'}</button>
      <button type="button" class="btn ghost" onclick={() => (adding = false)}>Cancel</button>
    </div>
  </form>
{/if}

{#if services.data && services.data.length === 0 && !adding}
  <div class="card empty">
    <p>No services yet.</p>
    <button class="btn primary" onclick={() => (adding = true)}><Icon name="plus" size={16} /> Add your first service</button>
  </div>
{/if}

{#each services.data ?? [] as v (v.hostname)}
  <div class="card svc" class:disabled={!v.enabled}>
    <div class="row">
      <button class="name" onclick={() => (expanded = expanded === v.hostname ? null : v.hostname)} aria-expanded={expanded === v.hostname}>
        <strong>{v.hostname}</strong>
      </button>
      <Badge tone="accent">{modeLabel[v.mode]}</Badge>
      {#if v.address}<span class="muted small mono">{v.address}</span>{/if}
      {#if !v.enabled}<Badge>disabled</Badge>{/if}
      <span class="spacer"></span>
      {#if v.mode === 'proxy' || v.passthrough}
        <span class="small">
          {#if v.health}
            <span class="dot" class:ok={v.health.up} class:bad={!v.health.up}></span>{v.health.up ? 'app is up' : 'app is down'}
          {/if}
          <span class="muted">→ {v.mode === 'proxy' ? v.target : `${v.passthrough} (passthrough)`}</span>
        </span>
      {/if}
      {#if v.cert}
        <Badge tone={v.cert.status === 'valid' ? 'ok' : v.cert.status === 'expiring' ? 'warn' : 'bad'}>{daysLeft(v.cert.notAfter)}</Badge>
      {/if}
      {#if v.url && v.enabled}
        <a class="btn small" href={v.url} target="_blank" rel="noreferrer">Open</a>
      {/if}
      <button class="btn small ghost" onclick={() => (expanded = expanded === v.hostname ? null : v.hostname)}>
        {expanded === v.hostname ? 'Close' : 'Manage'}
      </button>
    </div>

    {#if v.resolves === 'missing'}
      <p class="small warn-text">
        {v.hostname} isn't in your hosts file{v.address ? ` with ${v.address}` : ''} yet, so it won't resolve{v.address ? ' there' : ''}. Run <code>devca hosts apply</code>.
      </p>
    {/if}
    {#if v.health && !v.health.up && v.enabled}
      <p class="small muted">{v.health.error}. Start your app, or change the target.</p>
    {/if}

    {#if expanded === v.hostname}
      {#key rev}
      <div class="details">
        {#if v.mode === 'proxy'}
          <div class="field inline">
            <label for={'t-' + v.hostname}>Target</label>
            <input id={'t-' + v.hostname} type="text" value={v.target} onchange={(e) => update(v, { target: e.currentTarget.value })} />
          </div>
        {/if}
        {#if v.mode === 'export' && v.certDir}
          <h3>Certificate files</h3>
          <p class="small muted">Replaced atomically on renewal, keeping the same private key. Reload your app when <code>certificate.pem</code> changes, or point it at <code>bundle.pem</code> (key and certificate in one file).</p>
          <Code text={v.certDir} />
          {#if v.exportDir}<Code text={v.exportDir} />{/if}
        {/if}
        {#if v.mode !== 'proxy'}
          <div class="field inline">
            <label for={'p-' + v.hostname}>Forward HTTPS on port 443 to</label>
            <input id={'p-' + v.hostname} type="text" value={v.passthrough ?? ''} placeholder="e.g. 8443 (optional)" onchange={(e) => update(v, { passthrough: e.currentTarget.value })} />
          </div>
          <div class="field inline">
            <label for={'a-' + v.hostname}>Loopback address</label>
            <input id={'a-' + v.hostname} type="text" value={v.address ?? ''} placeholder="127.0.0.1" onchange={(e) => update(v, { address: e.currentTarget.value })} />
          </div>
        {/if}
        {#if v.mode === 'acme'}
          <p class="small muted">An external ACME client owns this hostname. DevCA issues when the client asks and never renews on its own. See <a href="#/acme">ACME</a> for the directory URL.</p>
        {/if}
        {#if v.resolves === 'browser'}
          <p class="small muted">.localhost names work in Chrome, Firefox and Edge as-is. For Safari and command-line tools run <code>devca hosts apply</code>.</p>
        {/if}
        <div class="actions">
          <label class="check"><input type="checkbox" checked={v.enabled} onchange={(e) => update(v, { enabled: e.currentTarget.checked })} /> Enabled</label>
          {#if v.mode !== 'acme'}
            <label class="check"><input type="checkbox" checked={v.autoRenew} onchange={(e) => update(v, { autoRenew: e.currentTarget.checked })} /> Renew automatically</label>
          {/if}
          <span class="spacer"></span>
          <select aria-label="Mode" value={v.mode} onchange={(e) => changeMode(v, e.currentTarget.value as Mode)}>
            {#each modes as m}<option value={m.id}>{m.title}</option>{/each}
          </select>
          {#if v.mode !== 'acme'}
            <button class="btn small" onclick={() => renew(v)}><Icon name="renew" size={16} /> Renew now</button>
          {/if}
          {#if v.cert}<a class="btn small" href={`#/certificates?${v.cert.id}`}>Certificate</a>{/if}
          <button class="btn small danger" onclick={() => remove(v)}><Icon name="trash" size={16} /> Remove</button>
        </div>
      </div>
      {/key}
    {/if}
  </div>
{/each}

<style>
  .label { display: block; font-weight: 500; margin-bottom: .3rem; }
  .svc { padding: .8rem 1rem; }
  .svc.disabled { opacity: .7; }
  .row { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }
  .name { font: inherit; background: none; border: none; padding: 0; color: var(--text); cursor: pointer; }
  .name:hover strong { color: var(--accent); }
  .spacer { flex: 1; }
  .details { border-top: 1px solid var(--border); margin-top: .8rem; padding-top: .8rem; }
  .details select { width: auto; padding: .25rem .5rem; }
  .field.inline { max-width: 28rem; }
  .warn-text { color: var(--warn); margin: .5rem 0 0; }
  .svc > p { margin: .5rem 0 0; }
</style>
