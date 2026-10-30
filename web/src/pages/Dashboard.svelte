<script lang="ts">
  import type { Status, Service } from '../lib/api'
  import { resource } from '../lib/resource.svelte'
  import { ago, date, daysLeft } from '../lib/format'
  import Code from '../lib/Code.svelte'
  import Badge from '../lib/Badge.svelte'

  const status = resource<Status>('/api/status')
  const services = resource<Service[]>('/api/services')

  let s = $derived(status.data)
  let failedListeners = $derived(s?.gateway.listeners?.filter((l) => l.error && !l.addr.startsWith('[::1]')) ?? [])
  let firstRun = $derived(s && (!s.ca.trust.trusted || s.counts.services === 0))
</script>

<div class="page-head">
  <div>
    <h1>Dashboard</h1>
    <p>Local HTTPS for development.</p>
  </div>
</div>

{#if status.error}
  <div class="card danger"><strong>Can't reach DevCA.</strong> <span class="muted">{status.error}</span></div>
{/if}

{#if s}
  {#if firstRun}
    <div class="card">
      <h2>Get started</h2>
      <ol class="steps">
        <li class="done">Local certificate authority created</li>
        <li class:done={s.ca.trust.trusted}>
          {#if s.ca.trust.trusted}
            Root certificate trusted by this computer
          {:else}
            <strong>Trust the root certificate</strong> so browsers accept DevCA certificates. Run in a terminal:
            <Code text="devca trust install" />
            <span class="muted small">This is a security-sensitive change, so it's done from the terminal where you can review it. <a href="#/ca">Why it's safe</a></span>
          {/if}
        </li>
        <li class:done={s.counts.services > 0}>
          {#if s.counts.services > 0}
            First service added
          {:else}
            <a href="#/services?new">Add your first service</a>: a hostname and the port your app runs on.
          {/if}
        </li>
      </ol>
    </div>
  {/if}

  {#if failedListeners.length}
    <div class="card notice">
      <strong>The HTTPS gateway isn't fully running.</strong>
      <ul>
        {#each failedListeners as l}<li><code>{l.addr}</code>: {l.error}</li>{/each}
      </ul>
      <span class="small">Change the ports in <a href="#/settings">Settings</a> or stop the program using them, then restart DevCA.</span>
    </div>
  {/if}

  <div class="stats">
    <a class="stat" href="#/services"><div class="value">{s.counts.services}</div><div class="label">Services</div></a>
    <a class="stat" href="#/certificates"><div class="value">{s.counts.activeCerts}</div><div class="label">Active certificates</div></a>
    <div class="stat">
      <div class="value" class:warn={s.counts.expiring > 0}>{s.counts.expiring}</div>
      <div class="label">Expiring soon</div>
    </div>
    <a class="stat" href="#/acme">
      <div class="value" class:bad={s.counts.acmeFailures24h > 0}>{s.counts.acmeFailures24h}</div>
      <div class="label">ACME failures (24h)</div>
    </a>
  </div>

  <div class="grid two">
    <div class="card">
      <h2>Status</h2>
      <dl class="kv">
        <dt>Gateway</dt>
        <dd>
          {#if !s.gateway.enabled}
            <Badge>disabled</Badge>
          {:else if failedListeners.length}
            <Badge tone="bad">problem</Badge>
          {:else}
            <Badge tone="ok">running</Badge> <span class="muted small">ports {s.gateway.httpPort} / {s.gateway.httpsPort}</span>
          {/if}
        </dd>
        <dt>Root CA</dt>
        <dd>
          {#if s.ca.trust.trusted}<Badge tone="ok">trusted</Badge>{:else}<Badge tone="warn">not trusted</Badge>{/if}
          <span class="muted small">expires {date(s.ca.notAfter)}</span>
        </dd>
        <dt>Upstreams</dt>
        <dd>
          {#if s.counts.upstreams === 0}
            <span class="muted">no proxy services</span>
          {:else if s.counts.upstreamsDown}
            <Badge tone="warn">{s.counts.upstreamsDown} of {s.counts.upstreams} down</Badge>
          {:else}
            <Badge tone="ok">all {s.counts.upstreams} up</Badge>
          {/if}
        </dd>
        <dt>Version</dt>
        <dd>{s.version}</dd>
      </dl>
      {#if services.data?.length}
        <h3 style="margin-top:1rem">Services</h3>
        <ul class="plain svc">
          {#each services.data as v}
            <li>
              <span class="dot" class:ok={v.mode !== 'proxy' || v.health?.up} class:bad={v.mode === 'proxy' && v.health && !v.health.up}></span>
              {#if v.url}<a href={v.url} target="_blank" rel="noreferrer">{v.hostname}</a>{:else}{v.hostname}{/if}
              {#if !v.enabled}<Badge>disabled</Badge>{/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>

    <div class="card">
      <h2>Recent activity</h2>
      {#if s.recent?.length}
        <ul class="plain events">
          {#each s.recent as e}
            <li>
              <span class="time">{ago(e.time)}</span>
              <span class:error-text={e.level === 'error'}>{e.message}</span>
            </li>
          {/each}
        </ul>
      {:else}
        <div class="empty">Nothing yet.</div>
      {/if}
    </div>
  </div>

  {#if s.expiring?.length}
    <div class="card">
      <h2>Expiring soon</h2>
      <ul class="plain events">
        {#each s.expiring as c}
          <li><span class="time">{daysLeft(c.notAfter)}</span> <span>{c.names.join(', ')} <span class="muted small">({c.ownerLabel})</span></span></li>
        {/each}
      </ul>
      <p class="muted small" style="margin:.5rem 0 0">DevCA renews its own certificates automatically. Certificates from ACME clients are renewed by those clients.</p>
    </div>
  {/if}
{/if}

<style>
  a.stat { color: inherit; }
  a.stat:hover { text-decoration: none; border-color: var(--accent); }
  .value.warn { color: var(--warn); }
  .value.bad { color: var(--bad); }
  .steps { margin: 0; padding-left: 1.4rem; }
  .steps li::marker { content: '○  '; color: var(--muted); }
  .steps li { margin-bottom: .6rem; }
  .steps li.done { color: var(--muted); }
  .steps li.done::marker { content: '✓  '; color: var(--ok); }
  .svc li { padding: .2rem 0; }
</style>
