<script lang="ts">
  import { download, type TrustStatus } from '../lib/api'
  import { resource } from '../lib/resource.svelte'
  import { attempt } from '../lib/toast.svelte'
  import { date } from '../lib/format'
  import Badge from '../lib/Badge.svelte'
  import Code from '../lib/Code.svelte'
  import Icon from '../lib/Icon.svelte'

  type CAInfo = {
    subject: string
    fingerprint: string
    notBefore: string
    notAfter: string
    keyType: string
    suffixes: string[]
    trust: TrustStatus
    dataDir: string
    certPath: string
  }
  type Hosts = { path: string; managed: string[] | null; missing: string[] | null }

  const ca = resource<CAInfo>('/api/ca', 5000)
  const hosts = resource<Hosts>('/api/hosts', 5000)
  let c = $derived(ca.data)
</script>

<div class="page-head">
  <div>
    <h1>Certificate Authority</h1>
    <p>The local root that signs all DevCA certificates.</p>
  </div>
  <button class="btn" onclick={() => attempt(() => download('/api/ca/root.pem'))}><Icon name="download" size={16} /> Download root certificate</button>
</div>

{#if c}
  <div class="card" class:notice={!c.trust.trusted}>
    <h2>Trust {#if c.trust.trusted}<Badge tone="ok">trusted</Badge>{:else}<Badge tone="warn">not trusted</Badge>{/if}</h2>
    <p>{c.trust.detail}</p>
    {#if !c.trust.trusted}
      <p>
        Browsers show certificate warnings until this computer trusts DevCA's root. Installing a root certificate is a
        <strong>security-sensitive</strong> step: anything it signs is trusted. Run this in a terminal, review what it says, and confirm:
      </p>
      <Code text="devca trust install" />
    {/if}
    <p class="small">
      <strong>Why this root is safe to trust:</strong> it's restricted (by X.509 name constraints) to
      {#each c.suffixes as s, i}<code>*.{s}</code>{i < c.suffixes.length - 1 ? ', ' : ''}{/each} and loopback addresses. It can't vouch for
      public websites, even if its private key were stolen. The private key never leaves <code>{c.dataDir}</code> and isn't reachable through this
      interface.
    </p>
    {#each c.trust.notes ?? [] as n}<p class="small muted">{n}</p>{/each}
    {#if c.trust.trusted}
      <p class="small muted">To remove it later: <code>devca trust uninstall</code></p>
    {/if}
  </div>

  <div class="grid two">
    <div class="card">
      <h2>Root certificate</h2>
      <dl class="kv">
        <dt>Name</dt><dd>{c.subject}</dd>
        <dt>Valid</dt><dd>{date(c.notBefore)} – {date(c.notAfter)}</dd>
        <dt>Key</dt><dd>{c.keyType}</dd>
        <dt>Allowed names</dt><dd>{c.suffixes.map((s) => '.' + s).join(', ')}, 127.0.0.0/8, ::1</dd>
        <dt>File</dt><dd class="mono small">{c.certPath}</dd>
      </dl>
      <h3 style="margin-top:1rem">SHA-256 fingerprint</h3>
      <Code text={c.fingerprint} />
    </div>

    <div class="card">
      <h2>Backup</h2>
      <p class="small">The backup contains the CA private key. Store it somewhere safe. Restoring it on another machine keeps every existing certificate and trust installation valid.</p>
      <Code text="devca ca backup ~/devca-backup.zip" />
      <Code text="devca ca restore ~/devca-backup.zip" />
      <p class="small muted">Backups are file-based on purpose: the CA key is never sent over HTTP.</p>
    </div>
  </div>

  {#if hosts.data}
    <div class="card">
      <h2>Hosts file</h2>
      <p class="small">
        <code>.local</code> names need an entry in <code>{hosts.data.path}</code> to resolve to this computer (<code>.localhost</code> works in most
        browsers without one). DevCA only edits its own marked block, always shows the change first, and can remove it again.
      </p>
      {#if hosts.data.missing?.length}
        <p class="small">Not in the hosts file yet: {hosts.data.missing.join(', ')}</p>
        <Code text="devca hosts apply" />
      {:else}
        <p class="small muted">All service hostnames are in the hosts file.</p>
      {/if}
      {#if hosts.data.managed?.length}<p class="small muted">Undo: <code>devca hosts remove</code></p>{/if}
    </div>
  {/if}
{/if}
