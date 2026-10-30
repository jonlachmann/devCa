<script lang="ts">
  import { api, type Settings } from '../lib/api'
  import { attempt, notify } from '../lib/toast.svelte'

  let form = $state<Settings>()
  let suffixes = $state<string[]>([])
  let dataDir = $state('')
  let restart = $state(false)

  $effect(() => {
    api<{ settings: Settings; suffixes: string[]; dataDir: string }>('GET', '/api/settings').then(
      (r) => ((form = r.settings), (suffixes = r.suffixes), (dataDir = r.dataDir)),
      (e) => notify(e.message, 'error'),
    )
  })

  async function save(e: SubmitEvent) {
    e.preventDefault()
    await attempt(async () => {
      const r = await api<{ restartRequired: boolean }>('PUT', '/api/settings', form)
      restart = r.restartRequired
    }, 'Settings saved')
  }
</script>

<div class="page-head">
  <div>
    <h1>Settings</h1>
    <p>The defaults work for most setups.</p>
  </div>
</div>

{#if restart}
  <div class="card notice">Restart DevCA to apply the new ports, gateway or log settings.</div>
{/if}

{#if form}
  <form onsubmit={save}>
    <div class="grid two">
      <div class="card">
        <h2>Certificates</h2>
        <div class="field">
          <label for="leaf">Validity (days)</label>
          <input id="leaf" type="number" min="1" max="397" bind:value={form.leafDays} />
        </div>
        <div class="field">
          <label for="renew">Renew when fewer than this many days remain</label>
          <input id="renew" type="number" min="1" bind:value={form.renewDays} />
        </div>
        <div class="field">
          <label for="suffix">Default suffix for new services</label>
          <select id="suffix" bind:value={form.defaultSuffix}>
            {#each suffixes as s}<option value={s}>.{s}</option>{/each}
          </select>
          <div class="hint">Allowed suffixes are fixed in the root certificate. Changing them means creating and trusting a new root.</div>
        </div>
      </div>

      <div class="card">
        <h2>Listeners</h2>
        <label class="check field"><input type="checkbox" bind:checked={form.gatewayEnabled} /> Run the HTTPS gateway (proxy and HTTP-01 on port {form.httpPort})</label>
        <div class="ports">
          <div class="field"><label for="hp">HTTP</label><input id="hp" type="number" bind:value={form.httpPort} /></div>
          <div class="field"><label for="hsp">HTTPS</label><input id="hsp" type="number" bind:value={form.httpsPort} /></div>
          <div class="field"><label for="mp">Web UI</label><input id="mp" type="number" bind:value={form.mgmtPort} /></div>
          <div class="field"><label for="ap">ACME</label><input id="ap" type="number" bind:value={form.acmePort} /></div>
        </div>
        <div class="hint small muted">All listeners bind to this computer only (127.0.0.1 and ::1).</div>
      </div>

      <div class="card">
        <h2>Other</h2>
        <div class="field">
          <label for="log">Log level</label>
          <select id="log" bind:value={form.logLevel}>
            {#each ['debug', 'info', 'warn', 'error'] as l}<option>{l}</option>{/each}
          </select>
        </div>
        <div class="field">
          <span class="lbl">Data directory</span>
          <code class="small">{dataDir}</code>
          <div class="hint">Set with <code>--data</code> or <code>DEVCA_HOME</code>.</div>
        </div>
      </div>
    </div>
    <button class="btn primary">Save settings</button>
  </form>
{/if}

<style>
  .ports { display: grid; grid-template-columns: 1fr 1fr; gap: 0 1rem; }
  .lbl { display: block; font-weight: 500; margin-bottom: .3rem; }
</style>
