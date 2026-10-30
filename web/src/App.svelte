<script lang="ts">
  import Icon, { type IconName } from './lib/Icon.svelte'
  import { toast } from './lib/toast.svelte'
  import Dashboard from './pages/Dashboard.svelte'
  import Services from './pages/Services.svelte'
  import Certificates from './pages/Certificates.svelte'
  import Acme from './pages/Acme.svelte'
  import Authority from './pages/Authority.svelte'
  import Settings from './pages/Settings.svelte'

  const pages: { path: string; label: string; icon: IconName; component: any }[] = [
    { path: '/', label: 'Dashboard', icon: 'home', component: Dashboard },
    { path: '/services', label: 'Services', icon: 'services', component: Services },
    { path: '/certificates', label: 'Certificates', icon: 'certs', component: Certificates },
    { path: '/acme', label: 'ACME', icon: 'acme', component: Acme },
    { path: '/ca', label: 'Certificate Authority', icon: 'shield', component: Authority },
    { path: '/settings', label: 'Settings', icon: 'settings', component: Settings },
  ]

  const current = () => location.hash.slice(1) || '/'
  let route = $state(current())
  $effect(() => {
    const on = () => (route = current())
    addEventListener('hashchange', on)
    return () => removeEventListener('hashchange', on)
  })
  let page = $derived(pages.find((p) => p.path === route.split('?')[0]) ?? pages[0])
</script>

<div class="shell">
  <nav>
    <div class="brand">DevCA</div>
    {#each pages as p}
      <a href={'#' + p.path} class:active={p === page} aria-current={p === page ? 'page' : undefined}>
        <Icon name={p.icon} /> <span>{p.label}</span>
      </a>
    {/each}
  </nav>
  <main>
    {#key page}
      <page.component />
    {/key}
  </main>
</div>

{#if toast.message}
  <div class="toast {toast.kind}" role="status">{toast.message}</div>
{/if}

<style>
  .shell { display: grid; grid-template-columns: 220px 1fr; min-height: 100vh; }
  nav {
    background: var(--surface); border-right: 1px solid var(--border);
    padding: 1rem .75rem; position: sticky; top: 0; height: 100vh;
  }
  .brand { font-weight: 700; font-size: 1.05rem; padding: .25rem .6rem 1rem; letter-spacing: -.01em; }
  nav a {
    display: flex; align-items: center; gap: .6rem;
    padding: .45rem .6rem; border-radius: 8px; color: var(--muted); font-weight: 500;
  }
  nav a:hover { background: var(--surface-2); color: var(--text); text-decoration: none; }
  nav a.active { background: var(--accent-soft); color: var(--accent); }
  main { padding: 1.75rem 2rem 3rem; max-width: 1100px; width: 100%; }
  @media (max-width: 800px) {
    .shell { grid-template-columns: 1fr; }
    nav { position: static; height: auto; display: flex; overflow-x: auto; gap: .25rem; padding: .5rem; border-right: none; border-bottom: 1px solid var(--border); }
    .brand { padding: .45rem .6rem; }
    nav a span { display: none; }
    main { padding: 1.25rem 1rem 3rem; }
  }
  .toast {
    position: fixed; bottom: 1.25rem; right: 1.25rem; max-width: min(28rem, calc(100vw - 2.5rem));
    padding: .7rem 1rem; border-radius: 8px; color: #fff; background: #1f2937; box-shadow: 0 6px 20px rgb(0 0 0 / .2);
  }
  .toast.error { background: var(--bad); }
</style>
