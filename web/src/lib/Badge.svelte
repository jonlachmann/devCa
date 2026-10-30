<script lang="ts">
  import type { Snippet } from 'svelte'
  let { tone = 'neutral', children }: { tone?: 'ok' | 'warn' | 'bad' | 'neutral' | 'accent'; children: Snippet } = $props()
</script>

<span class="badge {tone}">{@render children()}</span>
