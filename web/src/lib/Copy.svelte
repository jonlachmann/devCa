<script lang="ts">
  import Icon from './Icon.svelte'
  let { text, label = 'Copy' }: { text: string; label?: string } = $props()
  let done = $state(false)
  async function copy() {
    await navigator.clipboard.writeText(text)
    done = true
    setTimeout(() => (done = false), 1500)
  }
</script>

<button type="button" class="btn ghost small" onclick={copy} title={label} aria-label={label}>
  <Icon name={done ? 'check' : 'copy'} size={16} />
</button>
