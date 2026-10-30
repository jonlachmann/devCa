<script lang="ts">
  import Copy from './Copy.svelte'
  let { text }: { text: string } = $props()
</script>

<div class="code"><code>{text}</code><Copy {text} /></div>
