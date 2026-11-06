<script lang="ts">
  // egui ComboBox: a button that opens a list of selectable values.
  type Option = { v: string; l: string };
  let { text, options, value, onpick, empty = "" }: { text: string; options: Option[]; value: string; onpick: (v: string) => void; empty?: string } = $props();
  let open = $state(false);
  let root: HTMLElement | undefined = $state();

  function pick(v: string) {
    onpick(v);
    open = false;
  }
</script>

<svelte:window
  onclick={(e) => {
    if (open && root && !root.contains(e.target as Node)) open = false;
  }}
  onkeydown={(e) => {
    if (open && e.key === "Escape") open = false;
  }}
/>

<span class="combo" bind:this={root}>
  <button type="button" aria-haspopup="listbox" aria-expanded={open} onclick={() => (open = !open)}>{text}</button>
  {#if open}
    <div class="menu" role="listbox">
      {#each options as o (o.v)}
        <button type="button" role="option" aria-selected={o.v === value} class={["sel", o.v === value && "on"]} onclick={() => pick(o.v)}>{o.l}</button>
      {:else}
        <span class="empty">{empty}</span>
      {/each}
    </div>
  {/if}
</span>

<style>
  .empty { padding: 2px 8px; white-space: nowrap; }
</style>
