<script lang="ts">
  // egui Window used for dialogs (Send, Install, password picker).
  import type { Snippet } from "svelte";
  let { title, onclose, left = 330, top = 60, width, children }: { title?: string; onclose?: () => void; left?: number; top?: number; width?: number; children: Snippet } = $props();
</script>

<div class="ewin" role="dialog" aria-label={title ?? "Dialog"} style:left="{left}px" style:top="{top}px" style:width={width ? `${width}px` : undefined}>
  {#if title}
    <div class="wt">
      <span>{title}</span>
      {#if onclose}<button type="button" aria-label="Close" onclick={onclose}>✕</button>{/if}
    </div>
  {/if}
  <div class="wb">{@render children()}</div>
</div>
