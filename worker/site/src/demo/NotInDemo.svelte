<script lang="ts">
  // Popup for features that lzssh has but this demo only shows.
  import { getApp } from "./app.svelte";
  import EWindow from "./EWindow.svelte";

  const app = getApp();
  const focusOnMount = (el: HTMLElement) => el.focus();
</script>

<svelte:window onkeydown={(e) => app.stub && e.key === "Escape" && (app.stub = null)} />

{#if app.stub}
  <EWindow title="Not in this demo" onclose={() => (app.stub = null)} left={300} top={130} width={400}>
    <span class="strong">{app.stub.what}</span>
    <span>{app.stub.text}</span>
    <div class="row"><button type="button" onclick={() => (app.stub = null)} {@attach focusOnMount}>OK</button></div>
  </EWindow>
{/if}
