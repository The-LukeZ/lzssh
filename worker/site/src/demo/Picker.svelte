<script lang="ts">
  // The password picker that the global hotkey opens.
  import { getApp } from "./app.svelte";
  import EWindow from "./EWindow.svelte";

  const app = getApp();
  let query = $state("");
  let index = $state(0);
  const passwords = $derived(app.secrets.filter((s) => s.kind === "Password"));
  const matches = $derived(passwords.filter((s) => !query.trim() || s.name.toLowerCase().includes(query.trim().toLowerCase())));

  function close() {
    app.picker = false;
    query = "";
    index = 0;
  }

  function pick(name: string) {
    close();
    app.note = `Picked "${name}". The real app puts it on the clipboard and clears it after 90 s. This demo copies nothing.`;
  }

  function onkey(e: KeyboardEvent) {
    if (e.key === "ArrowDown") index = Math.min(index + 1, matches.length - 1);
    else if (e.key === "ArrowUp") index = Math.max(index - 1, 0);
    else if (e.key === "Enter" && matches[index]) pick(matches[index].name);
    else if (e.key === "Escape") close();
    else return;
    e.preventDefault();
  }

  const focusOnMount = (el: HTMLElement) => el.focus();
</script>

{#if app.picker}
  <EWindow left={330} top={120} width={340}>
    <input type="text" placeholder="Filter passwords" aria-label="Filter passwords" bind:value={query} oninput={() => (index = 0)} onkeydown={onkey} {@attach focusOnMount} />
    {#if !passwords.length}
      <span>No passwords stored. Add one on the Secrets page.</span>
    {:else if !matches.length}
      <span>No match</span>
    {:else}
      <div class="picks">
        {#each matches as s, i (s.id)}
          <button type="button" class={["sel", i === index && "on"]} onclick={() => pick(s.name)}>{s.name}</button>
        {/each}
      </div>
    {/if}
  </EWindow>
{/if}

<style>
  .picks { display: flex; flex-direction: column; align-items: flex-start; gap: 2px; }
</style>
