<script lang="ts">
  import { onDestroy } from "svelte";
  import { getApp } from "./app.svelte";
  import { B32, CODE_MS, HEX, pseudo } from "./data";

  const app = getApp();
  let code = $state<{ text: string; at: number } | null>(null);
  let waitingCode = $state(false);
  let entered = $state("");
  let now = $state(Date.now());

  // Ticks the "valid for" countdown while a code is shown.
  const timer = setInterval(() => {
    if (code) now = Date.now();
  }, 1000);
  onDestroy(() => clearInterval(timer));

  const left = $derived(code ? Math.max(0, Math.ceil((CODE_MS - (now - code.at)) / 1000)) : 0);

  function newCode() {
    waitingCode = true;
    setTimeout(() => {
      waitingCode = false;
      code = { text: "LZ2-" + (pseudo(String(Date.now()), 112, B32).match(/.{1,4}/g) ?? []).join("-"), at: Date.now() };
      now = Date.now();
    }, 900);
  }

  function pair() {
    if (!entered.trim()) return;
    entered = "";
    app.toast("Pairing request sent. Waiting for the other device…");
    setTimeout(() => {
      const name = app.paired.some((p) => p.name === "Office PC") ? "Second laptop" : "Office PC";
      app.paired.push({ id: pseudo(name + Date.now(), 64, HEX), name });
      app.toast(`Paired with ${name}`);
    }, 1600);
  }

  const stub = {
    server: () => app.notInDemo("Sync server", "The first device needs the URL of your own sync Worker and its access token. Other devices get both from the pairing code."),
    remove: () => app.notInDemo("Remove device", "Removing a paired device makes this device stop accepting data from it."),
  };
</script>

<div class="central">
  <div class="heading">Sync server</div>
  <div class="row">
    <span>URL:</span><span class="strong">https://lzssh.example.com</span>
    <button type="button" class="sm" onclick={stub.server}>Change</button>
  </div>
  <div class="hr"></div>

  <div class="heading">Paired devices</div>
  {#if app.paired.length}
    <div class="list">
      {#each app.paired as p (p.id)}
        <div class="li">
          <span class="pname">{p.name}</span>
          <span class="weak grow">{p.id.slice(0, 16)}</span>
          <button type="button" onclick={stub.remove}>Remove</button>
        </div>
      {/each}
    </div>
  {:else}
    <span>None yet.</span>
  {/if}
  <div class="hr"></div>

  <div class="heading">Pair a new device</div>
  <div class="cols">
    <div class="col">
      <span class="strong">Show a code on this device</span>
      {#if code && left > 0}
        <span class="mono code">{code.text}</span>
        <span>valid for {Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</span>
        <span>Enter it on the other device within 10 minutes. Keep lzssh open here until both show the pairing.</span>
      {:else if waitingCode}
        <div class="row"><span class="spin"></span><span>Creating code…</span></div>
      {:else}
        <button type="button" onclick={newCode}>Pair new device</button>
      {/if}
    </div>
    <div class="col">
      <span class="strong">Enter a code from another device</span>
      <textarea rows="3" placeholder="LZ2-…" aria-label="Pairing code" bind:value={entered}></textarea>
      <button type="button" disabled={!entered.trim()} onclick={pair}>Pair</button>
    </div>
  </div>
</div>

<style>
  .pname { color: var(--eg-text); width: 140px; }
  .col { display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
  .code { word-break: break-all; color: var(--eg-text); user-select: text; }
</style>
