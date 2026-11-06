<script lang="ts">
  import { getApp } from "./app.svelte";
  import { DEMO_PIN } from "./data";

  const app = getApp();
  let pin = $state("");
  let error = $state<string | null>(null);
  let busy = $state(false);

  function unlock() {
    const p = pin.trim();
    if (!/^\d{6,256}$/.test(p)) error = "PIN must be 6 to 256 digits";
    else if (p !== DEMO_PIN) error = "Wrong PIN";
    else return app.unlocked();
    pin = "";
  }

  async function hello() {
    busy = true;
    error = null;
    const ok = await app.ask("hello-unlock");
    busy = false;
    if (ok) app.unlocked();
    else error = "The operation was canceled by the user.";
  }
</script>

<div class="unlock">
  <div class="heading">Enter PIN</div>
  <input type="password" placeholder="PIN" aria-label="PIN" inputmode="numeric" autocomplete="off" bind:value={pin} onkeydown={(e) => e.key === "Enter" && unlock()} />
  <button type="button" onclick={unlock}>Unlock</button>
  <span class="weak or">or</span>
  <button type="button" disabled={busy} onclick={hello}>Unlock with Windows Hello</button>
  {#if busy}
    <div class="row"><span class="spin"></span><span>Waiting for the Windows dialog…</span></div>
  {/if}
  {#if error}<span class="err">{error}</span>{/if}
</div>

<style>
  .unlock { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 6px; padding-top: 120px; }
  .unlock input { width: 170px; }
  .or { margin-top: 4px; }
</style>
