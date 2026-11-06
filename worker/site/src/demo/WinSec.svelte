<script lang="ts">
  // Stand-in for the Windows Hello / security key dialog.
  import { getApp, type SecurityKind } from "./app.svelte";

  const app = getApp();
  const TEXT: Record<SecurityKind, { title: string; heading: string; body: string; hello: boolean }> = {
    "hello-unlock": { title: "Windows Hello", heading: "Making sure it's you", body: "Confirm with Windows Hello to unlock lzssh.", hello: true },
    "key-create": { title: "Windows Security", heading: "Security key setup", body: "Insert your security key and touch it to create a new SSH key.", hello: false },
  };

  const t = $derived(app.security ? TEXT[app.security.kind] : null);

  function confirm() {
    const req = app.security;
    if (!req) return;
    req.resolve(true);
  }

  function cancel() {
    app.security?.resolve(false);
  }

  const focusOnMount = (el: HTMLElement) => el.focus();
</script>

{#if app.security && t}
  <div class="winsec" role="dialog" aria-modal="true" aria-labelledby="ws-h" tabindex="-1" onkeydown={(e) => e.key === "Escape" && cancel()}>
    <div class="b">
      <div class="t">{t.title}</div>
      <h4 id="ws-h">{t.heading}</h4>
      <p>{t.body}</p>
      <button type="button" class="key" onclick={confirm} {@attach focusOnMount}>
        {#if t.hello}
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><path d="M6.5 6.5a8 8 0 0 1 11 0M5 10.5a7.5 7.5 0 0 1 14 0M8 20c1-2 1.5-4 1.5-6a2.5 2.5 0 0 1 5 0c0 2.5-.5 5-1.5 7M12 14c0 3-.8 5.5-2 7.5M17 18.5c.3-1.4.5-2.9.5-4.5a5.5 5.5 0 0 0-11 0c0 1.2-.2 2.3-.5 3.3" /></svg>
          <span>Scan your finger (click here in this demo)</span>
        {:else}
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="7" y="2" width="10" height="20" rx="3" /><circle cx="12" cy="14" r="2.5" /><path d="M10 5h4" /></svg>
          <span>Touch your security key (click here)</span>
        {/if}
      </button>
    </div>
    <div class="f"><button type="button" onclick={cancel}>Cancel</button></div>
  </div>
{/if}

<style>
  .winsec {
    position: absolute; left: 320px; top: 140px; width: 400px; z-index: 6;
    background: #2b2b2b; color: #fff; border-radius: 8px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(255, 255, 255, 0.08);
    font: 400 14px/1.45 "Segoe UI", system-ui, sans-serif;
    overflow: hidden;
  }
  .winsec:focus { outline: none; }
  .b { padding: 18px 24px 22px; }
  .t { font-size: 12px; color: #c8c8c8; margin-bottom: 10px; }
  h4 { font: 600 20px/1.25 var(--display-font); margin: 0 0 8px; }
  p { margin: 0 0 14px; color: #dcdcdc; }
  .key {
    display: flex; align-items: center; gap: 12px; width: 100%;
    background: #383838; border: 1px solid #4a4a4a; border-radius: 6px; color: #fff;
    padding: 12px 14px; font: inherit; text-align: left; cursor: pointer;
  }
  .key:hover { background: #404040; }
  .key svg { flex: none; }
  .f { background: #202020; padding: 14px 24px; display: flex; justify-content: flex-end; }
  .f button { background: #3a3a3a; color: #fff; border: 1px solid #4a4a4a; border-radius: 4px; padding: 5px 22px; font: inherit; }
</style>
