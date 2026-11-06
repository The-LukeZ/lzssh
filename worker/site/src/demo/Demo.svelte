<script lang="ts">
  import "./chrome.css";
  import "./eg.css";
  import { DemoApp, setApp, type Screen } from "./app.svelte";
  import { HOTKEY } from "./data";
  import Devices from "./Devices.svelte";
  import { comboOf } from "./hotkey";
  import Hosts from "./Hosts.svelte";
  import NotInDemo from "./NotInDemo.svelte";
  import Picker from "./Picker.svelte";
  import Secrets from "./Secrets.svelte";
  import Terminal from "./Terminal.svelte";
  import Unlock from "./Unlock.svelte";
  import WinSec from "./WinSec.svelte";

  // The desk is laid out at a fixed 1180 by 680 px and scaled down to fit narrower screens.
  const DESK_W = 1180;
  const DESK_H = 680;

  const app = setApp(new DemoApp());
  let width = $state(DESK_W);
  const scale = $derived(Math.min(1, width / DESK_W));

  // Known hosts and Settings exist in lzssh but only open the "Not in this demo" popup here.
  const TABS: [Screen | "known" | "settings", string][] = [["hosts", "Hosts"], ["secrets", "Secrets"], ["known", "Known hosts"], ["devices", "Devices"], ["settings", "Settings"]];

  function tab(s: Screen | "known" | "settings") {
    if (s === "known") app.notInDemo("Known hosts", "lzssh lists the entries in ~/.ssh/known_hosts, with a filter, and removes the ones you no longer trust.");
    else if (s === "settings") app.notInDemo("Settings", `Change the password hotkey (${HOTKEY} by default) and set up quick unlock with Windows Hello or a FIDO2 security key.`);
    else app.screen = s;
  }

  function hotkey(e: KeyboardEvent) {
    if (comboOf(e) !== HOTKEY) return;
    e.preventDefault();
    if (app.screen === "unlock") app.note = "Unlock lzssh first";
    else app.picker = true;
  }
</script>

<svelte:window onkeydown={hotkey} />

<div class="fit" bind:clientWidth={width} style:height="{DESK_H * scale}px">
  <div class="desk" style:transform="scale({scale})" style:width="{DESK_W}px" style:height="{DESK_H}px">
    <div class="win app-win">
      <div class="titlebar" aria-hidden="true">
        <span class="tb-title"><img src="/icon-192.png" alt="" width="16" height="16" />lzssh</span>
        <span class="tb-btns"><i class="tb-min"></i><i class="tb-max"></i><i class="tb-x"></i></span>
      </div>
      <div class="eg" role="application" aria-label="lzssh demo">
        {#if app.screen === "unlock"}
          <div class="body"><Unlock /></div>
        {:else}
          <div class="nav">
            <span class="h">lzssh</span>
            <span class="vsep"></span>
            {#each TABS as [s, label] (s)}
              <button type="button" class={["sel", app.screen === s && "on"]} aria-pressed={app.screen === s} onclick={() => tab(s)}>{label}</button>
            {/each}
          </div>
          <div class="body">
            {#if app.screen === "hosts"}<Hosts />
            {:else if app.screen === "secrets"}<Secrets />
            {:else}<Devices />{/if}
          </div>
          {#if app.toasts.length}
            <div class="toasts" role="status">
              {#each app.toasts as t (t.id)}<div>{t.msg}</div>{/each}
            </div>
          {/if}
          <Picker />
          <NotInDemo />
        {/if}
      </div>
    </div>
    <Terminal />
    <WinSec />
  </div>
</div>
<p class="demo-note" aria-live="polite">
  {app.note || (scale < 0.6 ? "The demo is scaled down to fit. It works best on a wider screen." : "")}
</p>

<style>
  .fit { width: min(100% - 2.5rem, 74rem); margin-inline: auto; position: relative; }
  .desk { position: relative; transform-origin: 0 0; }
  .demo-note { width: min(100% - 2.5rem, 68rem); margin: 0.75rem auto 0; min-height: 1.5em; color: #b3c3cf; font-size: 0.92rem; }
</style>
