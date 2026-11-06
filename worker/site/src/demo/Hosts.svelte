<script lang="ts">
  import { tick } from "svelte";
  import { getApp } from "./app.svelte";
  import Combo from "./Combo.svelte";
  import { KINDS, nid, type Host, type Kind } from "./data";

  const app = getApp();
  let nameInput: HTMLInputElement | undefined = $state();
  let ungroupedOpen = $state(true);

  const missing = (h: Host) => app.secret(h.secret)?.kind !== h.auth;
  const groups = $derived([
    ...app.folders.map((f) => ({ f, hosts: app.hosts.filter((h) => h.folder === f.id) })),
    { f: null, hosts: app.hosts.filter((h) => !h.folder) },
  ]);
  const editFolder = $derived(app.folders.find((f) => f.id === app.edit?.folder)?.name ?? "Ungrouped");
  const secretOpts = $derived(app.secrets.filter((s) => s.kind === app.edit?.auth).map((s) => ({ v: s.id, l: s.name })));
  const secretText = $derived.by(() => {
    const s = app.edit && app.secret(app.edit.secret);
    return s && s.kind === app.edit!.auth ? s.name : "Choose a secret";
  });

  async function newHost() {
    app.sel = null;
    app.edit = { id: nid(), name: "", folder: null, addr: "", v6: "", port: "22", user: "", auth: "SSH key", secret: "" };
    app.isNew = true;
    await tick();
    nameInput?.focus();
  }

  function save() {
    const e = app.edit!;
    if (!e.name.trim()) return app.toast("Enter a name");
    e.name = e.name.trim();
    const cur = app.host(e.id);
    if (cur) Object.assign(cur, e);
    else app.hosts.push({ ...e });
    app.isNew = false;
    app.sel = e.id;
    app.toast("Saved");
  }

  function setAuth(k: string) {
    const e = app.edit!;
    e.auth = k as Kind;
    if (app.secret(e.secret)?.kind !== k) e.secret = app.secrets.find((s) => s.kind === k)?.id ?? "";
  }

  function close() {
    app.edit = null;
    app.sel = null;
    app.isNew = false;
  }

  function menu(e: MouseEvent, folder: boolean) {
    e.preventDefault();
    if (folder) app.notInDemo("Folder menu", "Right-click a folder in lzssh to add a host to it, send it to another device, rename it or delete it.");
    else app.notInDemo("Host menu", "Right-click a host in lzssh to connect (also over IPv6), edit or delete it.");
  }
</script>

<div class="hosts">
  <div class="left">
    <div class="row">
      <button type="button" onclick={newHost}>New host</button>
      <button type="button" onclick={() => app.notInDemo("New folder", "lzssh groups hosts in folders. You can create, rename and delete them.")}>New folder</button>
      <button type="button" onclick={() => app.notInDemo("Send to device", "Pick folders and secrets and send them, end-to-end encrypted, to a paired device. It picks them up the next time lzssh is unlocked there.")}>Send…</button>
    </div>
    <div class="hr"></div>

    {#each groups as g (g.f?.id ?? "ungrouped")}
      {@const open = g.f ? g.f.open : ungroupedOpen}
      <div class={["folder", !open && "closed"]}>
        <button type="button" class="fh" aria-expanded={open}
          onclick={() => (g.f ? (g.f.open = !g.f.open) : (ungroupedOpen = !ungroupedOpen))}
          oncontextmenu={(e) => g.f && menu(e, true)}>
          <span class="tri">▼</span>{g.f?.name ?? "Ungrouped"} ({g.hosts.length})
        </button>
        <div class="kids">
          {#each g.hosts as h (h.id)}
            <button type="button" class={["sel", app.sel === h.id && "on"]} aria-pressed={app.sel === h.id}
              onclick={() => app.openHost(h.id)} ondblclick={() => app.connect(h)} oncontextmenu={(e) => menu(e, false)}>
              {missing(h) ? `${h.name}  (secret missing)` : h.name}
            </button>
          {/each}
        </div>
      </div>
    {/each}
  </div>

  <div class="central">
    {#if app.edit}
      {@const e = app.edit}
      <div class="heading">{app.isNew ? "New host" : "Edit host"}</div>
      <div class="grid">
        <span>Name</span><input type="text" aria-label="Name" bind:value={e.name} bind:this={nameInput} />
        <span>Folder</span>
        <span class="fit-content">
          <Combo text={editFolder} value={e.folder ?? ""} options={[{ v: "", l: "Ungrouped" }, ...app.folders.map((f) => ({ v: f.id, l: f.name }))]} onpick={(v) => (e.folder = v || null)} />
        </span>
        <span>IPv4 / hostname</span><input type="text" aria-label="IPv4 or hostname" bind:value={e.addr} />
        <span>IPv6</span><input type="text" aria-label="IPv6" bind:value={e.v6} />
        <span>Port</span><span><input type="text" class="port" inputmode="numeric" aria-label="Port" bind:value={e.port} /></span>
        <span>Username</span><input type="text" aria-label="Username" bind:value={e.user} />
        <span>Authentication</span>
        <span class="fit-content"><Combo text={e.auth} value={e.auth} options={KINDS.map((k) => ({ v: k, l: k }))} onpick={setAuth} /></span>
        <span>Secret</span>
        <span class="fit-content"><Combo text={secretText} value={e.secret} options={secretOpts} empty="No {e.auth} in Secrets yet" onpick={(v) => (e.secret = v)} /></span>
      </div>
      <div class="row mt">
        <button type="button" onclick={save}>Save</button>
        <button type="button" onclick={close}>Close</button>
        {#if !app.isNew}<button type="button" onclick={() => app.connect(e)}>Connect</button>{/if}
      </div>
    {:else}
      <span>Select a host, or create one with "New host". Double-click a host to connect.</span>
    {/if}
  </div>
</div>

<style>
  .hosts { flex: 1; min-width: 0; display: flex; }
  .mt { margin-top: 10px; }
</style>
