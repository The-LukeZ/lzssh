<script lang="ts">
  import { tick } from "svelte";
  import { getApp } from "./app.svelte";
  import { nid, pubKey, type FidoType } from "./data";

  const app = getApp();
  let form = $state<{ name: string; kt: FidoType; err: string | null } | null>(null);
  let busy = $state(false);
  let nameInput: HTMLInputElement | undefined = $state();

  async function open() {
    form = { name: "", kt: "ed25519-sk", err: null };
    await tick();
    nameInput?.focus();
  }

  async function create() {
    const f = form!;
    if (!f.name.trim()) return (f.err = "Enter a name");
    f.err = null;
    busy = true;
    const ok = await app.ask("key-create");
    busy = false;
    if (!ok) return (f.err = "Key creation failed: the operation was canceled by the user.");
    const name = f.name.trim();
    app.secrets.push({ id: nid(), name, kind: "FIDO key", pk: pubKey(f.kt, name) });
    form = null;
    app.toast(`Created FIDO key ${name}`);
  }

  const stub = {
    ssh: () => app.notInDemo("Import SSH key", "lzssh imports an existing private key (with its passphrase) into the encrypted vault."),
    fidofile: () => app.notInDemo("Import FIDO key file", "Import a FIDO key handle such as id_ed25519_sk that was created elsewhere."),
    pw: () => app.notInDemo("Add password", "Store a password in the vault. lzssh hands it to ssh when you connect, so you never type it."),
    copy: () => app.notInDemo("Copy public key", "Copies the public key, ready to paste into authorized_keys or a Git host."),
    install: () => app.notInDemo("Install on host", "lzssh logs in to a host you pick and appends the public key to ~/.ssh/authorized_keys."),
    del: () => app.notInDemo("Delete secret", "Deleting a secret asks for confirmation first. Hosts that use it show \"secret missing\"."),
  };
</script>

<div class="central">
  <div class="row">
    <button type="button" onclick={stub.ssh}>Import SSH key</button>
    <button type="button" onclick={open}>Create FIDO key</button>
    <button type="button" onclick={stub.fidofile}>Import FIDO key file</button>
    <button type="button" onclick={stub.pw}>Add password</button>
  </div>
  <div class="hr"></div>

  {#if form}
    {@const f = form}
    <div class="form">
      <span>Windows will ask you to touch your security key or confirm with Windows Hello.</span>
      <div class="grid">
        <span>Name</span><input type="text" placeholder="Key name, e.g. YubiKey" aria-label="Key name" bind:value={f.name} bind:this={nameInput} onkeydown={(e) => e.key === "Enter" && create()} />
        <span>Type</span>
        <div class="row">
          {#each ["ecdsa-sk", "ed25519-sk"] as const as t (t)}
            <label class="ck"><input type="radio" name="fidotype" value={t} bind:group={f.kt} />{t}</label>
          {/each}
        </div>
      </div>
      {#if f.err}<span class="err">{f.err}</span>{/if}
      {#if busy}
        <div class="row"><span class="spin"></span><span>Waiting for the Windows security dialog…</span><button type="button" onclick={() => app.security?.resolve(false)}>Cancel</button></div>
      {:else}
        <div class="row"><button type="button" onclick={create}>Create</button><button type="button" onclick={() => (form = null)}>Cancel</button></div>
      {/if}
    </div>
    <div class="hr"></div>
  {/if}

  <div class="list">
    {#each app.secrets as m (m.id)}
      <div class="li">
        <span class="name">{m.name}</span>
        <span class="kind">{m.kind}</span>
        {#if m.pk}
          <span class="grow mono" title={m.pk}>{m.pk}</span>
          <button type="button" onclick={stub.copy}>Copy</button>
          <button type="button" onclick={stub.install}>Install on host…</button>
        {:else}
          <span class="grow"></span>
        {/if}
        <button type="button" onclick={stub.del}>Delete</button>
      </div>
    {/each}
  </div>
</div>

<style>
  .form { display: flex; flex-direction: column; gap: 6px; max-width: 620px; }
  .name { width: 110px; flex: none; color: var(--eg-text); overflow: hidden; text-overflow: ellipsis; }
  .kind { width: 70px; flex: none; }
</style>
