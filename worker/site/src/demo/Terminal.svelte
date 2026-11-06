<script lang="ts">
  // Windows Terminal window with one tab per ssh session.
  import { getApp } from "./app.svelte";

  const app = getApp();
  const s = $derived(app.sessions.find((x) => x.id === app.activeSession) ?? app.sessions[0]);
  // Focuses the screen when a tab is shown.
  const focusScreen = (el: HTMLElement) => {
    el.focus({ preventScroll: true });
  };

  // Keeps the newest output in view; re-runs whenever the output or the input line changes.
  const followOutput = (el: HTMLElement) => {
    void s?.lines.length;
    void s?.input;
    void s?.phase;
    el.scrollTop = el.scrollHeight;
  };

  function touch(e: MouseEvent) {
    s?.touch();
    app.note = "";
    (e.currentTarget as HTMLElement).closest<HTMLElement>(".screen")?.focus();
  }

  function onkey(e: KeyboardEvent) {
    if (!s) return;
    const r = s.key(e);
    if (r === "close") app.closeSession(s.id);
    if (r) {
      e.preventDefault();
      if (s.phase !== "touch") app.note = app.note.startsWith("ssh is waiting") ? "" : app.note;
    }
  }

  function tabKey(e: KeyboardEvent, fn: () => void) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fn();
    }
  }
</script>

{#if s}
  <div class="win term">
    <div class="tabs" role="tablist">
      {#each app.sessions as x (x.id)}
        <div class={["tab", x.id === s.id && "on"]}>
          <span role="tab" tabindex="0" aria-selected={x.id === s.id} onclick={() => (app.activeSession = x.id)} onkeydown={(e) => tabKey(e, () => (app.activeSession = x.id))}>{x.title}</span>
          <span class="tx" role="button" tabindex="0" aria-label="Close tab" onclick={() => app.closeSession(x.id)} onkeydown={(e) => tabKey(e, () => app.closeSession(x.id))}>✕</span>
        </div>
      {/each}
      <span class="tsp"></span>
      <span class="tb-btns">
        <i class="tb-min" aria-hidden="true"></i><i class="tb-max" aria-hidden="true"></i>
        <i class="tb-x" role="button" tabindex="0" aria-label="Close terminal" onclick={() => (app.sessions = [])} onkeydown={(e) => tabKey(e, () => (app.sessions = []))}></i>
      </span>
    </div>
    {#key s.id}
      <!-- The screen is the terminal's input surface, like a real terminal it takes keys directly. -->
      <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
      <div class="screen" tabindex="0" role="log" aria-label="Terminal, {s.title}" {@attach focusScreen} {@attach followOutput}
        onkeydown={onkey} onpaste={(e) => (e.preventDefault(), s.paste(e.clipboardData?.getData("text") ?? ""))}
        onclick={(e) => e.currentTarget === e.target && e.currentTarget.focus()}>
        {#each s.lines as line, i (i)}<div>{#each line as seg, j (j)}<span class={seg.c && `c-${seg.c}`}>{seg.t}</span>{/each}{#if !line.length || (line.length === 1 && !line[0].t)}&#8203;{/if}</div>{/each}
        {#if s.phase === "touch"}
          <button type="button" class="touch" onclick={touch}>Touch your security key (click, or press Space)</button>
        {:else if s.phase === "shell"}
          <div>{#each s.prompt() as seg, j (j)}<span class={seg.c && `c-${seg.c}`}>{seg.t}</span>{/each}{s.input}<span class="cur"> </span></div>
        {/if}
      </div>
    {/key}
  </div>
{/if}

<style>
  .term {
    left: 430px; top: 250px; width: 740px; height: 420px;
    background: #0c0c0c;
    display: flex; flex-direction: column;
    font: 400 14px/1.4 var(--mono);
    color: #cccccc;
    z-index: 3;
  }
  .tabs { height: 38px; flex: none; background: #202020; display: flex; align-items: flex-end; padding-left: 8px; gap: 2px; }
  .tab {
    height: 32px; display: flex; align-items: center; gap: 10px;
    padding: 0 10px 0 12px; border-radius: 6px 6px 0 0;
    font: 400 12px/1 "Segoe UI", system-ui, sans-serif; color: #b8b8b8;
    max-width: 210px;
  }
  .tab.on { background: #0c0c0c; color: #fff; }
  .tab span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: default; }
  .tab .tx { font-size: 14px; color: #9a9a9a; padding: 0 3px; border-radius: 3px; }
  .tab .tx:hover { background: #3a3a3a; color: #fff; }
  .tsp { flex: 1; }
  .tabs .tb-btns { align-self: stretch; }
  .screen { flex: 1; overflow: auto; padding: 8px 12px; white-space: pre-wrap; word-break: break-all; cursor: text; }
  .screen:focus { outline: none; }
  .c-g { color: #16c60c; }
  .c-b { color: #3b78ff; }
  .c-d { color: #767676; }
  .cur { background: #cccccc; color: #0c0c0c; }
  .screen:not(:focus) .cur { background: none; outline: 1px solid #cccccc; color: inherit; }
  .touch {
    display: inline-block; margin: 4px 0; padding: 2px 10px;
    background: #1f3a4f; color: #fff; border: 1px solid #3b78ff; border-radius: 4px;
    font: inherit; cursor: pointer;
    animation: pulse 1.2s ease-in-out infinite;
  }
  @keyframes pulse { 50% { border-color: #9cc3ff; box-shadow: 0 0 0 3px rgba(59, 120, 255, 0.25); } }
</style>
