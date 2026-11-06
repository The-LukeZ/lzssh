// Shared state of the demo app, provided to all components through context.
import { createContext } from "svelte";
import { nid, seed, type Host } from "./data";
import { Session } from "./session.svelte";

export type Screen = "unlock" | "hosts" | "secrets" | "devices";
export type SecurityKind = "hello-unlock" | "key-create";
type Toast = { id: string; msg: string };

const TOAST_MS = 4000;

export class DemoApp {
  screen = $state<Screen>("unlock");

  folders = $state(seed().folders);
  hosts = $state(seed().hosts);
  secrets = $state(seed().secrets);
  paired = $state(seed().paired);

  /** Hosts screen: selected host and the edit draft. Kept here so unlock can preselect a host. */
  sel = $state<string | null>(null);
  edit = $state<Host | null>(null);
  isNew = $state(false);

  toasts = $state<Toast[]>([]);
  note = $state("");
  picker = $state(false);
  security = $state<{ kind: SecurityKind; resolve: (ok: boolean) => void } | null>(null);
  /** "Not in this demo" popup for features the demo only shows. */
  stub = $state<{ what: string; text: string } | null>(null);

  sessions = $state<Session[]>([]);
  activeSession = $state<string | null>(null);

  secret = (id: string) => this.secrets.find((s) => s.id === id);
  host = (id: string) => this.hosts.find((h) => h.id === id);

  toast(msg: string) {
    const t = { id: nid(), msg };
    this.toasts.push(t);
    setTimeout(() => (this.toasts = this.toasts.filter((x) => x.id !== t.id)), TOAST_MS);
  }

  /** Explains a feature that exists in lzssh but not in this demo. */
  notInDemo(what: string, text: string) {
    this.stub = { what, text };
  }

  /** Shows the fake Windows security dialog; resolves to false when canceled. */
  ask(kind: SecurityKind): Promise<boolean> {
    this.security?.resolve(false);
    return new Promise((resolve) => {
      this.security = {
        kind,
        resolve: (ok) => {
          this.security = null;
          resolve(ok);
        },
      };
    });
  }

  openHost(id: string) {
    const h = this.host(id);
    if (!h) return;
    this.sel = id;
    this.edit = { ...h };
    this.isNew = false;
  }

  unlocked() {
    this.screen = "hosts";
    this.openHost("h4");
    this.note = "Unlocked. Try Connect, then touch the security key in the terminal.";
  }

  connect(h: Host) {
    const s = this.secret(h.secret);
    if (!s || s.kind !== h.auth) return this.toast(`${h.name}: Secret missing`);
    const session = new Session(h, s);
    this.sessions.push(session);
    this.activeSession = session.id;
    if (h.auth === "FIDO key") this.note = "ssh is waiting for the security key. Click the button in the terminal or press Space.";
  }

  closeSession(id: string) {
    this.sessions = this.sessions.filter((s) => s.id !== id);
    if (this.activeSession === id) this.activeSession = this.sessions.at(-1)?.id ?? null;
  }
}

export const [getApp, setApp] = createContext<DemoApp>();
