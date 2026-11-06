// A fake ssh session shown in the Windows Terminal window.
import { B64, nid, pseudo, type Host, type Secret } from "./data";

/** A line is a list of segments; `c` is a colour class (g, b, d). */
export type Seg = { t: string; c?: "g" | "b" | "d" };
export type Line = Seg[];
export type Phase = "connecting" | "touch" | "shell" | "closed";

const txt = (t: string, c?: Seg["c"]): Line => [{ t, c }];

export class Session {
  id = nid();
  title: string;
  user: string;
  hn: string;
  addr: string;
  lines = $state<Line[]>([]);
  input = $state("");
  phase = $state<Phase>("connecting");
  private hist: string[] = [];
  private hi = 0;

  constructor(host: Host, secret: Secret) {
    this.user = host.user || "root";
    this.hn = host.name.toLowerCase().replace(/[^a-z0-9-]+/g, "-");
    this.addr = host.addr || host.v6;
    this.title = `${this.user}@${host.name}`;
    if (host.auth === "FIDO key") {
      const alg = secret.pk?.startsWith("sk-ecdsa") ? "ECDSA-SK" : "ED25519-SK";
      this.lines.push(txt(`Confirm user presence for key ${alg} SHA256:${pseudo(secret.name + "fp", 43, B64)}`));
      this.phase = "touch";
    } else {
      setTimeout(() => this.welcome(), 450);
    }
  }

  prompt(): Line {
    return [{ t: `${this.user}@${this.hn}`, c: "g" }, { t: ":" }, { t: "~", c: "b" }, { t: this.user === "root" ? "# " : "$ " }];
  }

  touch() {
    if (this.phase !== "touch") return;
    this.lines.push(txt("User presence confirmed"));
    this.welcome();
  }

  private welcome() {
    this.lines.push(
      txt(`Linux ${this.hn} 6.12.48-1-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 x86_64`),
      txt(""),
      txt("The programs included with the Debian GNU/Linux system are free software.", "d"),
      txt("Last login: Thu Nov  5 21:14:09 2026 from 198.51.100.7"),
    );
    this.phase = "shell";
  }

  private end() {
    this.phase = "closed";
    this.lines.push(txt(""), txt("[process exited with code 0 (0x00000000)]", "d"), txt("You can now close this terminal with Ctrl+D, or press Enter to restart.", "d"));
  }

  /** Handles a key press. Returns "close" when the tab should close, true when handled. */
  key(ev: KeyboardEvent): boolean | "close" {
    if (this.phase === "touch") {
      if (ev.key === " " || ev.key === "Enter") return this.touch(), true;
      return false;
    }
    if (this.phase === "closed") return ev.key === "Enter" || (ev.ctrlKey && ev.key === "d") ? "close" : false;
    if (this.phase !== "shell" || ev.altKey || ev.metaKey) return false;
    if (ev.ctrlKey) {
      if (ev.key === "l") this.lines = [];
      else if (ev.key === "c") this.lines.push([...this.prompt(), { t: this.input + "^C" }]), (this.input = "");
      else if (ev.key === "d" && !this.input) this.run("logout");
      else return false;
      return true;
    }
    if (ev.key === "Enter") {
      this.lines.push([...this.prompt(), { t: this.input }]);
      this.run(this.input);
      this.input = "";
    } else if (ev.key === "Backspace") this.input = this.input.slice(0, -1);
    else if (ev.key === "ArrowUp") (this.hi = Math.max(0, this.hi - 1)), (this.input = this.hist[this.hi] ?? this.input);
    else if (ev.key === "ArrowDown") (this.hi = Math.min(this.hist.length, this.hi + 1)), (this.input = this.hist[this.hi] ?? "");
    else if (ev.key === "Tab") { /* no completion in the demo */ }
    else if (ev.key.length === 1) this.input += ev.key;
    else return false;
    return true;
  }

  paste(text: string) {
    if (this.phase === "shell") this.input += text.replace(/[\r\n]+/g, " ");
  }

  private run(cmdline: string) {
    const [cmd, ...args] = cmdline.trim().split(/\s+/);
    if (!cmd) return;
    const out = (...l: string[]) => this.lines.push(...l.map((t) => txt(t)));
    this.hist.push(cmdline);
    this.hi = this.hist.length;
    switch (cmd) {
      case "help": out("This is a demo shell. Try: ls, whoami, uptime, clear, exit"); break;
      case "ls": out(this.user === "root" ? "backups  docker-compose.yml  notes.txt" : "app  deploy.sh  logs"); break;
      case "whoami": out(this.user); break;
      case "uptime": out(" 21:47:12 up 41 days,  3:02,  1 user,  load average: 0.08, 0.03, 0.01"); break;
      case "clear": this.lines = []; break;
      case "exit":
      case "logout":
        out("logout", `Connection to ${this.addr} closed.`);
        this.end();
        break;
      default: out(`-bash: ${cmd}: command not found`);
    }
  }
}
