// Seed data and helpers for the demo. All names and addresses are fictional
// (documentation ranges 192.0.2.0/24, 203.0.113.0/24, 2001:db8::/32).

export const DEMO_PIN = "123456";
export const HOTKEY = "Ctrl+Alt+P";
export const CODE_MS = 10 * 60 * 1000;

export type Kind = "Password" | "SSH key" | "FIDO key";
export const KINDS: Kind[] = ["Password", "SSH key", "FIDO key"];
export type FidoType = "ecdsa-sk" | "ed25519-sk";

export interface Folder { id: string; name: string; open: boolean }
export interface Host { id: string; name: string; folder: string | null; addr: string; v6: string; port: string; user: string; auth: Kind; secret: string }
export interface Secret { id: string; name: string; kind: Kind; pk?: string }
export interface Device { id: string; name: string }

let uid = 100;
export const nid = () => `id${uid++}`;

/** Deterministic pseudo-random string, so fake keys look the same on every visit. */
export function pseudo(seed: string, n: number, alphabet: string): string {
  let x = 0;
  for (const c of seed) x = (x * 31 + c.charCodeAt(0)) >>> 0;
  let out = "";
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    out += alphabet[(x >>> 16) % alphabet.length];
  }
  return out;
}
export const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
export const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const HEX = "0123456789abcdef";

export function pubKey(type: FidoType | "ed25519", name: string): string {
  if (type === "ed25519-sk") return `sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t${pseudo(name, 60, B64)} ${name}`;
  if (type === "ecdsa-sk") return `sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20${pseudo(name, 96, B64)} ${name}`;
  return `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${pseudo(name, 43, B64)} ${name}`;
}

export const seed = () => ({
  folders: [
    { id: "f1", name: "homelab", open: true },
    { id: "f2", name: "staging, fsn1", open: true },
  ] as Folder[],
  hosts: [
    { id: "h1", name: "nas", folder: "f1", addr: "192.0.2.10", v6: "", port: "22", user: "admin", auth: "Password", secret: "s3" },
    { id: "h2", name: "pihole", folder: "f1", addr: "192.0.2.53", v6: "", port: "22", user: "pi", auth: "SSH key", secret: "s2" },
    { id: "h3", name: "router", folder: "f1", addr: "192.0.2.1", v6: "", port: "22", user: "root", auth: "FIDO key", secret: "s1" },
    { id: "h4", name: "api", folder: "f2", addr: "203.0.113.24", v6: "2001:db8::24", port: "61189", user: "deploy", auth: "FIDO key", secret: "s1" },
    { id: "h5", name: "db", folder: "f2", addr: "203.0.113.25", v6: "", port: "61189", user: "root", auth: "SSH key", secret: "s2" },
  ] as Host[],
  secrets: [
    { id: "s1", name: "YubiKey", kind: "FIDO key", pk: pubKey("ed25519-sk", "YubiKey") },
    { id: "s2", name: "id_ed25519", kind: "SSH key", pk: pubKey("ed25519", "id_ed25519") },
    { id: "s3", name: "nas admin", kind: "Password" },
  ] as Secret[],
  paired: [{ id: "c41e" + pseudo("laptop", 60, HEX), name: "Laptop" }] as Device[],
});
