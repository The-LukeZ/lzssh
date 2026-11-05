import { exports } from "cloudflare:workers";

export const TOKEN = "test-token";
export const BASE = "https://lzssh.test";

export type Dev = { hex: string; key: CryptoKey };

const hex = (b: ArrayBuffer | Uint8Array) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const b64 = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b)));

export async function newDevice(): Promise<Dev> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = (await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer;
  return { hex: hex(raw), key: kp.privateKey };
}

export const now = () => Math.floor(Date.now() / 1000);

export type SignOpts = { time?: number; token?: string | null; ticket?: string; device?: string; signer?: Dev };

export async function signedRequest(dev: Dev, method: string, path: string, body = "", opts: SignOpts = {}): Promise<Request> {
  const time = String(opts.time ?? now());
  const bodyBytes = new TextEncoder().encode(body);
  const s = `lzssh-req-v1\n${method}\n${path}\n${time}\n${hex(await crypto.subtle.digest("SHA-256", bodyBytes))}`;
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, (opts.signer ?? dev).key, new TextEncoder().encode(s));
  const headers: Record<string, string> = {
    "X-Lz-Device": opts.device ?? dev.hex,
    "X-Lz-Time": time,
    "X-Lz-Sig": b64(sig),
  };
  if (opts.token !== null) headers.Authorization = `Bearer ${opts.token ?? TOKEN}`;
  if (opts.ticket) headers["X-Lz-Pair-Ticket"] = opts.ticket;
  return new Request(BASE + path, { method, headers, body: method === "GET" || method === "HEAD" ? undefined : bodyBytes });
}

export function call(req: Request): Promise<Response> {
  return exports.default.fetch(req);
}
