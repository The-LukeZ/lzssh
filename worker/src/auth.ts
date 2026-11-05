/** Request authentication: the shared access token, then the device's Ed25519 signature. */

export const HEX_ID = /^[0-9a-f]{64}$/;
const CLOCK_WINDOW_SEC = 300;
const enc = new TextEncoder();

export function toHex(b: ArrayBuffer | Uint8Array): string {
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s: string): Uint8Array | null {
  if (s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function fromB64(s: string): Uint8Array | null {
  try {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function sha256Hex(b: Uint8Array): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", b));
}

/** `lzssh-req-v1\n METHOD \n PATH \n TIME \n hex(sha256(body))` */
export async function signingString(method: string, path: string, time: string, body: Uint8Array): Promise<string> {
  return `lzssh-req-v1\n${method}\n${path}\n${time}\n${await sha256Hex(body)}`;
}

/** Constant-time check of `Authorization: Bearer <token>`. */
export async function tokenOk(header: string | null, secret: string): Promise<boolean> {
  if (!header || !secret || !header.startsWith("Bearer ")) return false;
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(header.slice(7))),
    crypto.subtle.digest("SHA-256", enc.encode(secret)),
  ]);
  return crypto.subtle.timingSafeEqual(a, b);
}

export type Verified = { device: string; sig: string };
export type AuthFailure = { error: "auth" | "clock" };

export async function verifyRequest(req: Request, body: Uint8Array, nowSec: number): Promise<Verified | AuthFailure> {
  const device = req.headers.get("X-Lz-Device") ?? "";
  const time = req.headers.get("X-Lz-Time") ?? "";
  const sigB64 = req.headers.get("X-Lz-Sig") ?? "";
  if (!HEX_ID.test(device) || !/^\d{1,12}$/.test(time)) return { error: "auth" };
  if (Math.abs(nowSec - Number(time)) > CLOCK_WINDOW_SEC) return { error: "clock" };
  const sig = fromB64(sigB64);
  if (!sig || sig.length !== 64) return { error: "auth" };
  try {
    const key = await crypto.subtle.importKey("raw", fromHex(device)!, { name: "Ed25519" }, false, ["verify"]);
    const msg = enc.encode(await signingString(req.method, new URL(req.url).pathname, time, body));
    if (!(await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg))) return { error: "auth" };
  } catch {
    return { error: "auth" };
  }
  return { device, sig: sigB64 };
}
